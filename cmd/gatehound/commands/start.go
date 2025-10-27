package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/internal/common/store"
	"github.com/aegis-sentinel/aegis-suite/internal/common/telemetry"
	"github.com/aegis-sentinel/aegis-suite/internal/gatehound/alerts"
	"github.com/aegis-sentinel/aegis-suite/internal/gatehound/correlation"
	"github.com/aegis-sentinel/aegis-suite/internal/gatehound/enrich"
	"github.com/aegis-sentinel/aegis-suite/internal/gatehound/evidence"
	"github.com/aegis-sentinel/aegis-suite/internal/gatehound/monitor"
	"github.com/aegis-sentinel/aegis-suite/internal/gatehound/policy"
	"github.com/aegis-sentinel/aegis-suite/internal/gatehound/report"
	"github.com/spf13/cobra"
	"github.com/google/uuid"
)

type startOptions struct {
	iface          string
	daemon         bool
	filter         string
	outputPath     string
	dbPath         string
	ouiDB          string
	enableGeoIP    bool
	enableWhois    bool
	webhook        string
	autoReport     bool
	reportInterval int
}

func newStartCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	opts := &startOptions{}

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start passive network monitoring",
		Long: `Start Gatehound passive monitoring to detect unknown devices, collect
forensic evidence, and generate incident reports automatically.

The monitoring system will:
- Capture network traffic on the specified interface
- Detect ARP, DHCP, DNS, mDNS, HTTP, and TLS events
- Fingerprint devices and enrich with GeoIP/WHOIS data
- Flag unknown devices based on policy rules
- Generate signed forensic reports
- Send alerts via configured webhooks

Examples:
  gatehound start --iface=eth0
  gatehound start --iface=eth0 --daemon
  gatehound start --iface=eth0 --filter="not port 22"
  gatehound start --iface=wlan0 --webhook=https://hooks.slack.com/...`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStart(ctx, logger, opts)
		},
	}

	cmd.Flags().StringVar(&opts.iface, "iface", "eth0", "network interface to monitor")
	cmd.Flags().BoolVar(&opts.daemon, "daemon", false, "run as daemon in background")
	cmd.Flags().StringVar(&opts.filter, "filter", "", "BPF filter expression")
	cmd.Flags().StringVar(&opts.outputPath, "output", "./data/gatehound", "output path for pcaps and evidence")
	cmd.Flags().StringVar(&opts.dbPath, "db-path", "./data/gatehound.db", "database path")
	cmd.Flags().StringVar(&opts.ouiDB, "oui-db", "", "OUI database file path")
	cmd.Flags().BoolVar(&opts.enableGeoIP, "geoip", false, "enable GeoIP enrichment")
	cmd.Flags().BoolVar(&opts.enableWhois, "whois", false, "enable WHOIS enrichment")
	cmd.Flags().StringVar(&opts.webhook, "webhook", "", "webhook URL for alerts")
	cmd.Flags().BoolVar(&opts.autoReport, "auto-report", true, "automatically generate reports for unknown devices")
	cmd.Flags().IntVar(&opts.reportInterval, "report-interval", 300, "report generation interval in seconds")

	return cmd
}

func runStart(ctx context.Context, logger *logging.Logger, opts *startOptions) error {
	logger.Info("Starting Gatehound passive monitoring system",
		logging.WithAction("start"),
		logging.WithExtra("interface", opts.iface),
	)

	metrics := telemetry.Global()
	go func() {
		addr := fmt.Sprintf(":%d", metricsPort)
		logger.Info(fmt.Sprintf("Starting metrics server on %s", addr))
		if err := metrics.StartMetricsServer(addr); err != nil {
			logger.Error("Metrics server failed", logging.WithError(err))
		}
	}()

	st, err := store.Open(opts.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer st.Close()

	ouiDB, err := enrich.NewOUIDatabase(opts.ouiDB)
	if err != nil {
		logger.Warning("Failed to load OUI database", logging.WithError(err))
		ouiDB, _ = enrich.NewOUIDatabase("")
	}
	logger.Info(fmt.Sprintf("Loaded %d OUI entries", ouiDB.Count()))

	var geoIPEnricher *enrich.GeoIPEnricher
	if opts.enableGeoIP {
		geoIPProvider := enrich.NewMockGeoIPProvider()
		geoIPEnricher = enrich.NewGeoIPEnricher(geoIPProvider)
		logger.Info("GeoIP enrichment enabled")
	}

	var whoisEnricher *enrich.WhoisEnricher
	if opts.enableWhois {
		whoisEnricher = enrich.NewWhoisEnricher(24*time.Hour, 5)
		logger.Info("WHOIS enrichment enabled")
	}

	evidenceStore, err := evidence.NewEvidenceStore(st, opts.outputPath+"/evidence", "gatehound-operator")
	if err != nil {
		return fmt.Errorf("failed to create evidence store: %w", err)
	}

	policyEngine := policy.NewPolicyEngine()
	correlationEngine := correlation.NewCorrelationEngine(logger)
	alertBridge := alerts.NewAlertBridge(logger, 2)
	alertBridge.Start()

	if opts.webhook != "" {
		alertBridge.AddWebhook(opts.webhook)
		logger.Info("Webhook configured", logging.WithExtra("url", opts.webhook))
	}

	reportGen, err := report.NewPDFGenerator(opts.outputPath+"/reports", report.TemplateUniversal)
	if err != nil {
		return fmt.Errorf("failed to create report generator: %w", err)
	}

	listenerConfig := &monitor.ListenerConfig{
		Interface:      opts.iface,
		Mode:           monitor.CaptureModeLive,
		PromiscMode:    true,
		SnapLen:        65536,
		Filter:         opts.filter,
		OutputPath:     opts.outputPath + "/pcaps",
		MaxPcapSize:    100 * 1024 * 1024,
		RotateInterval: 1 * time.Hour,
		Encrypted:      false,
		BufferSize:     10000,
		Workers:        4,
	}

	listener, err := monitor.NewPcapListener(listenerConfig, logger, metrics)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	if err := listener.Start(ctx); err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}
	defer listener.Stop()

	logger.Info("Passive monitoring active",
		logging.WithExtra("interface", opts.iface),
		logging.WithExtra("mode", "live"),
	)

	eventCount := 0
	unknownDeviceCount := 0

	go func() {
		ticker := time.NewTicker(time.Duration(opts.reportInterval) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats := correlationEngine.Stats()
				logger.Info("Periodic stats",
					logging.WithExtra("devices", stats["total_devices"]),
					logging.WithExtra("unknown", stats["unknown_devices"]),
					logging.WithExtra("events", stats["total_events"]),
				)
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Shutting down passive monitoring")
			return nil

		case event := <-listener.Events():
			eventCount++
			metrics.IncrementCustomCounter("gatehound_events_total")

			if event.SrcMAC != nil {
				ouiInfo := ouiDB.Lookup(event.SrcMAC)
				if ouiInfo != nil {
					event.Extra["vendor"] = ouiInfo.Vendor
				}
			}

			device, err := correlationEngine.ProcessEvent(event)
			if err != nil {
				logger.Error("Failed to process event", logging.WithError(err))
				continue
			}

			if device != nil && len(device.MAC) > 0 {
				ouiInfo := ouiDB.Lookup(device.MAC)
				if ouiInfo != nil {
					device.Vendor = ouiInfo.Vendor
				}

				action := policyEngine.EvaluateDevice(device)

				if action == policy.ActionAlert && !device.IsKnown {
					unknownDeviceCount++
					metrics.IncrementCustomCounter("gatehound_unknown_devices")

					logger.Warning("Unknown device detected",
						logging.WithAction("unknown_device"),
						logging.WithExtra("mac", device.MAC.String()),
						logging.WithExtra("vendor", device.Vendor),
						logging.WithExtra("threat_score", device.ThreatScore),
					)

					alert := &alerts.Alert{
						ID:          uuid.New().String(),
						Type:        alerts.AlertTypeUnknownDevice,
						Severity:    "medium",
						Timestamp:   time.Now(),
						Title:       "Unknown Device Detected",
						Description: fmt.Sprintf("Unknown device with MAC %s detected on network", device.MAC.String()),
						Device:      device,
						Metadata: map[string]interface{}{
							"vendor":       device.Vendor,
							"threat_score": device.ThreatScore,
						},
					}

					if device.ThreatScore >= 50.0 {
						alert.Severity = "high"
					}

					alertBridge.SendAlert(alert)

					if opts.autoReport {
						incidentReport := &report.IncidentReport{
							ID:          fmt.Sprintf("INC-%s", uuid.New().String()[:8]),
							Title:       "Unknown Device Detection",
							Timestamp:   time.Now(),
							Severity:    alert.Severity,
							Device:      device,
							Events:      correlationEngine.GetRecentEvents(time.Now().Add(-5 * time.Minute)),
							ThreatScore: device.ThreatScore,
							Analyst:     "gatehound-automated",
							Remediation: []string{
								"Verify device ownership and authorization",
								"Check device against asset inventory",
								"Isolate device if unauthorized",
								"Update policy to allow if authorized",
							},
						}

						if geoIPEnricher != nil && len(device.IP) > 0 {
							geoInfo, err := geoIPEnricher.Enrich(device.IP[0])
							if err == nil {
								incidentReport.GeoInfo = geoInfo
							}
						}

						if whoisEnricher != nil && len(device.IP) > 0 {
							whoisInfo, err := whoisEnricher.Lookup(device.IP[0])
							if err == nil {
								incidentReport.WhoisInfo = whoisInfo
							}
						}

						reportPath, err := reportGen.GenerateReport(incidentReport)
						if err != nil {
							logger.Error("Failed to generate report", logging.WithError(err))
						} else {
							logger.Info("Incident report generated",
								logging.WithExtra("report_path", reportPath),
								logging.WithExtra("incident_id", incidentReport.ID),
							)
						}
					}

					evidenceStore.StoreDevice(device, "Unknown device detected via passive monitoring")
				}

				if device.ThreatScore >= 75.0 {
					logger.Warning("High threat device detected",
						logging.WithAction("high_threat"),
						logging.WithExtra("mac", device.MAC.String()),
						logging.WithExtra("threat_score", device.ThreatScore),
					)

					alert := &alerts.Alert{
						ID:          uuid.New().String(),
						Type:        alerts.AlertTypeHighThreat,
						Severity:    "critical",
						Timestamp:   time.Now(),
						Title:       "High Threat Device Detected",
						Description: fmt.Sprintf("Device %s shows high threat indicators (score: %.2f)", device.MAC.String(), device.ThreatScore),
						Device:      device,
					}
					alertBridge.SendAlert(alert)
				}
			}

			if eventCount%100 == 0 {
				logger.Debug(fmt.Sprintf("Processed %d events, %d unknown devices", eventCount, unknownDeviceCount))
			}
		}
	}
}
