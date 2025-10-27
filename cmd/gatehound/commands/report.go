package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/internal/gatehound/report"
	"github.com/spf13/cobra"
)

type reportOptions struct {
	id         string
	format     string
	template   string
	outputDir  string
}

func newReportCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	opts := &reportOptions{}

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate incident reports",
		Long: `Generate forensic incident reports for detected devices or events.

Report templates:
  universal  - Complete forensic report with all details (default)
  executive  - High-level summary for management
  forensic   - Detailed technical forensic analysis

Examples:
  gatehound report create --id=evt-123456
  gatehound report create --id=dev-00:11:22:33:44:55 --template=forensic
  gatehound report list`,
	}

	cmd.AddCommand(newReportCreateCmd(ctx, logger, opts))
	cmd.AddCommand(newReportListCmd(ctx, logger))

	return cmd
}

func newReportCreateCmd(ctx context.Context, logger *logging.Logger, opts *reportOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new incident report",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReportCreate(ctx, logger, opts)
		},
	}

	cmd.Flags().StringVar(&opts.id, "id", "", "event or device ID (required)")
	cmd.Flags().StringVar(&opts.format, "format", "pdf", "output format (pdf|text|json)")
	cmd.Flags().StringVar(&opts.template, "template", "universal", "report template (universal|executive|forensic)")
	cmd.Flags().StringVar(&opts.outputDir, "output", "./data/gatehound/reports", "output directory")
	cmd.MarkFlagRequired("id")

	return cmd
}

func runReportCreate(ctx context.Context, logger *logging.Logger, opts *reportOptions) error {
	logger.Info("Generating incident report",
		logging.WithAction("report_create"),
		logging.WithExtra("id", opts.id),
		logging.WithExtra("template", opts.template),
	)

	var templateType report.ReportTemplate
	switch opts.template {
	case "executive":
		templateType = report.TemplateExecutive
	case "forensic":
		templateType = report.TemplateForensic
	default:
		templateType = report.TemplateUniversal
	}

	reportGen, err := report.NewPDFGenerator(opts.outputDir, templateType)
	if err != nil {
		return fmt.Errorf("failed to create report generator: %w", err)
	}

	incidentReport := &report.IncidentReport{
		ID:        opts.id,
		Title:     "Incident Report",
		Timestamp: time.Now(),
		Severity:  "medium",
		Analyst:   "manual-generation",
	}

	reportPath, err := reportGen.GenerateReport(incidentReport)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                   REPORT GENERATED")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("Report ID:     %s\n", opts.id)
	fmt.Printf("Template:      %s\n", opts.template)
	fmt.Printf("Format:        %s\n", opts.format)
	fmt.Printf("Output:        %s\n", reportPath)
	fmt.Println("═══════════════════════════════════════════════════════════════")

	logger.Info("Report generated successfully",
		logging.WithExtra("report_path", reportPath),
	)

	return nil
}

func newReportListCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List generated reports",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("═══════════════════════════════════════════════════════════════")
			fmt.Println("                   GENERATED REPORTS")
			fmt.Println("═══════════════════════════════════════════════════════════════")
			fmt.Println("\n(scan reports directory for list)")
			return nil
		},
	}
}
