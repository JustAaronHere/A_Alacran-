package cli

import (
	"fmt"
	"strings"
	"time"
)

type TUIConfig struct {
	RefreshRate time.Duration
	ShowMetrics bool
	ShowLogs    bool
	ColorMode   bool
}

type TUIStats struct {
	ActiveScans    int
	HostsScanned   int
	PortsScanned   int
	VulnsFound     int
	RunningWorkers int
	QueueDepth     int
	Uptime         time.Duration
	LastUpdate     time.Time
}

type TUI struct {
	config *TUIConfig
	stats  *TUIStats
}

func NewTUI(config *TUIConfig) *TUI {
	if config.RefreshRate == 0 {
		config.RefreshRate = 1 * time.Second
	}

	return &TUI{
		config: config,
		stats:  &TUIStats{},
	}
}

func (t *TUI) UpdateStats(stats *TUIStats) {
	t.stats = stats
	t.stats.LastUpdate = time.Now()
}

func (t *TUI) Render() string {
	var sb strings.Builder

	sb.WriteString(t.renderHeader())
	sb.WriteString("\n")
	sb.WriteString(t.renderMetrics())
	sb.WriteString("\n")
	sb.WriteString(t.renderProgress())

	return sb.String()
}

func (t *TUI) renderHeader() string {
	title := "╔═══════════════════════════════════════════════════╗\n"
	title += "║        AEGIS SENTINEL SUITE - LIVE MONITOR       ║\n"
	title += "╚═══════════════════════════════════════════════════╝"
	return title
}

func (t *TUI) renderMetrics() string {
	var sb strings.Builder

	sb.WriteString("┌─ SCAN METRICS ────────────────────────────────────┐\n")
	sb.WriteString(fmt.Sprintf("│ Active Scans:     %-32d │\n", t.stats.ActiveScans))
	sb.WriteString(fmt.Sprintf("│ Hosts Scanned:    %-32d │\n", t.stats.HostsScanned))
	sb.WriteString(fmt.Sprintf("│ Ports Scanned:    %-32d │\n", t.stats.PortsScanned))
	sb.WriteString(fmt.Sprintf("│ Vulnerabilities:  %-32d │\n", t.stats.VulnsFound))
	sb.WriteString(fmt.Sprintf("│ Active Workers:   %-32d │\n", t.stats.RunningWorkers))
	sb.WriteString(fmt.Sprintf("│ Queue Depth:      %-32d │\n", t.stats.QueueDepth))
	sb.WriteString(fmt.Sprintf("│ Uptime:           %-32s │\n", t.formatDuration(t.stats.Uptime)))
	sb.WriteString("└───────────────────────────────────────────────────┘")

	return sb.String()
}

func (t *TUI) renderProgress() string {
	var sb strings.Builder

	sb.WriteString("┌─ STATUS ──────────────────────────────────────────┐\n")
	if t.stats.ActiveScans > 0 {
		sb.WriteString("│ Status: SCANNING                                  │\n")
		sb.WriteString(fmt.Sprintf("│ Progress: %s │\n", t.renderProgressBar(t.stats.HostsScanned, 1000)))
	} else {
		sb.WriteString("│ Status: IDLE                                      │\n")
	}
	sb.WriteString(fmt.Sprintf("│ Last Update: %-37s │\n", t.stats.LastUpdate.Format("15:04:05")))
	sb.WriteString("└───────────────────────────────────────────────────┘")

	return sb.String()
}

func (t *TUI) renderProgressBar(current, total int) string {
	if total == 0 {
		return "[                    ] 0%"
	}

	barWidth := 20
	progress := float64(current) / float64(total)
	if progress > 1.0 {
		progress = 1.0
	}

	filled := int(progress * float64(barWidth))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	return fmt.Sprintf("[%s] %d%%", bar, int(progress*100))
}

func (t *TUI) formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

func (t *TUI) Clear() {
	fmt.Print("\033[H\033[2J")
}

func (t *TUI) RenderLoop(updateFunc func() *TUIStats, stopChan <-chan struct{}) {
	ticker := time.NewTicker(t.config.RefreshRate)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.Clear()
			stats := updateFunc()
			t.UpdateStats(stats)
			fmt.Print(t.Render())
		case <-stopChan:
			return
		}
	}
}

type ModuleTUI struct {
	Module string
	Stats  map[string]interface{}
}

func RenderModuleDashboard(modules []ModuleTUI) string {
	var sb strings.Builder

	sb.WriteString("╔═══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║         AEGIS SENTINEL SUITE - MODULE DASHBOARD              ║\n")
	sb.WriteString("╚═══════════════════════════════════════════════════════════════╝\n\n")

	for _, mod := range modules {
		sb.WriteString(fmt.Sprintf("┌─ %s ───────────────────────────────────────────\n", strings.ToUpper(mod.Module)))
		for key, value := range mod.Stats {
			sb.WriteString(fmt.Sprintf("│ %-20s: %v\n", key, value))
		}
		sb.WriteString("└─────────────────────────────────────────────────────────────┘\n\n")
	}

	return sb.String()
}
