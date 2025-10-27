package output

import (
	"fmt"
	"os"
	"strings"
)

var noColor = os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb"

type Color string

const (
	Reset     Color = "\033[0m"
	Bold      Color = "\033[1m"
	Dim       Color = "\033[2m"
	Italic    Color = "\033[3m"
	Underline Color = "\033[4m"

	Black   Color = "\033[30m"
	Red     Color = "\033[31m"
	Green   Color = "\033[32m"
	Yellow  Color = "\033[33m"
	Blue    Color = "\033[34m"
	Magenta Color = "\033[35m"
	Cyan    Color = "\033[36m"
	White   Color = "\033[37m"
	Gray    Color = "\033[90m"

	BrightRed     Color = "\033[91m"
	BrightGreen   Color = "\033[92m"
	BrightYellow  Color = "\033[93m"
	BrightBlue    Color = "\033[94m"
	BrightMagenta Color = "\033[95m"
	BrightCyan    Color = "\033[96m"
	BrightWhite   Color = "\033[97m"

	BgBlack   Color = "\033[40m"
	BgRed     Color = "\033[41m"
	BgGreen   Color = "\033[42m"
	BgYellow  Color = "\033[43m"
	BgBlue    Color = "\033[44m"
	BgMagenta Color = "\033[45m"
	BgCyan    Color = "\033[46m"
	BgWhite   Color = "\033[47m"
)

func Colorize(color Color, text string) string {
	if noColor {
		return text
	}
	return string(color) + text + string(Reset)
}

func ColorizeMulti(colors []Color, text string) string {
	if noColor {
		return text
	}
	var colorStr strings.Builder
	for _, c := range colors {
		colorStr.WriteString(string(c))
	}
	return colorStr.String() + text + string(Reset)
}

func Success(text string) string {
	return Colorize(Green, "✓ "+text)
}

func Error(text string) string {
	return Colorize(Red, "✗ "+text)
}

func Warning(text string) string {
	return Colorize(Yellow, "⚠ "+text)
}

func Info(text string) string {
	return Colorize(Cyan, "ℹ "+text)
}

func Critical(text string) string {
	return ColorizeMulti([]Color{Bold, BrightRed}, "🔴 "+text)
}

func High(text string) string {
	return Colorize(Red, "🟠 "+text)
}

func Medium(text string) string {
	return Colorize(Yellow, "🟡 "+text)
}

func Low(text string) string {
	return Colorize(Gray, "🔵 "+text)
}

func Badge(color Color, text string) string {
	if noColor {
		return fmt.Sprintf("[%s]", text)
	}
	return string(color) + string(BgWhite) + " " + text + " " + string(Reset)
}

func SeverityBadge(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return ColorizeMulti([]Color{Bold, BrightRed}, "[CRITICAL]")
	case "HIGH":
		return Colorize(Red, "[HIGH]")
	case "MEDIUM":
		return Colorize(Yellow, "[MEDIUM]")
	case "LOW":
		return Colorize(Gray, "[LOW]")
	case "INFO":
		return Colorize(Cyan, "[INFO]")
	default:
		return fmt.Sprintf("[%s]", severity)
	}
}

func StatusBadge(status string) string {
	switch strings.ToUpper(status) {
	case "RUNNING", "ACTIVE", "SCANNING":
		return Colorize(BrightGreen, "● "+status)
	case "COMPLETED", "SUCCESS", "DONE":
		return Colorize(Green, "✓ "+status)
	case "FAILED", "ERROR":
		return Colorize(Red, "✗ "+status)
	case "PENDING", "WAITING":
		return Colorize(Yellow, "○ "+status)
	case "IDLE":
		return Colorize(Gray, "○ "+status)
	default:
		return status
	}
}

func ProgressBar(current, total int, width int) string {
	if total == 0 {
		return Colorize(Gray, "["+strings.Repeat("─", width)+"]") + " 0%"
	}

	progress := float64(current) / float64(total)
	if progress > 1.0 {
		progress = 1.0
	}

	filled := int(progress * float64(width))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)

	percentage := int(progress * 100)
	var color Color
	if percentage < 30 {
		color = Red
	} else if percentage < 70 {
		color = Yellow
	} else {
		color = Green
	}

	return "[" + Colorize(color, bar) + "] " + Colorize(Bold, fmt.Sprintf("%d%%", percentage))
}

func Spinner(index int) string {
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	return Colorize(Cyan, frames[index%len(frames)])
}

func Box(title string, content string, width int) string {
	var sb strings.Builder

	titleLen := len(title)
	leftPad := (width - titleLen - 4) / 2
	rightPad := width - titleLen - 4 - leftPad

	sb.WriteString(Colorize(Cyan, "╔"+strings.Repeat("═", leftPad)+"╡ "))
	sb.WriteString(Colorize(Bold, title))
	sb.WriteString(Colorize(Cyan, " ╞"+strings.Repeat("═", rightPad)+"╗\n"))

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		padding := width - len(stripAnsi(line)) - 2
		if padding < 0 {
			padding = 0
		}
		sb.WriteString(Colorize(Cyan, "║ "))
		sb.WriteString(line)
		sb.WriteString(strings.Repeat(" ", padding))
		sb.WriteString(Colorize(Cyan, "║\n"))
	}

	sb.WriteString(Colorize(Cyan, "╚"+strings.Repeat("═", width)+"╝"))

	return sb.String()
}

func stripAnsi(str string) string {
	result := ""
	inEscape := false
	for _, r := range str {
		if r == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEscape = false
			}
			continue
		}
		result += string(r)
	}
	return result
}

func Header(text string) string {
	width := 65
	textLen := len(text)
	padding := (width - textLen - 2) / 2

	var sb strings.Builder
	sb.WriteString(Colorize(BrightCyan, "╔"+strings.Repeat("═", width)+"╗\n"))
	sb.WriteString(Colorize(BrightCyan, "║"))
	sb.WriteString(strings.Repeat(" ", padding))
	sb.WriteString(ColorizeMulti([]Color{Bold, BrightWhite}, text))
	sb.WriteString(strings.Repeat(" ", width-textLen-padding))
	sb.WriteString(Colorize(BrightCyan, "║\n"))
	sb.WriteString(Colorize(BrightCyan, "╚"+strings.Repeat("═", width)+"╝"))

	return sb.String()
}

func Section(title string) string {
	return "\n" + Colorize(BrightCyan, "┌─ "+strings.ToUpper(title)+" ") + 
		Colorize(Cyan, strings.Repeat("─", 65-len(title)-4))
}

func SectionEnd() string {
	return Colorize(Cyan, "└"+strings.Repeat("─", 65))
}

func Divider() string {
	return Colorize(Gray, strings.Repeat("─", 65))
}

func KeyValue(key, value string) string {
	return Colorize(Gray, key+": ") + Colorize(Bold, value)
}

func KeyValueColored(key, value string, valueColor Color) string {
	return Colorize(Gray, key+": ") + Colorize(valueColor, value)
}
