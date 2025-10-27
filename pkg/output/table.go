package output

import (
	"strings"
)

type Table struct {
	Headers []string
	Rows    [][]string
	Widths  []int
}

func NewTable(headers ...string) *Table {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	return &Table{
		Headers: headers,
		Rows:    [][]string{},
		Widths:  widths,
	}
}

func (t *Table) AddRow(cols ...string) {
	row := make([]string, len(t.Headers))
	for i := 0; i < len(t.Headers) && i < len(cols); i++ {
		row[i] = cols[i]
		plainLen := len(stripAnsi(cols[i]))
		if plainLen > t.Widths[i] {
			t.Widths[i] = plainLen
		}
	}
	t.Rows = append(t.Rows, row)
}

func (t *Table) Render() string {
	if len(t.Headers) == 0 {
		return ""
	}

	var sb strings.Builder

	t.renderTopBorder(&sb)
	t.renderHeaders(&sb)
	t.renderHeaderSeparator(&sb)

	for _, row := range t.Rows {
		t.renderRow(&sb, row)
	}

	t.renderBottomBorder(&sb)

	return sb.String()
}

func (t *Table) renderTopBorder(sb *strings.Builder) {
	sb.WriteString(Colorize(Cyan, "┌"))
	for i, width := range t.Widths {
		sb.WriteString(Colorize(Cyan, strings.Repeat("─", width+2)))
		if i < len(t.Widths)-1 {
			sb.WriteString(Colorize(Cyan, "┬"))
		}
	}
	sb.WriteString(Colorize(Cyan, "┐\n"))
}

func (t *Table) renderHeaders(sb *strings.Builder) {
	sb.WriteString(Colorize(Cyan, "│"))
	for i, header := range t.Headers {
		padding := t.Widths[i] - len(header)
		sb.WriteString(" ")
		sb.WriteString(ColorizeMulti([]Color{Bold, BrightWhite}, header))
		sb.WriteString(strings.Repeat(" ", padding+1))
		sb.WriteString(Colorize(Cyan, "│"))
	}
	sb.WriteString("\n")
}

func (t *Table) renderHeaderSeparator(sb *strings.Builder) {
	sb.WriteString(Colorize(Cyan, "├"))
	for i, width := range t.Widths {
		sb.WriteString(Colorize(Cyan, strings.Repeat("─", width+2)))
		if i < len(t.Widths)-1 {
			sb.WriteString(Colorize(Cyan, "┼"))
		}
	}
	sb.WriteString(Colorize(Cyan, "┤\n"))
}

func (t *Table) renderRow(sb *strings.Builder, row []string) {
	sb.WriteString(Colorize(Cyan, "│"))
	for i, cell := range row {
		plainLen := len(stripAnsi(cell))
		padding := t.Widths[i] - plainLen
		sb.WriteString(" ")
		sb.WriteString(cell)
		sb.WriteString(strings.Repeat(" ", padding+1))
		sb.WriteString(Colorize(Cyan, "│"))
	}
	sb.WriteString("\n")
}

func (t *Table) renderBottomBorder(sb *strings.Builder) {
	sb.WriteString(Colorize(Cyan, "└"))
	for i, width := range t.Widths {
		sb.WriteString(Colorize(Cyan, strings.Repeat("─", width+2)))
		if i < len(t.Widths)-1 {
			sb.WriteString(Colorize(Cyan, "┴"))
		}
	}
	sb.WriteString(Colorize(Cyan, "┘"))
}
