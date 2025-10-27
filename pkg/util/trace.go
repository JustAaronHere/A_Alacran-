package util

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type TraceContext struct {
	TraceID    string
	SpanID     string
	ParentSpan string
	StartTime  time.Time
	EndTime    *time.Time
	Tags       map[string]string
	Logs       []TraceLog
}

type TraceLog struct {
	Timestamp time.Time
	Level     string
	Message   string
	Fields    map[string]interface{}
}

type Tracer struct {
	serviceName string
	enabled     bool
	spans       map[string]*TraceContext
}

func NewTracer(serviceName string, enabled bool) *Tracer {
	return &Tracer{
		serviceName: serviceName,
		enabled:     enabled,
		spans:       make(map[string]*TraceContext),
	}
}

func (t *Tracer) StartSpan(ctx context.Context, operationName string) (*TraceContext, context.Context) {
	if !t.enabled {
		return nil, ctx
	}

	traceID := uuid.New().String()
	spanID := uuid.New().String()
	
	parentSpan := ""
	if parent := t.extractParentSpan(ctx); parent != nil {
		parentSpan = parent.SpanID
		traceID = parent.TraceID
	}

	span := &TraceContext{
		TraceID:    traceID,
		SpanID:     spanID,
		ParentSpan: parentSpan,
		StartTime:  time.Now(),
		Tags:       make(map[string]string),
		Logs:       make([]TraceLog, 0),
	}

	span.Tags["operation"] = operationName
	span.Tags["service"] = t.serviceName

	t.spans[spanID] = span

	newCtx := context.WithValue(ctx, "trace_span", span)
	return span, newCtx
}

func (t *Tracer) FinishSpan(span *TraceContext) {
	if !t.enabled || span == nil {
		return
	}

	now := time.Now()
	span.EndTime = &now
}

func (t *Tracer) AddTag(span *TraceContext, key, value string) {
	if !t.enabled || span == nil {
		return
	}
	span.Tags[key] = value
}

func (t *Tracer) LogEvent(span *TraceContext, level, message string, fields map[string]interface{}) {
	if !t.enabled || span == nil {
		return
	}

	log := TraceLog{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
		Fields:    fields,
	}

	span.Logs = append(span.Logs, log)
}

func (t *Tracer) extractParentSpan(ctx context.Context) *TraceContext {
	if span, ok := ctx.Value("trace_span").(*TraceContext); ok {
		return span
	}
	return nil
}

func (t *Tracer) GetSpan(spanID string) *TraceContext {
	return t.spans[spanID]
}

func (t *Tracer) ExportSpans() []*TraceContext {
	spans := make([]*TraceContext, 0, len(t.spans))
	for _, span := range t.spans {
		spans = append(spans, span)
	}
	return spans
}

func (span *TraceContext) Duration() time.Duration {
	if span.EndTime == nil {
		return time.Since(span.StartTime)
	}
	return span.EndTime.Sub(span.StartTime)
}

func (span *TraceContext) String() string {
	duration := span.Duration()
	status := "active"
	if span.EndTime != nil {
		status = "completed"
	}

	return fmt.Sprintf("Span[%s] trace=%s parent=%s duration=%s status=%s",
		span.SpanID[:8], span.TraceID[:8], span.ParentSpan, duration, status)
}

type TraceExporter interface {
	Export(spans []*TraceContext) error
}

type ConsoleExporter struct{}

func (ce *ConsoleExporter) Export(spans []*TraceContext) error {
	for _, span := range spans {
		fmt.Printf("Trace: %s | Span: %s | Operation: %s | Duration: %s\n",
			span.TraceID[:8], span.SpanID[:8], span.Tags["operation"], span.Duration())
		
		for key, value := range span.Tags {
			if key != "operation" && key != "service" {
				fmt.Printf("  Tag: %s = %s\n", key, value)
			}
		}

		for _, log := range span.Logs {
			fmt.Printf("  Log [%s]: %s\n", log.Level, log.Message)
		}
	}
	return nil
}

var globalTracer *Tracer

func InitGlobalTracer(serviceName string, enabled bool) {
	globalTracer = NewTracer(serviceName, enabled)
}

func GlobalTracer() *Tracer {
	return globalTracer
}

func StartSpan(ctx context.Context, operationName string) (*TraceContext, context.Context) {
	if globalTracer == nil {
		return nil, ctx
	}
	return globalTracer.StartSpan(ctx, operationName)
}

func FinishSpan(span *TraceContext) {
	if globalTracer != nil {
		globalTracer.FinishSpan(span)
	}
}
