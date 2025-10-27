package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Severity string

const (
	SeverityDebug   Severity = "DEBUG"
	SeverityInfo    Severity = "INFO"
	SeverityWarning Severity = "WARNING"
	SeverityError   Severity = "ERROR"
	SeverityCritical Severity = "CRITICAL"
)

type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	SessionID string                 `json:"session_id,omitempty"`
	Operator  string                 `json:"operator,omitempty"`
	Module    string                 `json:"module"`
	Target    string                 `json:"target,omitempty"`
	Action    string                 `json:"action,omitempty"`
	Result    string                 `json:"result,omitempty"`
	Severity  Severity               `json:"severity"`
	Message   string                 `json:"message"`
	Error     string                 `json:"error,omitempty"`
	Extra     map[string]interface{} `json:"extra,omitempty"`
}

type Logger struct {
	mu        sync.Mutex
	output    io.Writer
	module    string
	sessionID string
	operator  string
	minLevel  Severity
}

var (
	defaultLogger *Logger
	once          sync.Once
)

func Initialize(module string) *Logger {
	return &Logger{
		output:   os.Stdout,
		module:   module,
		minLevel: SeverityInfo,
	}
}

func Default() *Logger {
	once.Do(func() {
		defaultLogger = Initialize("aegis")
	})
	return defaultLogger
}

func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = w
}

func (l *Logger) SetSessionID(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sessionID = id
}

func (l *Logger) SetOperator(op string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.operator = op
}

func (l *Logger) SetMinLevel(level Severity) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.minLevel = level
}

func (l *Logger) WithContext(ctx context.Context) *Logger {
	newLogger := *l
	if sid, ok := ctx.Value("session_id").(string); ok {
		newLogger.sessionID = sid
	}
	if op, ok := ctx.Value("operator").(string); ok {
		newLogger.operator = op
	}
	return &newLogger
}

func (l *Logger) log(severity Severity, message string, opts ...func(*LogEntry)) {
	if !l.shouldLog(severity) {
		return
	}

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: l.sessionID,
		Operator:  l.operator,
		Module:    l.module,
		Severity:  severity,
		Message:   message,
	}

	for _, opt := range opts {
		opt(&entry)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal log entry: %v\n", err)
		return
	}

	fmt.Fprintln(l.output, string(data))
}

func (l *Logger) shouldLog(severity Severity) bool {
	levels := map[Severity]int{
		SeverityDebug:    0,
		SeverityInfo:     1,
		SeverityWarning:  2,
		SeverityError:    3,
		SeverityCritical: 4,
	}
	return levels[severity] >= levels[l.minLevel]
}

func (l *Logger) Debug(message string, opts ...func(*LogEntry)) {
	l.log(SeverityDebug, message, opts...)
}

func (l *Logger) Info(message string, opts ...func(*LogEntry)) {
	l.log(SeverityInfo, message, opts...)
}

func (l *Logger) Warning(message string, opts ...func(*LogEntry)) {
	l.log(SeverityWarning, message, opts...)
}

func (l *Logger) Error(message string, opts ...func(*LogEntry)) {
	l.log(SeverityError, message, opts...)
}

func (l *Logger) Critical(message string, opts ...func(*LogEntry)) {
	l.log(SeverityCritical, message, opts...)
}

func WithTarget(target string) func(*LogEntry) {
	return func(e *LogEntry) {
		e.Target = target
	}
}

func WithAction(action string) func(*LogEntry) {
	return func(e *LogEntry) {
		e.Action = action
	}
}

func WithResult(result string) func(*LogEntry) {
	return func(e *LogEntry) {
		e.Result = result
	}
}

func WithError(err error) func(*LogEntry) {
	return func(e *LogEntry) {
		if err != nil {
			e.Error = err.Error()
		}
	}
}

func WithExtra(key string, value interface{}) func(*LogEntry) {
	return func(e *LogEntry) {
		if e.Extra == nil {
			e.Extra = make(map[string]interface{})
		}
		e.Extra[key] = value
	}
}

func WithExtraMap(extra map[string]interface{}) func(*LogEntry) {
	return func(e *LogEntry) {
		if e.Extra == nil {
			e.Extra = make(map[string]interface{})
		}
		for k, v := range extra {
			e.Extra[k] = v
		}
	}
}
