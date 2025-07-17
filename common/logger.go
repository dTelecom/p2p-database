package common

import (
	"context"
	"log/slog"
)

// slogLogger implements the Logger interface using Go's standard slog package
type slogLogger struct {
	logger *slog.Logger
}

// NewSlogLogger creates a logger using Go's standard slog (recommended for Go 1.23.11+)
func NewSlogLogger(logger *slog.Logger) Logger {
	return &slogLogger{logger: logger}
}

func (l *slogLogger) Debug(msg string, keysAndValues ...interface{}) {
	l.logger.Debug(msg, keysAndValues...)
}

func (l *slogLogger) Info(msg string, keysAndValues ...interface{}) {
	l.logger.Info(msg, keysAndValues...)
}

func (l *slogLogger) Warn(msg string, keysAndValues ...interface{}) {
	l.logger.Warn(msg, keysAndValues...)
}

func (l *slogLogger) Error(msg string, keysAndValues ...interface{}) {
	l.logger.Error(msg, keysAndValues...)
}

func (l *slogLogger) DebugEnabled() bool {
	return l.logger.Enabled(context.Background(), slog.LevelDebug)
}

// LiveKitLogger defines the interface expected by LiveKit logging
// with keyed logging methods ending in 'w' (Debugw, Infow, etc.)
type LiveKitLogger interface {
	Debugw(msg string, keysAndValues ...interface{})
	Infow(msg string, keysAndValues ...interface{})
	Warnw(msg string, err error, keysAndValues ...interface{})
	Errorw(msg string, err error, keysAndValues ...interface{})
}

// livekitLoggerAdapter adapts external LiveKit loggers to our Logger interface
type livekitLoggerAdapter struct {
	logger LiveKitLogger
}

// NewLivekitLoggerAdapter creates a logger adapter for LiveKit loggers
// LiveKit loggers typically use methods like Debugw, Infow, Warnw, Errorw
// that accept keyed logging with variadic key-value pairs
func NewLivekitLoggerAdapter(logger LiveKitLogger) Logger {
	return &livekitLoggerAdapter{logger: logger}
}

func (l *livekitLoggerAdapter) Debug(msg string, keysAndValues ...interface{}) {
	l.logger.Debugw(msg, keysAndValues...)
}

func (l *livekitLoggerAdapter) Info(msg string, keysAndValues ...interface{}) {
	l.logger.Infow(msg, keysAndValues...)
}

func (l *livekitLoggerAdapter) Warn(msg string, keysAndValues ...interface{}) {
	l.logger.Warnw(msg, nil, keysAndValues...)
}

func (l *livekitLoggerAdapter) Error(msg string, keysAndValues ...interface{}) {
	l.logger.Errorw(msg, nil, keysAndValues...)
}

func (l *livekitLoggerAdapter) DebugEnabled() bool {
	// LiveKit loggers don't typically have a debug enabled check
	// so we assume debug is always enabled
	return true
}
