package logger

import (
	"fmt"

	"github.com/dTelecom/p2p-database/internal/common"
)

// LivekitLogger defines the interface expected for LiveKit loggers
type LivekitLogger interface {
	Debugw(msg string, keysAndValues ...interface{})
	Infow(msg string, keysAndValues ...interface{})
	Warnw(msg string, err error, keysAndValues ...interface{})
	Errorw(msg string, err error, keysAndValues ...interface{})
}

// LivekitLoggerAdapter adapts a LiveKit logger to our internal logger interface
type LivekitLoggerAdapter struct {
	logger LivekitLogger
}

// NewLivekitLoggerAdapter creates a new adapter for LiveKit loggers
func NewLivekitLoggerAdapter(logger LivekitLogger) common.Logger {
	return &LivekitLoggerAdapter{logger: logger}
}

// Direct pass-through methods
func (a *LivekitLoggerAdapter) Debugw(msg string, keysAndValues ...interface{}) {
	a.logger.Debugw(msg, keysAndValues...)
}

func (a *LivekitLoggerAdapter) Infow(msg string, keysAndValues ...interface{}) {
	a.logger.Infow(msg, keysAndValues...)
}

func (a *LivekitLoggerAdapter) Warnw(msg string, err error, keysAndValues ...interface{}) {
	a.logger.Warnw(msg, err, keysAndValues...)
}

func (a *LivekitLoggerAdapter) Errorw(msg string, err error, keysAndValues ...interface{}) {
	a.logger.Errorw(msg, err, keysAndValues...)
}

// Format-based methods use the w-style methods underneath
func (a *LivekitLoggerAdapter) Debugf(format string, args ...interface{}) {
	a.logger.Debugw(fmt.Sprintf(format, args...))
}

func (a *LivekitLoggerAdapter) Infof(format string, args ...interface{}) {
	a.logger.Infow(fmt.Sprintf(format, args...))
}

func (a *LivekitLoggerAdapter) Warnf(format string, args ...interface{}) {
	a.logger.Warnw(fmt.Sprintf(format, args...), nil)
}

func (a *LivekitLoggerAdapter) Errorf(format string, args ...interface{}) {
	a.logger.Errorw(fmt.Sprintf(format, args...), nil)
}

// Debug implements the standard Debug method by using Debugw
func (a *LivekitLoggerAdapter) Debug(args ...interface{}) {
	a.logger.Debugw(fmt.Sprint(args...))
}
