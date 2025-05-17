package p2p_database

import (
	"github.com/dTelecom/p2p-database/internal/common"
	"github.com/dTelecom/p2p-database/logger"
)

// NewLivekitLoggerAdapter creates a new adapter specifically for LiveKit loggers.
// This adapter works with loggers that have the Debugw, Infow, Warnw, and Errorw methods.
func NewLivekitLoggerAdapter(livekitLogger logger.LivekitLogger) common.Logger {
	return logger.NewLivekitLoggerAdapter(livekitLogger)
}

// NewConsoleLogger creates a new simple console logger that can be used with Connect.
func NewConsoleLogger() common.Logger {
	return new(common.ConsoleLogger)
}
