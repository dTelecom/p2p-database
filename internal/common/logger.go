package common

import (
	"fmt"
)

type Logger interface {
	Debugw(msg string, keysAndValues ...interface{})
	Infow(msg string, keysAndValues ...interface{})
	Warnw(msg string, err error, keysAndValues ...interface{})
	Errorw(msg string, err error, keysAndValues ...interface{})

	// Add these methods to match the usage in the codebase
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})

	// Add Debug method to satisfy StandardLogger interface
	Debug(args ...interface{})
}

func printMessage(level, msg string, keysAndValues ...interface{}) {
	msg = fmt.Sprintf(msg, keysAndValues...)
	fmt.Printf("%s: %s\n", level, msg)
}

func printMessageWithError(level, msg string, err error, keysAndValues ...interface{}) {
	msg = fmt.Sprintf(msg, keysAndValues...)
	fmt.Printf("%s: %s (err = %s)\n", level, msg, err.Error())
}

type ConsoleLogger struct{}

func (c ConsoleLogger) Debugw(msg string, keysAndValues ...interface{}) {
	printMessage("DEBUG", msg, keysAndValues...)
}

func (c ConsoleLogger) Infow(msg string, keysAndValues ...interface{}) {
	printMessage("INFO", msg, keysAndValues...)
}

func (c ConsoleLogger) Warnw(msg string, err error, keysAndValues ...interface{}) {
	printMessageWithError("WARN", msg, err, keysAndValues...)
}

func (c ConsoleLogger) Errorw(msg string, err error, keysAndValues ...interface{}) {
	printMessageWithError("ERROR", msg, err, keysAndValues...)
}

// Implement the additional methods
func (c ConsoleLogger) Debugf(format string, args ...interface{}) {
	printMessage("DEBUG", format, args...)
}

func (c ConsoleLogger) Infof(format string, args ...interface{}) {
	printMessage("INFO", format, args...)
}

func (c ConsoleLogger) Warnf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("WARN: %s\n", msg)
}

func (c ConsoleLogger) Errorf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("ERROR: %s\n", msg)
}

func (c ConsoleLogger) Debug(args ...interface{}) {
	fmt.Printf("DEBUG: %s\n", fmt.Sprint(args...))
}
