package common

import (
	"testing"
)

// Compile-time interface check
var _ Logger = (*livekitLoggerAdapter)(nil)

// MockLiveKitLogger implements the LiveKitLogger interface for testing
type MockLiveKitLogger struct {
	debugCalls []LogCall
	infoCalls  []LogCall
	warnCalls  []LogCallWithError
	errorCalls []LogCallWithError
}

type LogCall struct {
	Message       string
	KeysAndValues []interface{}
}

type LogCallWithError struct {
	Message       string
	Error         error
	KeysAndValues []interface{}
}

func (m *MockLiveKitLogger) Debugw(msg string, keysAndValues ...interface{}) {
	m.debugCalls = append(m.debugCalls, LogCall{
		Message:       msg,
		KeysAndValues: keysAndValues,
	})
}

func (m *MockLiveKitLogger) Infow(msg string, keysAndValues ...interface{}) {
	m.infoCalls = append(m.infoCalls, LogCall{
		Message:       msg,
		KeysAndValues: keysAndValues,
	})
}

func (m *MockLiveKitLogger) Warnw(msg string, err error, keysAndValues ...interface{}) {
	m.warnCalls = append(m.warnCalls, LogCallWithError{
		Message:       msg,
		Error:         err,
		KeysAndValues: keysAndValues,
	})
}

func (m *MockLiveKitLogger) Errorw(msg string, err error, keysAndValues ...interface{}) {
	m.errorCalls = append(m.errorCalls, LogCallWithError{
		Message:       msg,
		Error:         err,
		KeysAndValues: keysAndValues,
	})
}

func TestLiveKitLoggerAdapter(t *testing.T) {
	// Create mock LiveKit logger
	mockLogger := &MockLiveKitLogger{}

	// Create adapter
	adapter := NewLivekitLoggerAdapter(mockLogger)

	// Test Debug
	adapter.Debug("debug message", "key1", "value1", "key2", "value2")
	if len(mockLogger.debugCalls) != 1 {
		t.Errorf("Expected 1 debug call, got %d", len(mockLogger.debugCalls))
	}
	if mockLogger.debugCalls[0].Message != "debug message" {
		t.Errorf("Expected 'debug message', got '%s'", mockLogger.debugCalls[0].Message)
	}

	// Test Info
	adapter.Info("info message", "info_key", "info_value")
	if len(mockLogger.infoCalls) != 1 {
		t.Errorf("Expected 1 info call, got %d", len(mockLogger.infoCalls))
	}
	if mockLogger.infoCalls[0].Message != "info message" {
		t.Errorf("Expected 'info message', got '%s'", mockLogger.infoCalls[0].Message)
	}

	// Test Warn
	adapter.Warn("warn message", "warn_key", "warn_value")
	if len(mockLogger.warnCalls) != 1 {
		t.Errorf("Expected 1 warn call, got %d", len(mockLogger.warnCalls))
	}
	if mockLogger.warnCalls[0].Message != "warn message" {
		t.Errorf("Expected 'warn message', got '%s'", mockLogger.warnCalls[0].Message)
	}
	if mockLogger.warnCalls[0].Error != nil {
		t.Errorf("Expected nil error, got %v", mockLogger.warnCalls[0].Error)
	}

	// Test Error
	adapter.Error("error message", "error_key", "error_value")
	if len(mockLogger.errorCalls) != 1 {
		t.Errorf("Expected 1 error call, got %d", len(mockLogger.errorCalls))
	}
	if mockLogger.errorCalls[0].Message != "error message" {
		t.Errorf("Expected 'error message', got '%s'", mockLogger.errorCalls[0].Message)
	}
	if mockLogger.errorCalls[0].Error != nil {
		t.Errorf("Expected nil error, got %v", mockLogger.errorCalls[0].Error)
	}

	// Test DebugEnabled
	if !adapter.DebugEnabled() {
		t.Error("Expected DebugEnabled to return true")
	}
}
