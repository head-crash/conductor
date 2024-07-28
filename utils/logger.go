package utils

import (
	"log"
)

// Logger is a simple wrapper around the log package
type Logger struct {
	*log.Logger
}

// NewLogger creates a new Logger instance
func NewLogger() *Logger {
	return &Logger{log.New(log.Writer(), log.Prefix(), log.Flags())}
}

// Debug logs a message at the debug level
func (l *Logger) Debug(v ...interface{}) {
	l.Println("[DEBUG]", v)
}

// Info logs a message at the info level
func (l *Logger) Info(v ...interface{}) {
	l.Println("[INFO]", v)
}

// Warn logs a message at the warn level
func (l *Logger) Warn(v ...interface{}) {
	l.Println("[WARN]", v)
}

// Error logs a message at the error level
func (l *Logger) Error(v ...interface{}) {
	l.Println("[ERROR]", v)
}

// Fatal logs a message at the fatal level
func (l *Logger) Fatal(v ...interface{}) {
	l.Println("[FATAL]", v)
}

// Debugf logs a formatted message at the debug level
func (l *Logger) Debugf(format string, v ...interface{}) {
	l.Print("[DEBUG] ", format, v)
}

// Infof logs a formatted message at the info level
func (l *Logger) Infof(format string, v ...interface{}) {
	l.Print("[INFO] ", format, v)
}

// Warnf logs a formatted message at the warn level
func (l *Logger) Warnf(format string, v ...interface{}) {
	l.Print("[WARN] ", format, v)
}

// Errorf logs a formatted message at the error level
func (l *Logger) Errorf(format string, v ...interface{}) {
	l.Print("[ERROR] ", format, v)
}

// Fatalf logs a formatted message at the fatal level
func (l *Logger) Fatalf(format string, v ...interface{}) {
	l.Print("[FATAL] ", format, v)
}
