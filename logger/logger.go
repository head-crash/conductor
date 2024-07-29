package logger

import (
	"fmt"
	"log"
	"os"
	"time"
)

type Loglevel string

const (
	INFO  Loglevel = "INFO"
	WARN  Loglevel = "WARN"
	ERROR Loglevel = "ERROR"
	DEBUG Loglevel = "DEBUG"
)

var LogLevelOrder = map[Loglevel]int{
	INFO:  0,
	WARN:  1,
	ERROR: 2,
	DEBUG: 3,
}

type Logger struct {
	*log.Logger
	loglevel Loglevel
}

func loggerTimeStamp() string {
	return time.Now().Format("2006/01/02-15:04:05")
}

func NewLogger() *Logger {
	newLogger := &Logger{
		log.New(os.Stdout, "", log.LstdFlags),
		INFO,
	}
	newLogger.Info(fmt.Sprintf("Logger initialized with log level %s", newLogger.loglevel))
	newLogger.Debug("!!! Debug log level enabled !!!")
	return newLogger
}

func (l *Logger) ShouldBeLogged(loglevel Loglevel) bool {
	return LogLevelOrder[l.loglevel] >= LogLevelOrder[loglevel]
}

func (l *Logger) Write(loglevel Loglevel, msg string, v ...any) {
	if l.ShouldBeLogged(loglevel) {
		l.Writer().Write([]byte(
			fmt.Sprintf("[LOG-%s][%v] %s\n", loglevel, loggerTimeStamp(), fmt.Sprintf(msg, v...)),
		))
	}
}

func (l *Logger) Info(msg string, v ...any) {
	l.Write(INFO, msg, v...)
}

func (l *Logger) Warn(msg string, v ...any) {
	l.Write(WARN, msg, v...)
}

func (l *Logger) Error(msg string, v ...any) {
	l.Write(ERROR, msg, v...)
}

func (l *Logger) Debug(msg string, v ...any) {
	l.Write(DEBUG, msg, v...)
}

func (l *Logger) SetLogLevel(loglevel Loglevel) {
	l.loglevel = loglevel
	l.Info(fmt.Sprintf("Log level set to %s", loglevel))
}

func (l *Logger) GetLogLevel() Loglevel {
	return l.loglevel
}

var Default = NewLogger()
