package logger

import (
	"fmt"
	"log"
	"os"
	"sync"
)

type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
)

var (
	defaultLogger *Logger
	once          sync.Once
)

type Logger struct {
	level  Level
	logger *log.Logger
	mu     sync.Mutex
}

func init() {
	defaultLogger = &Logger{
		level:  INFO, // default level is INFO
		logger: log.New(os.Stdout, "", log.LstdFlags),
	}
}

// GetLogger returns the default logger instance
func GetLogger() *Logger {
	return defaultLogger
}

// SetLevel sets the logging level
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// GetLevel returns the current logging level
func (l *Logger) GetLevel() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

// Printf logs a message at DEBUG level
func Printf(format string, args ...interface{}) {
	defaultLogger.log(DEBUG, format, args...)
}

// Debug logs a message at DEBUG level
func Debug(format string, args ...interface{}) {
	defaultLogger.log(DEBUG, format, args...)
}

// Debugf logs a formatted message at DEBUG level
func Debugf(format string, args ...interface{}) {
	defaultLogger.log(DEBUG, format, args...)
}

// Info logs a message at INFO level
func Info(format string, args ...interface{}) {
	defaultLogger.log(INFO, format, args...)
}

// Warn logs a message at WARN level
func Warn(format string, args ...interface{}) {
	defaultLogger.log(WARN, format, args...)
}

// Error logs a message at ERROR level
func Error(format string, args ...interface{}) {
	defaultLogger.log(ERROR, format, args...)
}

func (l *Logger) log(level Level, format string, args ...interface{}) {
	if level >= l.level {
		l.mu.Lock()
		defer l.mu.Unlock()
		msg := fmt.Sprintf(format, args...)
		l.logger.Printf("[%s] %s", getLevelString(level), msg)
	}
}

func getLevelString(level Level) string {
	switch level {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}
