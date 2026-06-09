package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

var (
	// LevelFlagOptions represents allowed logging levels.
	LevelFlagOptions = []string{"debug", "info", "warn", "error"}
	// FormatFlagOptions represents allowed formats.
	FormatFlagOptions = []string{"logfmt", "json"}

	defaultWriter = os.Stderr
)

// Logger is a wrapper around zap.SugaredLogger that provides a consistent logging interface
type Logger struct {
	*slog.Logger
}

// Config is a struct containing configurable settings for the logger
type Config struct {
	Level  *Level
	Format *Format
	Writer io.Writer
}

// New returns a new slog.Logger. Each logged line will be annotated
// with a timestamp. The output always goes to stderr.
func New(config *Config) *slog.Logger {
	if config.Level == nil {
		config.Level = NewLevel()
	}

	if config.Writer == nil {
		config.Writer = defaultWriter
	}

	logHandlerOpts := &slog.HandlerOptions{
		Level:     config.Level.lvl,
		AddSource: false,
	}

	if config.Format != nil && config.Format.s == "logfmt" {
		return slog.New(slog.NewTextHandler(config.Writer, logHandlerOpts))
	}
	return slog.New(slog.NewJSONHandler(config.Writer, logHandlerOpts))
}

// NewNopLogger is a convenience function to return an slog.Logger that writes
// to io.Discard.
func NewNopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Level controls a logging level, with an info default.
// It wraps slog.LevelVar with string-based level control.
// Level is safe to be used concurrently.
type Level struct {
	lvl *slog.LevelVar
}

// NewLevel returns a new Level.
func NewLevel() *Level {
	return &Level{
		lvl: &slog.LevelVar{},
	}
}

// String returns the current level.
func (l *Level) String() string {
	switch l.lvl.Level() {
	case slog.LevelDebug:
		return "debug"
	case slog.LevelInfo:
		return "info"
	case slog.LevelWarn:
		return "warn"
	case slog.LevelError:
		return "error"
	default:
		return ""
	}
}

// Set updates the logging level with the validation.
func (l *Level) Set(s string) error {
	switch strings.ToLower(s) {
	case "debug":
		l.lvl.Set(slog.LevelDebug)
	case "info":
		l.lvl.Set(slog.LevelInfo)
	case "warn":
		l.lvl.Set(slog.LevelWarn)
	case "error":
		l.lvl.Set(slog.LevelError)
	default:
		return fmt.Errorf("unrecognized log level %s", s)
	}
	return nil
}

// Format controls a logging output format.
// Not concurrency-safe.
type Format struct {
	s string
}

// NewFormat creates a new Format.
func NewFormat() *Format { return &Format{} }

func (f *Format) String() string {
	return f.s
}

// Set updates the value of the allowed format.
func (f *Format) Set(s string) error {
	switch s {
	case "logfmt", "json":
		f.s = s
	default:
		return fmt.Errorf("unrecognized log format %s", s)
	}
	return nil
}
