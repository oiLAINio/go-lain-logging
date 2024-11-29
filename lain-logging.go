// lain_logging.go

/*
Package logging provides a customizable logger based on logrus.
It offers a global logger that can be initialized with default fields
and is accessible throughout your application.

Designed to unify how I implement logs across all my microservices
and reduce boilerplate. Set, Forget, Call, Go home early

Features:

- Global logger with default fields (e.g., env, version, host)
- Supports log levels: Panic, Fatal, Error, Warn, Info, Debug, Trace
- Customizable formatters (text, JSON)
- Ability to add hooks (e.g., InfluxDB hook)
- Thread-safe for concurrent use

Usage:

Initialize the logger once in your main function or initialization code:

    import (
        "os"
        "github.com/oiLAINio/go-lain-logging"
    )

    func main() {
        defaultFields := logging.Fields{
            "env":     "development",
            "version": "1.0.0",
            "host":    "localhost",
        }

        logging.InitLogger(
            os.Stdout,
            logging.DebugLevel,
            logging.TextFormatter(),
            defaultFields,
        )

        // Use the logger
        logging.Log.Info("Application started")
    }


In other parts of your application, import the logging package and use the logger:

    import "github.com/oiLAINio/go-lain-logging"

    func someFunction() {
        logging.Log.WithField("module", "someFunction").Info("This is a log message")
    }


## Adding fields on the fly:

You can add new fields by using "WithFields()" for example:

	func someFunction() {
		logging.Log.WithFields(logging.Fields{
			"module": "someFunction",
			"test":   "ok",
		}).Warn("A warning from someFunction")
	}

If you're adding just one additional field, you can use WithField instead:

	func anotherFunction() {
		logging.Log.WithField("userID", 12345).Info("User logged in")
	}

You can also use WithError to include error information in your logs:

	func processData() {
		err := doSomething()
		if err != nil {
			logging.Log.WithFields(logging.Fields{
				"module": "processData",
				"step":   "doSomething",
			}).WithError(err).Error("An error occurred while processing data")
		}
	}

	func doSomething() error {
		// Simulate an error
		return fmt.Errorf("simulated error")
	}

Sample Output:
ERROR   [2024-11-29T12:00:00-07:00]   An error occurred while processing data env=development version=1.0.0 host=localhost module=processData step=doSomething error="simulated error"


Adding Hooks:

To add a hook (e.g., InfluxDB hook), use the AddHook method:

    influxdbHook := &InfluxDBHook{
        // Initialize your hook
    }
    logging.Log.AddHook(influxdbHook)

*/

package lain_logging

import (
	"io"

	"github.com/sirupsen/logrus"
)

// LogLevel represents the severity of the log message.
type LogLevel uint32

const (
	PanicLevel LogLevel = iota // 0
	FatalLevel                 // 1
	ErrorLevel                 // 2
	WarnLevel                  // 3
	InfoLevel                  // 4
	DebugLevel                 // 5
	TraceLevel                 // 6
)

// Logger defines the interface for our custom logger.
type Logger interface {
	Trace(args ...interface{})
	Debug(args ...interface{})
	Info(args ...interface{})
	Warn(args ...interface{})
	Error(args ...interface{})
	Fatal(args ...interface{})
	Panic(args ...interface{})
	WithField(key string, value interface{}) Logger
	WithFields(fields Fields) Logger
	SetLevel(level LogLevel)
	WithError(err error) Logger
	AddHook(hook logrus.Hook)
}

// Fields type, used to pass to `WithFields`.
type Fields map[string]interface{}

type logger struct {
	entry *logrus.Entry
}

func (l *logger) Trace(args ...interface{}) {
	l.entry.Trace(args...)
}

func (l *logger) Debug(args ...interface{}) {
	l.entry.Debug(args...)
}

func (l *logger) Info(args ...interface{}) {
	l.entry.Info(args...)
}

func (l *logger) Warn(args ...interface{}) {
	l.entry.Warn(args...)
}

func (l *logger) Error(args ...interface{}) {
	l.entry.Error(args...)
}

func (l *logger) Fatal(args ...interface{}) {
	l.entry.Fatal(args...)
}

func (l *logger) Panic(args ...interface{}) {
	l.entry.Panic(args...)
}

func (l *logger) WithField(key string, value interface{}) Logger {
	return &logger{entry: l.entry.WithField(key, value)}
}

func (l *logger) WithFields(fields Fields) Logger {
	return &logger{entry: l.entry.WithFields(logrus.Fields(fields))}
}

func (l *logger) SetLevel(level LogLevel) {
	l.entry.Logger.SetLevel(logrus.Level(level))
}

// NewLogger creates a new instance of our custom logger.
func NewLogger(output io.Writer, level LogLevel, formatter logrus.Formatter) Logger {
	baseLogger := logrus.New()
	baseLogger.SetOutput(output)
	baseLogger.SetLevel(logrus.Level(level))
	baseLogger.SetFormatter(formatter)

	return &logger{
		entry: logrus.NewEntry(baseLogger),
	}
}

// Package-level logger
var Log Logger

// InitLogger initializes the package-level logger with default fields.
func InitLogger(output io.Writer, level LogLevel, formatter logrus.Formatter, defaultFields Fields) {
	baseLogger := logrus.New()
	baseLogger.SetOutput(output)
	baseLogger.SetLevel(logrus.Level(level))
	baseLogger.SetFormatter(formatter)

	// Create an entry with default fields
	entry := logrus.NewEntry(baseLogger).WithFields(logrus.Fields(defaultFields))

	// Assign the entry to the package-level logger
	Log = &logger{
		entry: entry,
	}
}

// TextFormatter returns a logrus formatter for text output.
func TextFormatter() logrus.Formatter {
	return &logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02T15:04:05-07:00",
		ForceColors:     true,
		DisableColors:   false,
		PadLevelText:    true,
	}
}

// JSONFormatter returns a logrus formatter for JSON output.
func JSONFormatter() logrus.Formatter {
	return &logrus.JSONFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
	}
}

// Update logger struct methods
func (l *logger) WithError(err error) Logger {
	return &logger{entry: l.entry.WithError(err)}
}

// MultiWriter allows writing to multiple io.Writer destinations.
func MultiWriter(writers ...io.Writer) io.Writer {
	return io.MultiWriter(writers...)
}

func (l *logger) AddHook(hook logrus.Hook) {
	l.entry.Logger.AddHook(hook)
}
