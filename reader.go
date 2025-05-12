package schema

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type LoggingQueryer struct {
	db      DB
	logger  Logger
	dryRun  bool
	timeout time.Duration
}

type Logger interface {
	Println(...any)
}

type LoggerFunc func(...any)

// Println implements Logger
func (f LoggerFunc) Println(args ...any) {
	f(args...)
}

var LoggerFmt Logger = LoggerFunc(func(v ...any) {
	fmt.Println(v...)
})

func NewLoggingQueryer(db DB, opts ...LoggingOption) LoggingQueryer {
	r := LoggingQueryer{
		db: db,
	}
	for _, o := range opts {
		o(&r)
	}
	return r
}

type LoggingOption func(*LoggingQueryer)

// WithLogger used to log queries before executing them
func WithLogger(l Logger) LoggingOption {
	return func(r *LoggingQueryer) {
		r.logger = l
	}
}

// WithDryRun allows to avoid running any queries
func WithDryRun(d bool) LoggingOption {
	return func(r *LoggingQueryer) {
		r.dryRun = d
	}
}

// WithTimeout for a single query
func WithTimeout(t time.Duration) LoggingOption {
	return func(r *LoggingQueryer) {
		r.timeout = t
	}
}

func (r LoggingQueryer) Query(q string, v ...any) (*sql.Rows, CloseFunc, error) {
	if r.logger != nil {
		r.logger.Println(q)
		r.logger.Println(v)
	}
	if r.dryRun {
		return nil, nil, sql.ErrNoRows
	}
	if r.timeout != 0 {
		ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
		rows, err := r.db.QueryContext(ctx, q, v...)
		return rows, func() { cancel(); rows.Close() }, err
	}
	rows, err := r.db.QueryContext(context.Background(), q, v...)
	return rows, func() { rows.Close() }, err
}

// CloseFunc should be called when result won't be processed anymore
type CloseFunc func()
