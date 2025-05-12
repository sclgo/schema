package schema

import (
	"context"
	"database/sql"
)

// DB is the common interface for database operations, compatible with
// database/sql.DB and database/sql.Tx.
type DB interface {
	//ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	//QueryRowContext(context.Context, string, ...interface{}) *sql.Row
	//PrepareContext(context.Context, string) (*sql.Stmt, error)
}
