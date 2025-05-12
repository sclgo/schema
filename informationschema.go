// Package schema provides metadata readers that query tables from
// the information_schema schema. It tries to be database agnostic,
// but there is a set of options to configure what tables and columns to expect.
package schema

import (
	"database/sql"
	"fmt"
	"strings"
)

type Queryer interface {
	Query(q string, v ...any) (*sql.Rows, CloseFunc, error)
}

// InformationSchema metadata reader
type InformationSchema struct {
	q                   Queryer
	pf                  func(int) string
	hasFunctions        bool
	hasSequences        bool
	hasIndexes          bool
	hasConstraints      bool
	hasCheckConstraints bool
	hasTablePrivileges  bool
	hasColumnPrivileges bool
	hasUsagePrivileges  bool
	clauses             map[ClauseName]string
	limit               int
	systemSchemas       []string
	currentSchema       string
	dataTypeFormatter   func(Column) string
}

type ClauseName string

const (
	ColumnsDataType         = ClauseName("columns.data_type")
	ColumnsColumnSize       = ClauseName("columns.column_size")
	ColumnsNumericScale     = ClauseName("columns.numeric_scale")
	ColumnsNumericPrecRadix = ClauseName("columns.numeric_precision_radix")
	ColumnsCharOctetLength  = ClauseName("columns.character_octet_length")

	FunctionColumnsColumnSize       = ClauseName("function_columns.column_size")
	FunctionColumnsNumericScale     = ClauseName("function_columns.numeric_scale")
	FunctionColumnsNumericPrecRadix = ClauseName("function_columns.numeric_precision_radix")
	FunctionColumnsCharOctetLength  = ClauseName("function_columns.character_octet_length")

	FunctionsSecurityType = ClauseName("functions.security_type")

	ConstraintIsDeferrable      = ClauseName("constraint_columns.is_deferrable")
	ConstraintInitiallyDeferred = ClauseName("constraint_columns.initially_deferred")
	ConstraintJoinCond          = ClauseName("constraint_join.fk")

	SequenceColumnsIncrement = ClauseName("sequence_columns.increment")

	PrivilegesGrantor = ClauseName("privileges.grantor")
)

// New InformationSchema reader
func New(q Queryer, opts ...ReaderOption) *InformationSchema {
	s := &InformationSchema{
		pf:                  func(n int) string { return fmt.Sprintf("$%d", n) },
		hasFunctions:        true,
		hasSequences:        true,
		hasIndexes:          true,
		hasConstraints:      true,
		hasCheckConstraints: true,
		hasTablePrivileges:  true,
		hasColumnPrivileges: true,
		hasUsagePrivileges:  true,
		clauses: map[ClauseName]string{
			ColumnsDataType:                 "data_type",
			ColumnsColumnSize:               "COALESCE(character_maximum_length, numeric_precision, datetime_precision, 0)",
			ColumnsNumericScale:             "COALESCE(numeric_scale, 0)",
			ColumnsNumericPrecRadix:         "COALESCE(numeric_precision_radix, 10)",
			ColumnsCharOctetLength:          "COALESCE(character_octet_length, 0)",
			FunctionColumnsColumnSize:       "COALESCE(character_maximum_length, numeric_precision, datetime_precision, 0)",
			FunctionColumnsNumericScale:     "COALESCE(numeric_scale, 0)",
			FunctionColumnsNumericPrecRadix: "COALESCE(numeric_precision_radix, 10)",
			FunctionColumnsCharOctetLength:  "COALESCE(character_octet_length, 0)",
			FunctionsSecurityType:           "security_type",
			ConstraintIsDeferrable:          "t.is_deferrable",
			ConstraintInitiallyDeferred:     "t.initially_deferred",
			SequenceColumnsIncrement:        "increment",
			PrivilegesGrantor:               "grantor",
		},
		systemSchemas:     []string{"information_schema"},
		dataTypeFormatter: func(col Column) string { return col.DataType },
		q:                 q,
	}
	// apply InformationSchema specific options
	for _, o := range opts {
		o(s)
	}

	return s
}

func NewFromDB(db DB, opts ...ReaderOption) *InformationSchema {
	return New(NewLoggingQueryer(db, WithLogger(LoggerFmt)), opts...)
}

type ReaderOption func(schema *InformationSchema)

// WithLimit for a single query
func WithLimit(l int) ReaderOption {
	return func(r *InformationSchema) {
		r.limit = l
	}
}

// WithPlaceholder generator function, that usually returns either `?` or `$n`,
// where `n` is the argument.
func WithPlaceholder(pf func(int) string) ReaderOption {
	return func(r *InformationSchema) {
		r.pf = pf
	}
}

// WithCustomClauses to use different expressions for some columns
func WithCustomClauses(cols map[ClauseName]string) ReaderOption {
	return func(r *InformationSchema) {
		for k, v := range cols {
			r.clauses[k] = v
		}
	}
}

// WithFunctions when the `routines` and `parameters` tables exists
func WithFunctions(fun bool) ReaderOption {
	return func(r *InformationSchema) {
		r.hasFunctions = fun
	}
}

// WithIndexes when the `statistics` table exists
func WithIndexes(ind bool) ReaderOption {
	return func(r *InformationSchema) {
		r.hasIndexes = ind
	}
}

// WithConstraints when the `statistics` table exists
func WithConstraints(con bool) ReaderOption {
	return func(r *InformationSchema) {
		r.hasConstraints = con
	}
}

// WithCheckConstraints when the `statistics` table exists
func WithCheckConstraints(con bool) ReaderOption {
	return func(r *InformationSchema) {
		r.hasCheckConstraints = con
	}
}

// WithSequences when the `sequences` table exists
func WithSequences(seq bool) ReaderOption {
	return func(r *InformationSchema) {
		r.hasSequences = seq
	}
}

// WithTablePrivileges when the `table_privileges` table exists
func WithTablePrivileges(t bool) ReaderOption {
	return func(r *InformationSchema) {
		r.hasTablePrivileges = t
	}
}

// WithColumnPrivileges when the `column_privileges` table exists
func WithColumnPrivileges(c bool) ReaderOption {
	return func(r *InformationSchema) {
		r.hasColumnPrivileges = c
	}
}

// WithUsagePrivileges when the `usage_privileges` table exists
func WithUsagePrivileges(u bool) ReaderOption {
	return func(r *InformationSchema) {
		r.hasUsagePrivileges = u
	}
}

// WithSystemSchemas that are ignored unless WithSystem filter is true
func WithSystemSchemas(schemas []string) ReaderOption {
	return func(r *InformationSchema) {
		r.systemSchemas = schemas
	}
}

// WithCurrentSchema expression to filter by when OnlyVisible filter is true
func WithCurrentSchema(expr string) ReaderOption {
	return func(r *InformationSchema) {
		r.currentSchema = expr
	}
}

// WithDataTypeFormatter function to build updated string representation of data type
// from Column
func WithDataTypeFormatter(f func(Column) string) ReaderOption {
	return func(r *InformationSchema) {
		r.dataTypeFormatter = f
	}
}

// Columns from selected catalog (or all, if empty), matching schemas and tables
func (s InformationSchema) Columns(f Filter) (*ColumnSet, error) {
	columns := []string{
		"table_catalog",
		"table_schema",
		"table_name",
		"column_name",
		"ordinal_position",
		s.clauses[ColumnsDataType],
		"COALESCE(column_default, '')",
		"COALESCE(is_nullable, '') AS is_nullable",
		s.clauses[ColumnsColumnSize],
		s.clauses[ColumnsNumericScale],
		s.clauses[ColumnsNumericPrecRadix],
		s.clauses[ColumnsCharOctetLength],
	}

	qstr := "SELECT\n  " + strings.Join(columns, ",\n  ") + " FROM information_schema.columns\n"
	conds, vals := s.conditions(1, f, formats{
		catalog:    "table_catalog LIKE %s",
		schema:     "table_schema LIKE %s",
		notSchemas: "table_schema NOT IN (%s)",
		parent:     "table_name LIKE %s",
	})
	rows, closeRows, err := s.query(qstr, conds, "table_catalog, table_schema, table_name, ordinal_position", vals...)
	if err != nil {
		if err == sql.ErrNoRows {
			return NewColumnSet([]Column{}), nil
		}
		return nil, err
	}
	defer closeRows()

	results := []Column{}
	for rows.Next() {
		rec := Column{}
		err = rows.Scan(
			&rec.Catalog,
			&rec.Schema,
			&rec.Table,
			&rec.Name,
			&rec.OrdinalPosition,
			&rec.DataType,
			&rec.Default,
			&rec.IsNullable,
			&rec.ColumnSize,
			&rec.DecimalDigits,
			&rec.NumPrecRadix,
			&rec.CharOctetLength,
		)
		if err != nil {
			return nil, err
		}
		rec.DataType = s.dataTypeFormatter(rec)
		results = append(results, rec)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return NewColumnSet(results), nil
}

// Tables from selected catalog (or all, if empty), matching schemas, names and types
func (s InformationSchema) Tables(f Filter) (*TableSet, error) {
	qstr := `SELECT
  table_catalog,
  table_schema,
  table_name,
  table_type
FROM information_schema.tables
`
	conds, vals := s.conditions(1, f, formats{
		catalog:    "table_catalog LIKE %s",
		schema:     "table_schema LIKE %s",
		notSchemas: "table_schema NOT IN (%s)",
		name:       "table_name LIKE %s",
		types:      "table_type IN (%s)",
	})
	if len(conds) != 0 {
		qstr += " WHERE " + strings.Join(conds, " AND ")
	}
	addSequences := false
	for _, t := range f.Types {
		if t == "SEQUENCE" && s.hasSequences {
			addSequences = true
		}
	}
	if addSequences {
		qstr += `
UNION ALL
SELECT
  sequence_catalog AS table_catalog,
  sequence_schema AS table_schema,
  sequence_name AS table_name,
  'SEQUENCE' AS table_type
FROM information_schema.sequences
`
		conds, seqVals := s.conditions(len(vals)+1, f, formats{
			catalog:    "sequence_catalog LIKE %s",
			schema:     "sequence_schema LIKE %s",
			notSchemas: "sequence_schema NOT IN (%s)",
			name:       "sequence_name LIKE %s",
		})
		vals = append(vals, seqVals...)
		if len(conds) != 0 {
			qstr += " WHERE " + strings.Join(conds, " AND ")
		}
	}
	rows, closeRows, err := s.query(qstr, []string{}, "table_catalog, table_schema, table_type, table_name", vals...)
	if err != nil {
		if err == sql.ErrNoRows {
			return NewTableSet([]Table{}), nil
		}
		return nil, err
	}
	defer closeRows()

	results := []Table{}
	for rows.Next() {
		rec := Table{}
		err = rows.Scan(&rec.Catalog, &rec.Schema, &rec.Name, &rec.Type)
		if err != nil {
			return nil, err
		}
		results = append(results, rec)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return NewTableSet(results), nil
}

// Schemas from selected catalog (or all, if empty), matching schemas and tables
func (s InformationSchema) Schemas(f Filter) (*SchemaSet, error) {
	qstr := `SELECT
  schema_name,
  catalog_name
FROM information_schema.schemata
`
	conds, vals := s.conditions(1, f, formats{
		catalog:    "catalog_name LIKE %s",
		name:       "schema_name LIKE %s",
		notSchemas: "schema_name NOT IN (%s)",
	})
	rows, closeRows, err := s.query(qstr, conds, "catalog_name, schema_name", vals...)
	if err != nil {
		if err == sql.ErrNoRows {
			return NewSchemaSet([]Schema{}), nil
		}
		return nil, err
	}
	defer closeRows()

	results := []Schema{}
	for rows.Next() {
		rec := Schema{}
		err = rows.Scan(&rec.Schema, &rec.Catalog)
		if err != nil {
			return nil, err
		}
		results = append(results, rec)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return NewSchemaSet(results), nil
}

// Functions from selected catalog (or all, if empty), matching schemas, names and types
func (s InformationSchema) Functions(f Filter) (*FunctionSet, error) {
	if !s.hasFunctions {
		return nil, ErrNotSupported
	}

	columns := []string{
		"specific_name",
		"routine_catalog",
		"routine_schema",
		"routine_name",
		"COALESCE(routine_type, '')",
		"COALESCE(data_type, '')",
		"routine_definition",
		"COALESCE(external_language, routine_body) AS language",
		"is_deterministic",
		s.clauses[FunctionsSecurityType],
	}

	qstr := "SELECT\n  " + strings.Join(columns, ",\n  ") + " FROM information_schema.routines\n"
	conds, vals := s.conditions(1, f, formats{
		catalog:    "routine_catalog LIKE %s",
		schema:     "routine_schema LIKE %s",
		notSchemas: "routine_schema NOT IN (%s)",
		name:       "routine_name LIKE %s",
		types:      "routine_type IN (%s)",
	})
	rows, closeRows, err := s.query(qstr, conds, "routine_catalog, routine_schema, routine_name, COALESCE(routine_type, '')", vals...)
	if err != nil {
		if err == sql.ErrNoRows {
			return NewFunctionSet([]Function{}), nil
		}
		return nil, err
	}
	defer closeRows()

	results := []Function{}
	for rows.Next() {
		rec := Function{}
		err = rows.Scan(
			&rec.SpecificName,
			&rec.Catalog,
			&rec.Schema,
			&rec.Name,
			&rec.Type,
			&rec.ResultType,
			&rec.Source,
			&rec.Language,
			&rec.Volatility,
			&rec.Security,
		)
		if err != nil {
			return nil, err
		}
		results = append(results, rec)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return NewFunctionSet(results), nil
}

// FunctionColumns (arguments) from selected catalog (or all, if empty), matching schemas and functions
func (s InformationSchema) FunctionColumns(f Filter) (*FunctionColumnSet, error) {
	if !s.hasFunctions {
		return nil, ErrNotSupported
	}

	columns := []string{
		"specific_catalog",
		"specific_schema",
		"specific_name",
		"COALESCE(parameter_name, '')",
		"ordinal_position",
		"COALESCE(parameter_mode, '')",
		"COALESCE(data_type, '')",
		s.clauses[FunctionColumnsColumnSize],
		s.clauses[FunctionColumnsNumericScale],
		s.clauses[FunctionColumnsNumericPrecRadix],
		s.clauses[FunctionColumnsCharOctetLength],
	}

	qstr := "SELECT\n  " + strings.Join(columns, ",\n  ") + " FROM information_schema.parameters\n"

	conds, vals := s.conditions(1, f, formats{
		catalog:    "specific_catalog LIKE %s",
		schema:     "specific_schema LIKE %s",
		notSchemas: "specific_schema NOT IN (%s)",
		parent:     "specific_name LIKE %s",
	})
	rows, closeRows, err := s.query(qstr, conds, "specific_catalog, specific_schema, specific_name, ordinal_position, COALESCE(parameter_name, '')", vals...)
	if err != nil {
		if err == sql.ErrNoRows {
			return NewFunctionColumnSet([]FunctionColumn{}), nil
		}
		return nil, err
	}
	defer closeRows()

	results := []FunctionColumn{}
	for rows.Next() {
		rec := FunctionColumn{}
		err = rows.Scan(
			&rec.Catalog,
			&rec.Schema,
			&rec.FunctionName,
			&rec.Name,
			&rec.OrdinalPosition,
			&rec.Type,
			&rec.DataType,
			&rec.ColumnSize,
			&rec.DecimalDigits,
			&rec.NumPrecRadix,
			&rec.CharOctetLength,
		)
		if err != nil {
			return nil, err
		}
		results = append(results, rec)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return NewFunctionColumnSet(results), nil
}

// Indexes from selected catalog (or all, if empty), matching schemas and names
func (s InformationSchema) Indexes(f Filter) (*IndexSet, error) {
	if !s.hasIndexes {
		return nil, ErrNotSupported
	}

	qstr := `SELECT
  table_catalog,
  index_schema,
  table_name,
  index_name,
  CASE WHEN non_unique = 0 THEN 'YES' ELSE 'NO' END AS is_unique,
  CASE WHEN index_name = 'PRIMARY' THEN 'YES' ELSE 'NO' END AS is_primary,
  index_type
FROM information_schema.statistics
`
	conds, vals := s.conditions(1, f, formats{
		catalog:    "table_catalog LIKE %s",
		schema:     "index_schema LIKE %s",
		notSchemas: "index_schema NOT IN (%s)",
		parent:     "table_name LIKE %s",
		name:       "index_name LIKE %s",
	})
	if len(conds) != 0 {
		qstr += " WHERE " + strings.Join(conds, " AND ")
	}
	qstr += `
GROUP BY table_catalog, index_schema, table_name, index_name,
  CASE WHEN non_unique = 0 THEN 'YES' ELSE 'NO' END,
  CASE WHEN index_name = 'PRIMARY' THEN 'YES' ELSE 'NO' END,
  index_type`
	rows, closeRows, err := s.query(qstr, []string{}, "table_catalog, index_schema, table_name, index_name", vals...)
	if err != nil {
		if err == sql.ErrNoRows {
			return NewIndexSet([]Index{}), nil
		}
		return nil, err
	}
	defer closeRows()

	results := []Index{}
	for rows.Next() {
		rec := Index{}
		err = rows.Scan(&rec.Catalog, &rec.Schema, &rec.Table, &rec.Name, &rec.IsUnique, &rec.IsPrimary, &rec.Type)
		if err != nil {
			return nil, err
		}
		results = append(results, rec)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return NewIndexSet(results), nil
}

// IndexColumns from selected catalog (or all, if empty), matching schemas and indexes
func (s InformationSchema) IndexColumns(f Filter) (*IndexColumnSet, error) {
	if !s.hasIndexes {
		return nil, ErrNotSupported
	}

	qstr := `SELECT
  i.table_catalog,
  i.table_schema,
  i.table_name,
  i.index_name,
  i.column_name,
  c.data_type,
  i.seq_in_index

FROM information_schema.statistics i
JOIN information_schema.columns c ON
  i.table_catalog = c.table_catalog AND
  i.table_schema = c.table_schema AND
  i.table_name = c.table_name AND
  i.column_name = c.column_name
`
	conds, vals := s.conditions(1, f, formats{
		catalog:    "i.table_catalog LIKE %s",
		schema:     "index_schema LIKE %s",
		notSchemas: "index_schema NOT IN (%s)",
		parent:     "i.table_name LIKE %s",
		name:       "index_name LIKE %s",
	})
	rows, closeRows, err := s.query(qstr, conds, "i.table_catalog, index_schema, table_name, index_name, seq_in_index", vals...)
	if err != nil {
		if err == sql.ErrNoRows {
			return NewIndexColumnSet([]IndexColumn{}), nil
		}
		return nil, err
	}
	defer closeRows()

	results := []IndexColumn{}
	for rows.Next() {
		rec := IndexColumn{}
		err = rows.Scan(&rec.Catalog, &rec.Schema, &rec.Table, &rec.IndexName, &rec.Name, &rec.DataType, &rec.OrdinalPosition)
		if err != nil {
			return nil, err
		}
		results = append(results, rec)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return NewIndexColumnSet(results), nil
}

// Constraints from selected catalog (or all, if empty), matching schemas and names
func (s InformationSchema) Constraints(f Filter) (*ConstraintSet, error) {
	if !s.hasConstraints {
		return nil, ErrNotSupported
	}

	columns := []string{
		"t.constraint_catalog",
		"t.table_schema",
		"t.table_name",
		"t.constraint_name",
		"t.constraint_type",
		s.clauses[ConstraintIsDeferrable],
		s.clauses[ConstraintInitiallyDeferred],
		"COALESCE(r.unique_constraint_catalog, '') AS foreign_catalog",
		"COALESCE(r.unique_constraint_schema, '') AS foreign_schema",
		"COALESCE(f.table_name, '') AS foreign_table",
		"COALESCE(r.unique_constraint_name, '') AS foreign_constraint",
		"COALESCE(r.match_option, '') AS match_options",
		"COALESCE(r.update_rule, '') AS update_rule",
		"COALESCE(r.delete_rule, '') AS delete_rule",
		"COALESCE(c.check_clause, '') AS check_clause",
	}

	qstr := "SELECT\n  " + strings.Join(columns, ",\n  ") + `
FROM information_schema.table_constraints t
LEFT JOIN information_schema.referential_constraints r ON t.constraint_catalog = r.constraint_catalog
  AND t.constraint_schema = r.constraint_schema
  AND t.constraint_name = r.constraint_name
  AND t.constraint_type = 'FOREIGN KEY'
LEFT JOIN information_schema.table_constraints f ON r.unique_constraint_catalog = f.constraint_catalog
  AND r.unique_constraint_schema = f.constraint_schema
  AND r.unique_constraint_name = f.constraint_name
  ` + s.clauses[ConstraintJoinCond] + `
LEFT JOIN information_schema.check_constraints c ON t.constraint_catalog = c.constraint_catalog
  AND t.constraint_schema = c.constraint_schema
  AND t.constraint_name = c.constraint_name
`
	conds, vals := s.conditions(1, f, formats{
		catalog:    "t.constraint_catalog LIKE %s",
		schema:     "t.table_schema LIKE %s",
		notSchemas: "t.table_schema NOT IN (%s)",
		parent:     "t.table_name LIKE %s",
		reference:  "f.table_name LIKE %s",
		name:       "t.constraint_name LIKE %s",
	})
	if len(conds) != 0 {
		qstr += " WHERE " + strings.Join(conds, " AND ")
	}
	rows, closeRows, err := s.query(qstr, []string{}, "t.constraint_catalog, t.table_schema, t.table_name, t.constraint_name", vals...)
	if err != nil {
		if err == sql.ErrNoRows {
			return NewConstraintSet([]Constraint{}), nil
		}
		return nil, err
	}
	defer closeRows()

	results := []Constraint{}
	for rows.Next() {
		rec := Constraint{}
		err = rows.Scan(
			&rec.Catalog,
			&rec.Schema,
			&rec.Table,
			&rec.Name,
			&rec.Type,
			&rec.IsDeferrable,
			&rec.IsInitiallyDeferred,
			&rec.ForeignCatalog,
			&rec.ForeignSchema,
			&rec.ForeignTable,
			&rec.ForeignName,
			&rec.MatchType,
			&rec.UpdateRule,
			&rec.DeleteRule,
			&rec.CheckClause,
		)
		if err != nil {
			return nil, err
		}
		results = append(results, rec)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return NewConstraintSet(results), nil
}

// ConstraintColumns from selected catalog (or all, if empty), matching schemas and constraints
func (s InformationSchema) ConstraintColumns(f Filter) (*ConstraintColumnSet, error) {
	if !s.hasConstraints {
		return nil, ErrNotSupported
	}

	vals := []interface{}{}
	qstr := ""
	if s.hasCheckConstraints {
		qstr = `SELECT
	  c.constraint_catalog,
	  c.table_schema,
	  c.table_name,
	  c.constraint_name,
	  c.column_name,
	  1 AS ordinal_position,
	  '' AS foreign_catalog,
	  '' AS foreign_schema,
	  '' AS foreign_table,
	  '' AS foreign_name
	FROM information_schema.constraint_column_usage c
	`
		conds, checkVals := s.conditions(len(vals)+1, f, formats{
			catalog:    "c.constraint_catalog LIKE %s",
			schema:     "c.table_schema LIKE %s",
			notSchemas: "c.table_schema NOT IN (%s)",
			parent:     "c.table_name LIKE %s",
			name:       "c.constraint_name LIKE %s",
		})
		if len(conds) != 0 {
			qstr += " WHERE " + strings.Join(conds, " AND ")
			vals = append(vals, checkVals...)
		}
		qstr += `
UNION ALL
`
	}
	qstr += `SELECT
  c.constraint_catalog,
  c.table_schema,
  c.table_name,
  c.constraint_name,
  c.column_name,
  c.ordinal_position,
  COALESCE(f.constraint_catalog, '') AS foreign_catalog,
  COALESCE(f.table_schema, '') AS foreign_schema,
  COALESCE(f.table_name, '') AS foreign_table,
  COALESCE(f.column_name, '') AS foreign_name
FROM information_schema.key_column_usage c
LEFT JOIN information_schema.referential_constraints r ON c.constraint_catalog = r.constraint_catalog
  AND c.constraint_schema = r.constraint_schema
  AND c.constraint_name = r.constraint_name
LEFT JOIN information_schema.key_column_usage f ON r.unique_constraint_catalog = f.constraint_catalog
  AND r.unique_constraint_schema = f.constraint_schema
  AND r.unique_constraint_name = f.constraint_name
  ` + s.clauses[ConstraintJoinCond] + `
  AND c.position_in_unique_constraint = f.ordinal_position
`
	conds, keyVals := s.conditions(len(vals)+1, f, formats{
		catalog:    "c.constraint_catalog LIKE %s",
		schema:     "c.table_schema LIKE %s",
		notSchemas: "c.table_schema NOT IN (%s)",
		parent:     "c.table_name LIKE %s",
		reference:  "f.table_name LIKE %s",
		name:       "c.constraint_name LIKE %s",
	})
	if len(conds) != 0 {
		qstr += " WHERE " + strings.Join(conds, " AND ")
		vals = append(vals, keyVals...)
	}
	rows, closeRows, err := s.query(qstr, []string{}, "constraint_catalog, table_schema, table_name, constraint_name, ordinal_position, column_name", vals...)
	if err != nil {
		if err == sql.ErrNoRows {
			return NewConstraintColumnSet([]ConstraintColumn{}), nil
		}
		return nil, err
	}
	defer closeRows()

	results := []ConstraintColumn{}
	i := 1
	for rows.Next() {
		rec := ConstraintColumn{OrdinalPosition: i}
		i++
		err = rows.Scan(
			&rec.Catalog,
			&rec.Schema,
			&rec.Table,
			&rec.Constraint,
			&rec.Name,
			&rec.OrdinalPosition,
			&rec.ForeignCatalog,
			&rec.ForeignSchema,
			&rec.ForeignTable,
			&rec.ForeignName,
		)
		if err != nil {
			return nil, err
		}
		results = append(results, rec)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return NewConstraintColumnSet(results), nil
}

// Sequences from selected catalog (or all, if empty), matching schemas and names
func (s InformationSchema) Sequences(f Filter) (*SequenceSet, error) {
	if !s.hasSequences {
		return nil, ErrNotSupported
	}
	columns := []string{
		"sequence_catalog",
		"sequence_schema",
		"sequence_name",
		"data_type",
		"start_value",
		"minimum_value",
		"maximum_value",
		s.clauses[SequenceColumnsIncrement],
		"cycle_option",
	}

	qstr := "SELECT\n  " + strings.Join(columns, ",\n  ") + " FROM information_schema.sequences\n"

	conds, vals := s.conditions(1, f, formats{
		catalog:    "sequence_catalog LIKE %s",
		schema:     "sequence_schema LIKE %s",
		notSchemas: "sequence_schema NOT IN (%s)",
		name:       "sequence_name LIKE %s",
	})
	rows, closeRows, err := s.query(qstr, conds, "sequence_catalog, sequence_schema, sequence_name", vals...)
	if err != nil {
		if err == sql.ErrNoRows {
			return NewSequenceSet([]Sequence{}), nil
		}
		return nil, err
	}
	defer closeRows()

	results := []Sequence{}
	for rows.Next() {
		rec := Sequence{}
		err = rows.Scan(&rec.Catalog, &rec.Schema, &rec.Name, &rec.DataType, &rec.Start, &rec.Min, &rec.Max, &rec.Increment, &rec.Cycles)
		if err != nil {
			return nil, err
		}
		results = append(results, rec)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return NewSequenceSet(results), nil
}

// PrivilegeSummaries of privileges on tables, views and sequences from selected catalog (or all, if empty), matching schemas and names
func (s InformationSchema) PrivilegeSummaries(f Filter) (*PrivilegeSummarySet, error) {
	if !s.hasTablePrivileges && !s.hasColumnPrivileges && !s.hasUsagePrivileges {
		return nil, ErrNotSupported
	}

	qstrs := []string{}
	conds, vals := s.conditions(1, f, formats{
		catalog:    "object_catalog LIKE %s",
		schema:     "object_schema LIKE %s",
		notSchemas: "object_schema NOT IN (%s)",
		name:       "object_name LIKE %s",
		types:      "object_type IN (%s)",
	})

	if s.hasTablePrivileges {
		columns := []string{
			"t.table_catalog AS object_catalog",
			"t.table_schema AS object_schema",
			"t.table_name AS object_name",
			"t.table_type AS object_type",
			"'' AS column_name",
			"COALESCE(grantee, '') AS grantee",
			"COALESCE(" + s.clauses[PrivilegesGrantor] + ", '') AS grantor",
			"COALESCE(privilege_type, '') AS privilege_type",
			"CASE WHEN is_grantable='YES' THEN 1 ELSE 0 END AS is_grantable",
		}

		// `tables` is on the left side of the join to also list tables that have no privileges set.
		qstr := "SELECT\n" +
			"  " + strings.Join(columns, ", ") + "\n" +
			"FROM information_schema.tables t\n" +
			"LEFT JOIN information_schema.table_privileges tp\n" +
			"  ON t.table_catalog = tp.table_catalog AND t.table_schema = tp.table_schema AND t.table_name = tp.table_name"
		qstrs = append(qstrs, qstr)
	}

	if s.hasColumnPrivileges {
		columns := []string{
			"t.table_catalog AS object_catalog",
			"t.table_schema AS object_schema",
			"t.table_name AS object_name",
			"t.table_type AS object_type",
			"column_name",
			"grantee",
			s.clauses[PrivilegesGrantor] + " AS grantor",
			"privilege_type",
			"CASE WHEN is_grantable='YES' THEN 1 ELSE 0 END AS is_grantable",
		}

		qstr := "SELECT\n" +
			"  " + strings.Join(columns, ", ") + "\n" +
			"FROM information_schema.column_privileges cp\n" +
			"LEFT JOIN information_schema.tables t\n" +
			"  ON t.table_catalog = cp.table_catalog AND t.table_schema = cp.table_schema AND t.table_name = cp.table_name"
		qstrs = append(qstrs, qstr)
	}

	if s.hasUsagePrivileges {
		columns := []string{
			"object_catalog",
			"object_schema",
			"object_name",
			"object_type",
			"'' AS column_name",
			"grantee",
			s.clauses[PrivilegesGrantor] + " AS grantor",
			"privilege_type",
			"CASE WHEN is_grantable='YES' THEN 1 ELSE 0 END AS is_grantable",
		}

		qstr := "SELECT\n" +
			"  " + strings.Join(columns, ", ") + "\n" +
			"FROM information_schema.usage_privileges"
		qstrs = append(qstrs, qstr)
	}

	// In the query result, table and column level privileges will be on separate rows.
	// Each table or column can have multple privileges (i.e rows).
	// For table level privileges the `column_name` column is empty.
	qstr := "SELECT * FROM (\n" + strings.Join(qstrs, "\nUNION ALL\n") + "\n) AS subquery"
	rows, closeRows, err := s.query(
		qstr,
		conds,
		"object_catalog, object_schema, object_type, object_name, column_name, grantee, grantor, privilege_type",
		vals...)
	if err != nil {
		if err == sql.ErrNoRows {
			return NewPrivilegeSummarySet([]PrivilegeSummary{}), nil
		}
		return nil, err
	}
	defer closeRows()

	type row struct {
		Catalog       string
		Schema        string
		Name          string
		ObjectType    string
		Column        string
		Grantee       string
		Grantor       string
		PrivilegeType string
		IsGrantable   bool
	}
	// The rows need to be aggregated into one `PrivilegeSummary` object per table. The rows are ordered by table such that we can append
	// to the current `PrivilegeSummary` as long as we are processing the same table.
	results := []PrivilegeSummary{}
	curSummary := &PrivilegeSummary{}
	for rows.Next() {
		r := row{}
		err = rows.Scan(&r.Catalog, &r.Schema, &r.Name, &r.ObjectType, &r.Column, &r.Grantee, &r.Grantor, &r.PrivilegeType, &r.IsGrantable)
		if err != nil {
			return nil, err
		}

		if curSummary.Catalog != r.Catalog || curSummary.Schema != r.Schema || curSummary.Name != r.Name {
			summary := PrivilegeSummary{
				Catalog:          r.Catalog,
				Schema:           r.Schema,
				Name:             r.Name,
				ObjectType:       r.ObjectType,
				ObjectPrivileges: ObjectPrivileges{},
				ColumnPrivileges: ColumnPrivileges{},
			}
			results = append(results, summary)
			curSummary = &results[len(results)-1]
		}

		switch {
		// If the row specifies neither column nor table level privileges
		case r.PrivilegeType == "":
		// If row specifies table level privilege
		case r.Column == "":
			objPrivilege := ObjectPrivilege{Grantee: r.Grantee, Grantor: r.Grantor, PrivilegeType: r.PrivilegeType, IsGrantable: r.IsGrantable}
			curSummary.ObjectPrivileges = append(curSummary.ObjectPrivileges, objPrivilege)
		// If row specifies column level privilege
		default:
			colPrivilege := ColumnPrivilege{Column: r.Column, Grantee: r.Grantee, Grantor: r.Grantor, PrivilegeType: r.PrivilegeType, IsGrantable: r.IsGrantable}
			curSummary.ColumnPrivileges = append(curSummary.ColumnPrivileges, colPrivilege)
		}
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return NewPrivilegeSummarySet(results), nil
}

func (s InformationSchema) conditions(baseParam int, filter Filter, formats formats) ([]string, []interface{}) {
	conds := []string{}
	vals := []interface{}{}
	if filter.Catalog != "" && formats.catalog != "" {
		vals = append(vals, filter.Catalog)
		conds = append(conds, fmt.Sprintf(formats.catalog, s.pf(baseParam)))
		baseParam++
	}
	if filter.Schema != "" && formats.schema != "" {
		vals = append(vals, filter.Schema)
		conds = append(conds, fmt.Sprintf(formats.schema, s.pf(baseParam)))
		baseParam++
	}

	if !filter.WithSystem && formats.notSchemas != "" && len(s.systemSchemas) != 0 {
		pholders := []string{}
		for _, v := range s.systemSchemas {
			if v == filter.Schema {
				continue
			}
			vals = append(vals, v)
			pholders = append(pholders, s.pf(baseParam))
			baseParam++
		}
		if len(pholders) != 0 {
			conds = append(conds, fmt.Sprintf(formats.notSchemas, strings.Join(pholders, ", ")))
		}
	}
	if filter.OnlyVisible && formats.schema != "" && s.currentSchema != "" {
		conds = append(conds, fmt.Sprintf(formats.schema, s.currentSchema))
	}
	if filter.Parent != "" && formats.parent != "" {
		vals = append(vals, filter.Parent)
		conds = append(conds, fmt.Sprintf(formats.parent, s.pf(baseParam)))
		baseParam++
	}
	if filter.Reference != "" && formats.reference != "" {
		vals = append(vals, filter.Reference)
		conds = append(conds, fmt.Sprintf(formats.reference, s.pf(baseParam)))
		baseParam++
	}
	if filter.Name != "" && formats.name != "" {
		vals = append(vals, filter.Name)
		conds = append(conds, fmt.Sprintf(formats.name, s.pf(baseParam)))
		baseParam++
	}
	if len(filter.Types) != 0 && formats.types != "" {
		pholders := []string{}
		for _, t := range filter.Types {
			vals = append(vals, t)
			pholders = append(pholders, s.pf(baseParam))
			baseParam++
		}
		if len(pholders) != 0 {
			conds = append(conds, fmt.Sprintf(formats.types, strings.Join(pholders, ", ")))
		}
	}

	return conds, vals
}

type formats struct {
	catalog    string
	schema     string
	notSchemas string
	parent     string
	reference  string
	name       string
	types      string
}

func (s InformationSchema) query(qstr string, conds []string, order string, vals ...interface{}) (*sql.Rows, CloseFunc, error) {
	if len(conds) != 0 {
		qstr += "\nWHERE " + strings.Join(conds, " AND ")
	}
	if order != "" {
		qstr += "\nORDER BY " + order
	}
	if s.limit != 0 {
		qstr += fmt.Sprintf("\nLIMIT %d", s.limit)
	}
	return s.q.Query(qstr, vals...)
}
