// Package informationschema_test runs integration tests for informationschema package
// on real databases running in containers. During development, to avoid rebuilding
// containers every run, add the `-cleanup=false` flags when calling `go test`.
package schema

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/go-cmp/cmp"
	_ "github.com/lib/pq"
	_ "github.com/microsoft/go-mssqldb" // DRIVER: sqlserver
	"github.com/murfffi/gorich/fi"
	dt "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "github.com/trinodb/trino-go-client/trino"
)

type Database struct {
	BuildArgs    []dc.BuildArg
	RunOptions   *dt.RunOptions
	Exec         []string
	Driver       string
	URL          string
	ReadinessURL string
	DockerPort   string
	Resource     *dt.Resource
	DB           *sql.DB
	Opts         []ReaderOption
	Reader       *InformationSchema
}

const (
	pw = "yourStrong123_Password"
)

var (
	dbs = map[string]*Database{
		"pgsql": {
			BuildArgs: []dc.BuildArg{
				{Name: "BASE_IMAGE", Value: "postgres:13"},
				{Name: "SCHEMA_URL", Value: "https://raw.githubusercontent.com/jOOQ/sakila/main/postgres-sakila-db/postgres-sakila-schema.sql"},
				{Name: "TARGET", Value: "/docker-entrypoint-initdb.d"},
				{Name: "USER", Value: "root"},
			},
			RunOptions: &dt.RunOptions{
				Name: "usql-pgsql",
				Cmd:  []string{"-c", "log_statement=all", "-c", "log_min_duration_statement=0"},
				Env:  []string{"POSTGRES_PASSWORD=pw"},
			},
			Driver:     "postgres",
			URL:        "postgres://postgres:pw@localhost:%s/postgres?sslmode=disable",
			DockerPort: "5432/tcp",
			Opts: []ReaderOption{
				WithIndexes(false),
				WithCustomClauses(map[ClauseName]string{
					ColumnsColumnSize:         "COALESCE(character_maximum_length, numeric_precision, datetime_precision, interval_precision, 0)",
					FunctionColumnsColumnSize: "COALESCE(character_maximum_length, numeric_precision, datetime_precision, interval_precision, 0)",
				}),
				WithSystemSchemas([]string{"pg_catalog", "pg_toast", "information_schema"}),
			},
		},
		"mysql": {
			BuildArgs: []dc.BuildArg{
				{Name: "BASE_IMAGE", Value: "mysql:8"},
				{Name: "SCHEMA_URL", Value: "https://raw.githubusercontent.com/jOOQ/sakila/main/mysql-sakila-db/mysql-sakila-schema.sql"},
				{Name: "TARGET", Value: "/docker-entrypoint-initdb.d"},
				{Name: "USER", Value: "root"},
			},
			RunOptions: &dt.RunOptions{
				Name: "usql-mysql",
				Cmd:  []string{"--general-log=1", "--general-log-file=/var/lib/mysql/mysql.log"},
				Env:  []string{"MYSQL_ROOT_PASSWORD=pw"},
			},
			Driver:     "mysql",
			URL:        "root:pw@(localhost:%s)/mysql?parseTime=true",
			DockerPort: "3306/tcp",
			Opts: []ReaderOption{
				WithPlaceholder(func(int) string { return "?" }),
				WithCheckConstraints(false),
				WithCustomClauses(map[ClauseName]string{
					ColumnsDataType:                 "column_type",
					ColumnsNumericPrecRadix:         "10",
					FunctionColumnsNumericPrecRadix: "10",
					ConstraintIsDeferrable:          "''",
					ConstraintInitiallyDeferred:     "''",
					PrivilegesGrantor:               "''",
					ConstraintJoinCond:              "AND r.referenced_table_name = f.table_name",
				}),
				WithSystemSchemas([]string{"mysql", "information_schema", "performance_schema", "sys"}),
				WithCurrentSchema("COALESCE(DATABASE(), '%')"),
				WithUsagePrivileges(false),
				WithSequences(false),
			},
		},
		"sqlserver": {
			BuildArgs: []dc.BuildArg{
				{Name: "BASE_IMAGE", Value: "mcr.microsoft.com/mssql/server:2019-latest"},
				{Name: "SCHEMA_URL", Value: "https://raw.githubusercontent.com/jOOQ/sakila/main/sql-server-sakila-db/sql-server-sakila-schema.sql"},
				{Name: "TARGET", Value: "/schema"},
				{Name: "USER", Value: "mssql:0"},
			},
			RunOptions: &dt.RunOptions{
				Name: "usql-sqlserver",
				Env:  []string{"ACCEPT_EULA=Y", "SA_PASSWORD=" + pw},
			},
			Exec:         []string{"/opt/mssql-tools/bin/sqlcmd", "-S", "localhost", "-U", "sa", "-P", pw, "-d", "master", "-i", "/schema/sql-server-sakila-schema.sql"},
			Driver:       "sqlserver",
			URL:          "sqlserver://sa:" + url.QueryEscape(pw) + "@127.0.0.1:%s?database=sakila",
			ReadinessURL: "sqlserver://sa:" + url.QueryEscape(pw) + "@127.0.0.1:%s",
			DockerPort:   "1433/tcp",
			Opts: []ReaderOption{
				WithPlaceholder(func(n int) string { return fmt.Sprintf("@p%d", n) }),
				WithIndexes(false),
				WithConstraints(false),
				WithCustomClauses(map[ClauseName]string{
					FunctionsSecurityType: "''",
				}),
				WithSystemSchemas([]string{
					"db_accessadmin",
					"db_backupoperator",
					"db_datareader",
					"db_datawriter",
					"db_ddladmin",
					"db_denydatareader",
					"db_denydatawriter",
					"db_owner",
					"db_securityadmin",
					"INFORMATION_SCHEMA",
					"sys",
				}),
				WithUsagePrivileges(false),
				WithSequences(false),
			},
		},
		"trino": {
			BuildArgs: []dc.BuildArg{
				{Name: "BASE_IMAGE", Value: "trinodb/trino:351"},
			},
			RunOptions: &dt.RunOptions{
				Name: "usql-trino",
			},
			Driver:     "trino",
			URL:        "http://test@localhost:%s?catalog=tpch&schema=sf1",
			DockerPort: "8080/tcp",
			Opts: []ReaderOption{
				WithPlaceholder(func(int) string { return "?" }),
				WithIndexes(false),
				WithConstraints(false),
				WithCustomClauses(map[ClauseName]string{
					ColumnsColumnSize:               "0",
					ColumnsNumericScale:             "0",
					ColumnsNumericPrecRadix:         "0",
					ColumnsCharOctetLength:          "0",
					FunctionColumnsColumnSize:       "0",
					FunctionColumnsNumericScale:     "0",
					FunctionColumnsNumericPrecRadix: "0",
					FunctionColumnsCharOctetLength:  "0",
				}),
			},
		},
	}
	cleanup = flag.Bool("cleanup", true, "delete containers when finished")
	only    = flag.String("dbs", "", "comma separated list of dbs to test: pgsql, mysql, sqlserver, trino")
)

func TestIS(t *testing.T) {
	fi.SkipLongTest(t)
	if *only != "" {
		runOnly := map[string]struct{}{}
		for _, dbName := range strings.Split(*only, ",") {
			dbName = strings.TrimSpace(dbName)
			runOnly[dbName] = struct{}{}
		}
		for dbName := range dbs {
			if _, ok := runOnly[dbName]; !ok {
				delete(dbs, dbName)
			}
		}
	}

	pool, err := dt.NewPool("")
	require.NoError(t, err)

	for dbName, db := range dbs {
		var ok bool
		db.Resource, ok = pool.ContainerByName(db.RunOptions.Name)
		if !ok {
			buildOpts := &dt.BuildOptions{
				ContextDir: "testdata/docker",
				BuildArgs:  db.BuildArgs,
			}
			db.Resource, err = pool.BuildAndRunWithBuildOptions(buildOpts, db.RunOptions)
			require.NoError(t, err)
		}
		state := db.Resource.Container.State.Status
		require.Contains(t, []string{"created", "running"}, state)
		dbUrl := db.URL
		if db.ReadinessURL != "" {
			dbUrl = db.ReadinessURL
		}
		port := db.Resource.GetPort(db.DockerPort)
		db.DB, err = waitForDbConnection(db.Driver, pool, dbUrl, port)
		require.NoError(t, err, "Timed out waiting for %s: %s", dbName, err)

		if len(db.Exec) != 0 {
			exitCode, err := db.Resource.Exec(db.Exec, dt.ExecOptions{
				StdIn:  os.Stdin,
				StdOut: os.Stdout,
				StdErr: os.Stderr,
				TTY:    true,
			})
			require.NoError(t, err)
			require.Equal(t, 0, exitCode)
		}

		// Reconnect with actual URL if a separate URL for readiness checking was used
		if db.ReadinessURL != "" {
			require.NoError(t, db.DB.Close())
			db.DB, err = waitForDbConnection(db.Driver, pool, db.URL, port)
			require.NoError(t, err, "Timed out waiting for %s: %s", dbName, err)
		}
		db.Reader = NewFromDB(db.DB, db.Opts...)
	}

	t.Run("Schemas", testSchemas)
	t.Run("Tables", testTables)
	t.Run("Columns", testColumns)
	t.Run("Functions", testFunctions)
	t.Run("FunctionColumns", testFunctionColumns)
	t.Run("Indexes", testIndexes)
	t.Run("IndexColumns", testIndexColumns)
	t.Run("Constraints", testConstraints)
	t.Run("ConstraintColumns", testConstraintColumns)
	t.Run("ReverseConstraints", testReverseConstraints)
	t.Run("Sequences", testSequences)
	t.Run("PrivilegeSummaries_NonExistent", testPrivilegeSummariesNonExistent)
	t.Run("PrivilegeSummaries", testPrivilegeSummaries)

	// You can't defer this because os.Exit doesn't care for defer
	if *cleanup {
		for _, db := range dbs {
			if err := pool.Purge(db.Resource); err != nil {
				log.Fatal("Could not purge resource: ", err)
			}
		}
	}

}

func waitForDbConnection(driver string, pool *dt.Pool, url string, port string) (*sql.DB, error) {
	// exponential backoff-retry, because the application in the container might not be ready to accept connections yet
	var db *sql.DB
	if err := pool.Retry(func() error {
		var err error
		db, err = sql.Open(driver, fmt.Sprintf(url, port))
		if err != nil {
			return err
		}
		return db.Ping()
	}); err != nil {
		return nil, err
	}
	return db, nil
}

func testSchemas(t *testing.T) {
	expected := map[string]string{
		"pgsql":     "information_schema, pg_catalog, pg_toast, public",
		"mysql":     "information_schema, mysql, performance_schema, sakila, sys",
		"sqlserver": "db_accessadmin, db_backupoperator, db_datareader, db_datawriter, db_ddladmin, db_denydatareader, db_denydatawriter, db_owner, db_securityadmin, dbo, guest, INFORMATION_SCHEMA, sys",
		"trino":     "information_schema, sf1, sf100, sf1000, sf10000, sf100000, sf300, sf3000, sf30000, tiny",
	}
	for dbName, db := range dbs {
		r := db.Reader

		result, err := r.Schemas(Filter{WithSystem: true})
		if err != nil {
			log.Fatalf("Could not read %s schemas: %v", dbName, err)
		}

		names := []string{}
		for result.Next() {
			names = append(names, result.Get().Schema)
		}
		actual := strings.Join(names, ", ")
		if actual != expected[dbName] {
			t.Errorf("Wrong %s schema names, expected:\n  %v\ngot:\n  %v", dbName, expected[dbName], names)
		}
	}
}

func testTables(t *testing.T) {
	schemas := map[string]string{
		"pgsql":     "public",
		"mysql":     "sakila",
		"sqlserver": "dbo",
		"trino":     "sf1",
	}
	expected := map[string]string{
		"pgsql":     "actor, address, category, city, country, customer, film, film_actor, film_category, inventory, language, payment, payment_p2007_01, payment_p2007_02, payment_p2007_03, payment_p2007_04, payment_p2007_05, payment_p2007_06, rental, staff, store, actor_info, customer_list, film_list, nicer_but_slower_film_list, sales_by_film_category, sales_by_store, staff_list",
		"mysql":     "actor, address, category, city, country, customer, film, film_actor, film_category, film_text, inventory, language, payment, rental, staff, store, actor_info, customer_list, film_list, nicer_but_slower_film_list, sales_by_film_category, sales_by_store, staff_list",
		"sqlserver": "actor, address, category, city, country, customer, film, film_actor, film_category, film_text, inventory, language, payment, rental, staff, store, customer_list, film_list, sales_by_film_category, sales_by_store, staff_list",
		"trino":     "customer, lineitem, nation, orders, part, partsupp, region, supplier",
	}
	for dbName, db := range dbs {
		r := db.Reader

		result, err := r.Tables(Filter{Schema: schemas[dbName], Types: []string{"BASE TABLE", "TABLE", "VIEW"}})
		if err != nil {
			log.Fatalf("Could not read %s tables: %v", dbName, err)
		}

		names := []string{}
		for result.Next() {
			names = append(names, result.Get().Name)
		}
		actual := strings.Join(names, ", ")
		if actual != expected[dbName] {
			t.Errorf("Wrong %s table names, expected:\n  %v\ngot:\n  %v", dbName, expected[dbName], names)
		}
	}
}

func testColumns(t *testing.T) {
	schemas := map[string]string{
		"pgsql":     "public",
		"mysql":     "sakila",
		"sqlserver": "dbo",
		"trino":     "sf1",
	}
	tables := map[string]string{
		"pgsql":     "film%",
		"mysql":     "film%",
		"sqlserver": "film%",
		"trino":     "orders",
	}
	expectedColumns := map[string]string{
		"pgsql":     "film_id, title, description, release_year, language_id, original_language_id, rental_duration, rental_rate, length, replacement_cost, rating, last_update, special_features, fulltext, actor_id, film_id, last_update, film_id, category_id, last_update, fid, title, description, category, price, length, rating, actors",
		"mysql":     "film_id, title, description, release_year, language_id, original_language_id, rental_duration, rental_rate, length, replacement_cost, rating, special_features, last_update, actor_id, film_id, last_update, film_id, category_id, last_update, FID, title, description, category, price, length, rating, actors, film_id, title, description",
		"sqlserver": "film_id, title, description, release_year, language_id, original_language_id, rental_duration, rental_rate, length, replacement_cost, rating, special_features, last_update, actor_id, film_id, last_update, film_id, category_id, last_update, FID, title, description, category, price, length, rating, actors, film_id, title, description",
		"trino":     "orderkey, custkey, orderstatus, totalprice, orderdate, orderpriority, clerk, shippriority, comment",
	}
	expectedTypes := map[string]string{
		"mysql": "int unsigned, varchar(255), text, year, int unsigned, int unsigned, tinyint unsigned, decimal(4,2), smallint unsigned, decimal(5,2), enum('G','PG','PG-13','R','NC-17'), set('Trailers','Commentaries','Deleted Scenes','Behind the Scenes'), timestamp, int unsigned, int unsigned, timestamp, int unsigned, int unsigned, timestamp, int unsigned, varchar(255), text, varchar(25), decimal(4,2), smallint unsigned, enum('G','PG','PG-13','R','NC-17'), text, int, varchar(255), text",
	}
	for dbName, db := range dbs {
		r := db.Reader

		result, err := r.Columns(Filter{Schema: schemas[dbName], Parent: tables[dbName]})
		if err != nil {
			log.Fatalf("Could not read %s columns: %v", dbName, err)
		}

		names := []string{}
		types := []string{}
		for result.Next() {
			names = append(names, result.Get().Name)
			types = append(types, result.Get().DataType)
		}
		actualColumns := strings.Join(names, ", ")
		actualTypes := strings.Join(types, ", ")
		if expected, ok := expectedColumns[dbName]; ok && actualColumns != expected {
			t.Errorf("Wrong %s column names, expected:\n  %v, got:\n  %v", dbName, expected, names)
		}
		if expected, ok := expectedTypes[dbName]; ok && actualTypes != expected {
			t.Errorf("Wrong %s column types, expected:\n  %v, got:\n  %v", dbName, expected, types)
		}
	}
}

func testFunctions(t *testing.T) {
	schemas := map[string]string{
		"pgsql": "public",
		"mysql": "sakila",
	}
	expected := map[string]string{
		"pgsql": "_group_concat, film_in_stock, film_not_in_stock, get_customer_balance, group_concat, inventory_held_by_customer, inventory_in_stock, last_day, last_updated, rewards_report",
		"mysql": "film_in_stock, film_not_in_stock, get_customer_balance, inventory_held_by_customer, inventory_in_stock, rewards_report",
	}
	for dbName, db := range dbs {
		if schemas[dbName] == "" {
			continue
		}
		r := NewFromDB(db.DB, db.Opts...)

		result, err := r.Functions(Filter{Schema: schemas[dbName]})
		if err != nil {
			log.Fatalf("Could not read %s functions: %v", dbName, err)
		}

		names := []string{}
		for result.Next() {
			names = append(names, result.Get().Name)
		}
		actual := strings.Join(names, ", ")
		if actual != expected[dbName] {
			t.Errorf("Wrong %s function names, expected:\n  %v\ngot:\n  %v", dbName, expected[dbName], names)
		}
	}
}

func testFunctionColumns(t *testing.T) {
	schemas := map[string]string{
		"pgsql": "public",
		"mysql": "sakila",
	}
	tables := map[string]string{
		"pgsql": "film%",
		"mysql": "film%",
	}
	expected := map[string]string{
		"pgsql": "p_film_id, p_store_id, p_film_count, p_film_id, p_store_id, p_film_count",
		"mysql": "p_film_id, p_store_id, p_film_count, p_film_id, p_store_id, p_film_count",
	}
	for dbName, db := range dbs {
		if schemas[dbName] == "" {
			continue
		}
		r := NewFromDB(db.DB, db.Opts...)

		result, err := r.FunctionColumns(Filter{Schema: schemas[dbName], Parent: tables[dbName]})
		if err != nil {
			log.Fatalf("Could not read %s function columns: %v", dbName, err)
		}

		var names []string
		for result.Next() {
			names = append(names, result.Get().Name)
		}
		actual := strings.Join(names, ", ")
		if actual != expected[dbName] {
			t.Errorf("Wrong %s function column names, expected:\n  %v, got:\n  %v", dbName, expected[dbName], names)
		}
	}
}

func testIndexes(t *testing.T) {
	schemas := map[string]string{
		"mysql": "sakila",
	}
	expected := map[string]string{
		"mysql": "actor.idx_actor_last_name, actor.PRIMARY, address.idx_fk_city_id, address.PRIMARY, category.PRIMARY, city.idx_fk_country_id, city.PRIMARY, country.PRIMARY, customer.idx_fk_address_id, customer.idx_fk_store_id, customer.idx_last_name, customer.PRIMARY, film.idx_fk_language_id, film.idx_fk_original_language_id, film.idx_title, film.PRIMARY, film_actor.idx_fk_film_id, film_actor.PRIMARY, film_category.fk_film_category_category, film_category.PRIMARY, film_text.idx_title_description, film_text.PRIMARY, inventory.idx_fk_film_id, inventory.idx_store_id_film_id, inventory.PRIMARY, language.PRIMARY, payment.fk_payment_rental, payment.idx_fk_customer_id, payment.idx_fk_staff_id, payment.PRIMARY, rental.idx_fk_customer_id, rental.idx_fk_inventory_id, rental.idx_fk_staff_id, rental.PRIMARY, rental.rental_date, staff.idx_fk_address_id, staff.idx_fk_store_id, staff.PRIMARY, store.idx_fk_address_id, store.idx_unique_manager, store.PRIMARY",
	}
	for dbName, db := range dbs {
		if schemas[dbName] == "" {
			continue
		}
		r := NewFromDB(db.DB, db.Opts...)

		result, err := r.Indexes(Filter{Schema: schemas[dbName]})
		if err != nil {
			log.Fatalf("Could not read %s indexes: %v", dbName, err)
		}

		names := []string{}
		for result.Next() {
			names = append(names, result.Get().Table+"."+result.Get().Name)
		}
		actual := strings.Join(names, ", ")
		if actual != expected[dbName] {
			t.Errorf("Wrong %s index names, expected:\n  %v\ngot:\n  %v", dbName, expected[dbName], names)
		}
	}
}

func testIndexColumns(t *testing.T) {
	schemas := map[string]string{
		"mysql": "sakila",
	}
	tables := map[string]string{
		"mysql": "idx%",
	}
	expected := map[string]string{
		"mysql": "last_name, city_id, country_id, address_id, store_id, last_name, language_id, original_language_id, title, film_id, title, description, film_id, store_id, film_id, customer_id, staff_id, customer_id, inventory_id, staff_id, address_id, store_id, address_id, manager_staff_id",
	}
	for dbName, db := range dbs {
		if schemas[dbName] == "" {
			continue
		}
		r := NewFromDB(db.DB, db.Opts...)

		result, err := r.IndexColumns(Filter{Schema: schemas[dbName], Name: tables[dbName]})
		if err != nil {
			log.Fatalf("Could not read %s index columns: %v", dbName, err)
		}

		names := []string{}
		for result.Next() {
			names = append(names, result.Get().Name)
		}
		actual := strings.Join(names, ", ")
		if actual != expected[dbName] {
			t.Errorf("Wrong %s index column names, expected:\n  %v, got:\n  %v", dbName, expected[dbName], names)
		}
	}
}

func testConstraints(t *testing.T) {
	schemas := map[string]string{
		"pgsql": "public",
		"mysql": "sakila",
	}
	constraints := map[string]string{
		"pgsql": "film%",
		"mysql": "film%",
	}
	expected := map[string]string{
		"pgsql": "film.2200_16417_10_not_null, film.2200_16417_12_not_null, film.2200_16417_14_not_null, film.2200_16417_1_not_null, film.2200_16417_2_not_null, film.2200_16417_5_not_null, film.2200_16417_7_not_null, film.2200_16417_8_not_null, film.film_language_id_fkey, film.film_original_language_id_fkey, film.film_pkey, film_actor.2200_16429_1_not_null, film_actor.2200_16429_2_not_null, film_actor.2200_16429_3_not_null, film_actor.film_actor_actor_id_fkey, film_actor.film_actor_film_id_fkey, film_actor.film_actor_pkey, film_category.2200_16433_1_not_null, film_category.2200_16433_2_not_null, film_category.2200_16433_3_not_null, film_category.film_category_category_id_fkey, film_category.film_category_film_id_fkey, film_category.film_category_pkey",
		"mysql": "film.fk_film_language, film.fk_film_language_original, film.PRIMARY, film_actor.fk_film_actor_actor, film_actor.fk_film_actor_film, film_actor.PRIMARY, film_category.fk_film_category_category, film_category.fk_film_category_film, film_category.PRIMARY, film_text.PRIMARY",
	}
	for dbName, db := range dbs {
		if schemas[dbName] == "" {
			continue
		}
		r := NewFromDB(db.DB, db.Opts...)

		result, err := r.Constraints(Filter{Schema: schemas[dbName], Parent: constraints[dbName]})
		if err != nil {
			log.Fatalf("Could not read %s constraints: %v", dbName, err)
		}

		names := []string{}
		for result.Next() {
			names = append(names, result.Get().Table+"."+result.Get().Name)
		}
		actual := strings.Join(names, ", ")
		if actual != expected[dbName] {
			t.Errorf("Wrong %s constraint names, expected:\n  %v\ngot:\n  %v", dbName, expected[dbName], names)
		}
	}
}

func testConstraintColumns(t *testing.T) {
	schemas := map[string]string{
		"pgsql": "public",
		"mysql": "sakila",
	}
	constraints := map[string]string{
		"pgsql": "film%",
		"mysql": "film%",
	}
	expected := map[string]string{
		"pgsql": "actor_id, category_id, film_id, film_id, language_id, original_language_id, film_id, film_id, actor_id, film_id, actor_id, actor_id, film_id, film_id, category_id, film_id, category_id, film_id, film_id, category_id, language_id, language_id",
		"mysql": "",
	}
	for dbName, db := range dbs {
		if schemas[dbName] == "" {
			continue
		}
		r := NewFromDB(db.DB, db.Opts...)

		result, err := r.ConstraintColumns(Filter{Schema: schemas[dbName], Name: constraints[dbName]})
		if err != nil {
			log.Fatalf("Could not read %s constraint columns: %v", dbName, err)
		}

		names := []string{}
		for result.Next() {
			names = append(names, result.Get().Name)
		}
		actual := strings.Join(names, ", ")
		if actual != expected[dbName] {
			t.Errorf("Wrong %s constraint column names, expected:\n  %v, got:\n  %v", dbName, expected[dbName], names)
		}
	}
}

func testReverseConstraints(t *testing.T) {
	schemas := map[string]string{
		"pgsql": "public",
		"mysql": "sakila",
	}
	constraints := map[string]string{
		"pgsql": "film%",
		"mysql": "film%",
	}
	expected := map[string]string{
		"pgsql": "film_actor.film_actor_film_id_fkey, film_category.film_category_film_id_fkey, inventory.inventory_film_id_fkey",
		"mysql": "film_actor.fk_film_actor_film, film_category.fk_film_category_film, inventory.fk_inventory_film",
	}
	for dbName, db := range dbs {
		if schemas[dbName] == "" {
			continue
		}
		r := NewFromDB(db.DB, db.Opts...)

		result, err := r.Constraints(Filter{Schema: schemas[dbName], Reference: constraints[dbName]})
		if err != nil {
			log.Fatalf("Could not read %s constraints: %v", dbName, err)
		}

		names := []string{}
		for result.Next() {
			names = append(names, result.Get().Table+"."+result.Get().Name)
		}
		actual := strings.Join(names, ", ")
		if actual != expected[dbName] {
			t.Errorf("Wrong %s reverse constraint names, expected:\n  %v\ngot:\n  %v", dbName, expected[dbName], names)
		}
	}
}

func testSequences(t *testing.T) {
	schemas := map[string]string{
		"pgsql": "public",
	}
	expected := map[string]string{
		"pgsql": "actor_actor_id_seq, address_address_id_seq, category_category_id_seq, city_city_id_seq, country_country_id_seq, customer_customer_id_seq, film_film_id_seq, inventory_inventory_id_seq, language_language_id_seq, payment_payment_id_seq, rental_rental_id_seq, staff_staff_id_seq, store_store_id_seq",
	}
	for dbName, db := range dbs {
		if schemas[dbName] == "" {
			continue
		}
		r := NewFromDB(db.DB, db.Opts...)

		result, err := r.Sequences(Filter{Schema: schemas[dbName]})
		if err != nil {
			log.Fatalf("Could not read %s sequences: %v", dbName, err)
		}

		names := []string{}
		for result.Next() {
			names = append(names, result.Get().Name)
		}
		actual := strings.Join(names, ", ")
		if actual != expected[dbName] {
			t.Errorf("Wrong %s sequence names, expected:\n  %v\ngot:\n  %v", dbName, expected[dbName], names)
		}
	}
}

func testPrivilegeSummariesNonExistent(t *testing.T) {
	type test struct {
		Name   string
		Db     *Database
		Schema string
	}
	tests := map[string]test{
		"pgsql":     {Db: dbs["pgsql"], Schema: "public"},
		"mysql":     {Db: dbs["mysql"], Schema: "sakila"},
		"sqlserver": {Db: dbs["sqlserver"], Schema: "dbo"},
	}

	for testName, test := range tests {
		if test.Db != nil {
			t.Run(testName, func(t *testing.T) {
				table := "privtest_table"

				// Read privileges
				r := NewFromDB(test.Db.DB, test.Db.Opts...)
				result, err := r.PrivilegeSummaries(Filter{Schema: test.Schema, Name: table})
				if err != nil {
					t.Fatalf("Could not read privileges: %v", err)
				}

				// Check result
				if result.Len() != 0 {
					t.Errorf("Wrong result count, expected:\n  %d, got:\n  %d", 0, result.Len())
				}
			})
		}
	}
}

func testPrivilegeSummaries(t *testing.T) {
	type test struct {
		Db             *Database
		Schema         string
		User           string
		Create         string
		CreateUserStmt string
		DropUserStmt   string
		Grants         []string
		WantTable      ObjectPrivileges
		WantColumn     ColumnPrivileges
	}
	setDefaults := func(t test) test {
		if t.User == "" {
			t.User = "privtest_user"
		}
		if t.Create == "" {
			t.Create = "TABLE"
		}
		if t.CreateUserStmt == "" {
			t.CreateUserStmt = "CREATE USER %s"
		}
		if t.DropUserStmt == "" {
			t.DropUserStmt = "DROP USER %s"
		}
		if t.Grants == nil {
			t.Grants = []string{}
		}
		if t.WantTable == nil {
			t.WantTable = ObjectPrivileges{}
		}
		if t.WantColumn == nil {
			t.WantColumn = ColumnPrivileges{}
		}
		return t
	}
	postgresDefaultTable := func() ObjectPrivileges {
		return ObjectPrivileges{
			ObjectPrivilege{Grantee: "postgres", Grantor: "postgres", IsGrantable: true, PrivilegeType: "INSERT"},
			ObjectPrivilege{Grantee: "postgres", Grantor: "postgres", IsGrantable: true, PrivilegeType: "SELECT"},
			ObjectPrivilege{Grantee: "postgres", Grantor: "postgres", IsGrantable: true, PrivilegeType: "UPDATE"},
			ObjectPrivilege{Grantee: "postgres", Grantor: "postgres", IsGrantable: true, PrivilegeType: "DELETE"},
			ObjectPrivilege{Grantee: "postgres", Grantor: "postgres", IsGrantable: true, PrivilegeType: "TRUNCATE"},
			ObjectPrivilege{Grantee: "postgres", Grantor: "postgres", IsGrantable: true, PrivilegeType: "REFERENCES"},
			ObjectPrivilege{Grantee: "postgres", Grantor: "postgres", IsGrantable: true, PrivilegeType: "TRIGGER"},
		}
	}
	postgresDefaultColumn := func(columns []string) ColumnPrivileges {
		p := ColumnPrivileges{}
		for _, col := range columns {
			p = append(p,
				ColumnPrivilege{Column: col, Grantee: "postgres", Grantor: "postgres", IsGrantable: true, PrivilegeType: "INSERT"},
				ColumnPrivilege{Column: col, Grantee: "postgres", Grantor: "postgres", IsGrantable: true, PrivilegeType: "SELECT"},
				ColumnPrivilege{Column: col, Grantee: "postgres", Grantor: "postgres", IsGrantable: true, PrivilegeType: "UPDATE"},
				ColumnPrivilege{Column: col, Grantee: "postgres", Grantor: "postgres", IsGrantable: true, PrivilegeType: "REFERENCES"})
		}
		return p
	}
	tests := map[string]test{
		"pgsql-no-grants": setDefaults(test{
			Db:         dbs["pgsql"],
			Schema:     "public",
			Grants:     []string{},
			WantTable:  postgresDefaultTable(),
			WantColumn: postgresDefaultColumn([]string{"col1", "col2"}),
		}),
		"pgsql-sequence": setDefaults(test{
			Db:     dbs["pgsql"],
			Schema: "public",
			Create: "SEQUENCE",
			Grants: []string{"USAGE"},
			WantTable: ObjectPrivileges{
				ObjectPrivilege{Grantee: "privtest_user", Grantor: "postgres", IsGrantable: false, PrivilegeType: "USAGE"},
				ObjectPrivilege{Grantee: "postgres", Grantor: "postgres", IsGrantable: true, PrivilegeType: "USAGE"},
			},
		}),
		"pgsql-view": setDefaults(test{
			Db:     dbs["pgsql"],
			Schema: "public",
			Create: "VIEW",
			Grants: []string{"SELECT", "INSERT*"},
			WantTable: append(postgresDefaultTable(),
				ObjectPrivilege{Grantee: "privtest_user", Grantor: "postgres", IsGrantable: false, PrivilegeType: "SELECT"},
				ObjectPrivilege{Grantee: "privtest_user", Grantor: "postgres", IsGrantable: true, PrivilegeType: "INSERT"},
			),
			WantColumn: append(
				postgresDefaultColumn([]string{"col1", "col2"}),
				ColumnPrivilege{Column: "col1", Grantee: "privtest_user", Grantor: "postgres", IsGrantable: false, PrivilegeType: "SELECT"},
				ColumnPrivilege{Column: "col1", Grantee: "privtest_user", Grantor: "postgres", IsGrantable: true, PrivilegeType: "INSERT"},
				ColumnPrivilege{Column: "col2", Grantee: "privtest_user", Grantor: "postgres", IsGrantable: false, PrivilegeType: "SELECT"},
				ColumnPrivilege{Column: "col2", Grantee: "privtest_user", Grantor: "postgres", IsGrantable: true, PrivilegeType: "INSERT"},
			),
		}),
		"pgsql-table": setDefaults(test{
			Db:     dbs["pgsql"],
			Schema: "public",
			Grants: []string{"SELECT", "INSERT*"},
			WantTable: append(postgresDefaultTable(),
				ObjectPrivilege{Grantee: "privtest_user", Grantor: "postgres", IsGrantable: false, PrivilegeType: "SELECT"},
				ObjectPrivilege{Grantee: "privtest_user", Grantor: "postgres", IsGrantable: true, PrivilegeType: "INSERT"},
			),
			WantColumn: append(
				postgresDefaultColumn([]string{"col1", "col2"}),
				ColumnPrivilege{Column: "col1", Grantee: "privtest_user", Grantor: "postgres", IsGrantable: false, PrivilegeType: "SELECT"},
				ColumnPrivilege{Column: "col1", Grantee: "privtest_user", Grantor: "postgres", IsGrantable: true, PrivilegeType: "INSERT"},
				ColumnPrivilege{Column: "col2", Grantee: "privtest_user", Grantor: "postgres", IsGrantable: false, PrivilegeType: "SELECT"},
				ColumnPrivilege{Column: "col2", Grantee: "privtest_user", Grantor: "postgres", IsGrantable: true, PrivilegeType: "INSERT"},
			),
		}),
		"pgsql-column": setDefaults(test{
			Db:        dbs["pgsql"],
			Schema:    "public",
			Grants:    []string{"SELECT(col1)", "INSERT(col2)*"},
			WantTable: postgresDefaultTable(),
			WantColumn: append(
				postgresDefaultColumn([]string{"col1", "col2"}),
				ColumnPrivilege{Column: "col1", Grantee: "privtest_user", Grantor: "postgres", IsGrantable: false, PrivilegeType: "SELECT"},
				ColumnPrivilege{Column: "col2", Grantee: "privtest_user", Grantor: "postgres", IsGrantable: true, PrivilegeType: "INSERT"},
			),
		}),
		"pgsql-table-column": setDefaults(test{
			Db:     dbs["pgsql"],
			Schema: "public",
			Grants: []string{"SELECT", "INSERT(col1)"},
			WantTable: append(postgresDefaultTable(),
				ObjectPrivilege{Grantee: "privtest_user", Grantor: "postgres", IsGrantable: false, PrivilegeType: "SELECT"},
			),
			WantColumn: append(
				postgresDefaultColumn([]string{"col1", "col2"}),
				ColumnPrivilege{Column: "col1", Grantee: "privtest_user", Grantor: "postgres", IsGrantable: false, PrivilegeType: "SELECT"},
				ColumnPrivilege{Column: "col1", Grantee: "privtest_user", Grantor: "postgres", IsGrantable: false, PrivilegeType: "INSERT"},
				ColumnPrivilege{Column: "col2", Grantee: "privtest_user", Grantor: "postgres", IsGrantable: false, PrivilegeType: "SELECT"},
			),
		}),
		"mysql-no-grants": setDefaults(test{
			Db:        dbs["mysql"],
			Schema:    "sakila",
			User:      "'privtest_user'@'%'",
			Grants:    []string{},
			WantTable: ObjectPrivileges{},
		}),
		"mysql-view": setDefaults(test{
			Db:     dbs["mysql"],
			Schema: "sakila",
			Create: "VIEW",
			User:   "'privtest_user'@'%'",
			Grants: []string{"SELECT", "INSERT"},
			WantTable: ObjectPrivileges{
				ObjectPrivilege{Grantee: "'privtest_user'@'%'", Grantor: "", IsGrantable: false, PrivilegeType: "SELECT"},
				ObjectPrivilege{Grantee: "'privtest_user'@'%'", Grantor: "", IsGrantable: false, PrivilegeType: "INSERT"},
			},
		}),
		"mysql-view-grantable": setDefaults(test{
			Db:     dbs["mysql"],
			Schema: "sakila",
			Create: "VIEW",
			User:   "'privtest_user'@'%'",
			Grants: []string{"SELECT*", "INSERT*"},
			WantTable: ObjectPrivileges{
				ObjectPrivilege{Grantee: "'privtest_user'@'%'", Grantor: "", IsGrantable: true, PrivilegeType: "SELECT"},
				ObjectPrivilege{Grantee: "'privtest_user'@'%'", Grantor: "", IsGrantable: true, PrivilegeType: "INSERT"},
			},
		}),
		"mysql-table": setDefaults(test{
			Db:     dbs["mysql"],
			Schema: "sakila",
			User:   "'privtest_user'@'%'",
			Grants: []string{"SELECT", "INSERT"},
			WantTable: ObjectPrivileges{
				ObjectPrivilege{Grantee: "'privtest_user'@'%'", Grantor: "", IsGrantable: false, PrivilegeType: "SELECT"},
				ObjectPrivilege{Grantee: "'privtest_user'@'%'", Grantor: "", IsGrantable: false, PrivilegeType: "INSERT"},
			},
		}),
		"mysql-table-grantable": setDefaults(test{
			Db:     dbs["mysql"],
			Schema: "sakila",
			User:   "'privtest_user'@'%'",
			Grants: []string{"SELECT*", "INSERT*"},
			WantTable: ObjectPrivileges{
				ObjectPrivilege{Grantee: "'privtest_user'@'%'", Grantor: "", IsGrantable: true, PrivilegeType: "SELECT"},
				ObjectPrivilege{Grantee: "'privtest_user'@'%'", Grantor: "", IsGrantable: true, PrivilegeType: "INSERT"},
			},
		}),
		"mysql-column": setDefaults(test{
			Db:     dbs["mysql"],
			Schema: "sakila",
			User:   "'privtest_user'@'%'",
			Grants: []string{"SELECT(col1)", "INSERT(col2)"},
			WantColumn: ColumnPrivileges{
				ColumnPrivilege{Column: "col1", Grantee: "'privtest_user'@'%'", Grantor: "", IsGrantable: false, PrivilegeType: "SELECT"},
				ColumnPrivilege{Column: "col2", Grantee: "'privtest_user'@'%'", Grantor: "", IsGrantable: false, PrivilegeType: "INSERT"},
			},
		}),
		"mysql-column-grantable": setDefaults(test{
			Db:     dbs["mysql"],
			Schema: "sakila",
			User:   "'privtest_user'@'%'",
			Grants: []string{"SELECT(col1)*", "INSERT(col2)*"},
			WantColumn: ColumnPrivileges{
				ColumnPrivilege{Column: "col1", Grantee: "'privtest_user'@'%'", Grantor: "", IsGrantable: true, PrivilegeType: "SELECT"},
				ColumnPrivilege{Column: "col2", Grantee: "'privtest_user'@'%'", Grantor: "", IsGrantable: true, PrivilegeType: "INSERT"},
			},
		}),
		"mysql-table-column": setDefaults(test{
			Db:     dbs["mysql"],
			Schema: "sakila",
			User:   "'privtest_user'@'%'",
			Grants: []string{"SELECT", "INSERT(col1)"},
			WantTable: ObjectPrivileges{
				ObjectPrivilege{Grantee: "'privtest_user'@'%'", Grantor: "", IsGrantable: false, PrivilegeType: "SELECT"},
			},
			WantColumn: ColumnPrivileges{
				ColumnPrivilege{Column: "col1", Grantee: "'privtest_user'@'%'", Grantor: "", IsGrantable: false, PrivilegeType: "INSERT"},
			},
		}),
		"sqlserver-no-grants": setDefaults(test{
			Db:             dbs["sqlserver"],
			Schema:         "dbo",
			CreateUserStmt: "CREATE LOGIN %[1]s WITH PASSWORD = 'yourStrong123_Password'; CREATE USER %[1]s FOR LOGIN %[1]s",
			DropUserStmt:   "DROP USER %[1]s; DROP LOGIN %[1]s",
			Grants:         []string{},
			WantTable:      ObjectPrivileges{},
		}),
		"sqlserver-view": setDefaults(test{
			Db:             dbs["sqlserver"],
			Schema:         "dbo",
			Create:         "VIEW",
			CreateUserStmt: "CREATE LOGIN %[1]s WITH PASSWORD = 'yourStrong123_Password'; CREATE USER %[1]s FOR LOGIN %[1]s",
			DropUserStmt:   "DROP USER %[1]s; DROP LOGIN %[1]s",
			Grants:         []string{"SELECT", "INSERT*"},
			WantTable: ObjectPrivileges{
				ObjectPrivilege{Grantee: "privtest_user", Grantor: "dbo", IsGrantable: false, PrivilegeType: "SELECT"},
				ObjectPrivilege{Grantee: "privtest_user", Grantor: "dbo", IsGrantable: true, PrivilegeType: "INSERT"},
			},
		}),
		"sqlserver-table": setDefaults(test{
			Db:             dbs["sqlserver"],
			Schema:         "dbo",
			CreateUserStmt: "CREATE LOGIN %[1]s WITH PASSWORD = 'yourStrong123_Password'; CREATE USER %[1]s FOR LOGIN %[1]s",
			DropUserStmt:   "DROP USER %[1]s; DROP LOGIN %[1]s",
			Grants:         []string{"SELECT", "INSERT*"},
			WantTable: ObjectPrivileges{
				ObjectPrivilege{Grantee: "privtest_user", Grantor: "dbo", IsGrantable: false, PrivilegeType: "SELECT"},
				ObjectPrivilege{Grantee: "privtest_user", Grantor: "dbo", IsGrantable: true, PrivilegeType: "INSERT"},
			},
		}),
		"sqlserver-column": setDefaults(test{
			Db:             dbs["sqlserver"],
			Schema:         "dbo",
			CreateUserStmt: "CREATE LOGIN %[1]s WITH PASSWORD = 'yourStrong123_Password'; CREATE USER %[1]s FOR LOGIN %[1]s",
			DropUserStmt:   "DROP USER %[1]s; DROP LOGIN %[1]s",
			Grants:         []string{"SELECT(col1)", "UPDATE(col2)*"},
			WantColumn: ColumnPrivileges{
				ColumnPrivilege{Column: "col1", Grantee: "privtest_user", Grantor: "dbo", IsGrantable: false, PrivilegeType: "SELECT"},
				ColumnPrivilege{Column: "col2", Grantee: "privtest_user", Grantor: "dbo", IsGrantable: true, PrivilegeType: "UPDATE"},
			},
		}),
		"sqlserver-table-column": setDefaults(test{
			Db:             dbs["sqlserver"],
			Schema:         "dbo",
			CreateUserStmt: "CREATE LOGIN %[1]s WITH PASSWORD = 'yourStrong123_Password'; CREATE USER %[1]s FOR LOGIN %[1]s",
			DropUserStmt:   "DROP USER %[1]s; DROP LOGIN %[1]s",
			Grants:         []string{"SELECT", "UPDATE(col1)"},
			WantTable: ObjectPrivileges{
				ObjectPrivilege{Grantee: "privtest_user", Grantor: "dbo", IsGrantable: false, PrivilegeType: "SELECT"},
			},
			WantColumn: ColumnPrivileges{
				ColumnPrivilege{Column: "col1", Grantee: "privtest_user", Grantor: "dbo", IsGrantable: false, PrivilegeType: "UPDATE"},
			},
		}),
	}

	for testName, testSpec := range tests {
		if testSpec.Db != nil {
			t.Run(testName, func(t *testing.T) {
				// Create user, table and grants
				const name = "privtest"
				var query string
				var err error
				query = fmt.Sprintf(testSpec.CreateUserStmt, testSpec.User)
				_, err = testSpec.Db.DB.Exec(query)
				if err != nil {
					t.Fatalf("Could not CREATE USER:\n%s\n%s", query, err)
				}
				defer func() {
					_, err = testSpec.Db.DB.Exec(fmt.Sprintf(testSpec.DropUserStmt, testSpec.User))
					assert.NoError(t, err)
				}()

				switch testSpec.Create {
				case "TABLE":
					query = fmt.Sprintf("CREATE TABLE %s.%s (col1 int, col2 varchar(255))", testSpec.Schema, name)
					_, err = testSpec.Db.DB.Exec(query)
					require.NoError(t, err, "Could not CREATE TABLE:\n%s\n%s", query, err)
					defer func() {
						_, err = testSpec.Db.DB.Exec(fmt.Sprintf("DROP TABLE %s.%s", testSpec.Schema, name))
						assert.NoError(t, err)
					}()
				case "VIEW":
					query = fmt.Sprintf("CREATE TABLE %s.%s_table (col1 int, col2 varchar(255))", testSpec.Schema, name)
					_, err = testSpec.Db.DB.Exec(query)
					require.NoError(t, err, "Could not CREATE TABLE:\n%s\n%s", query, err)
					defer func() {
						_, err = testSpec.Db.DB.Exec(fmt.Sprintf("DROP TABLE %s.%s_table", testSpec.Schema, name))
						assert.NoError(t, err)
					}()
					query = fmt.Sprintf("CREATE VIEW %s.%s AS SELECT * FROM %[1]s.%[2]s_table", testSpec.Schema, name)
					_, err = testSpec.Db.DB.Exec(query)
					require.NoError(t, err, "Could not CREATE VIEW:\n%s\n%s", query, err)
					defer func() {
						_, err = testSpec.Db.DB.Exec(fmt.Sprintf("DROP VIEW %s.%s", testSpec.Schema, name))
						assert.NoError(t, err)
					}()
				case "SEQUENCE":
					query = fmt.Sprintf("CREATE SEQUENCE %s.%s", testSpec.Schema, name)
					_, err = testSpec.Db.DB.Exec(query)
					require.NoError(t, err, "Could not CREATE SEQUENCE:\n%s\n%s", query, err)
					defer func() {
						_, err = testSpec.Db.DB.Exec(fmt.Sprintf("DROP SEQUENCE %s.%s", testSpec.Schema, name))
						assert.NoError(t, err)
					}()
				}

				for _, grant := range testSpec.Grants {
					isGrantable := false
					if grant[len(grant)-1] == '*' {
						isGrantable = true
						grant = grant[:len(grant)-1]
					}
					query = fmt.Sprintf("GRANT %s ON %s.%s TO %s", grant, testSpec.Schema, name, testSpec.User)
					if isGrantable {
						query += " WITH GRANT OPTION"
					}
					_, err = testSpec.Db.DB.Exec(query)
					if err != nil {
						t.Fatalf("Could not GRANT %s:\n%s\n%s", grant, query, err)
					}
				}

				// Read privileges
				r := NewFromDB(testSpec.Db.DB, testSpec.Db.Opts...)
				types := []string{"TABLE", "BASE TABLE", "SYSTEM TABLE", "SYNONYM", "LOCAL TEMPORARY", "GLOBAL TEMPORARY", "VIEW", "SYSTEM VIEW", "MATERIALIZED VIEW", "SEQUENCE"}
				result, err := r.PrivilegeSummaries(Filter{Schema: testSpec.Schema, Name: name, Types: types})
				if err != nil {
					t.Fatalf("Could not read privileges: %v", err)
				}

				// Check result
				if result.Len() != 1 {
					t.Fatalf("Wrong result count\nWant:\t%d\nGot:\t%d\n", 1, result.Len())
				}
				result.Next()
				if result.Get().Schema != testSpec.Schema {
					t.Errorf("Wrong schema!\nWant:\t%s\nGot:\t%s\n", testSpec.Schema, result.Get().Schema)
				}
				if result.Get().Name != name {
					t.Errorf("Wrong table!\nWant:\t%s\nGot:\t%s\n", name, result.Get().Name)
				}
				want := ""
				switch testSpec.Create {
				case "TABLE":
					want = "BASE TABLE"
				default:
					want = testSpec.Create
				}
				if result.Get().ObjectType != want {
					t.Errorf("Wrong Type!\nWant:\t%s\nGot:\t%s\n", want, result.Get().ObjectType)
				}
				gotTablePrivileges := result.Get().ObjectPrivileges
				sort.Sort(gotTablePrivileges)
				sort.Sort(testSpec.WantTable)
				if diff := cmp.Diff(testSpec.WantTable, gotTablePrivileges); diff != "" {
					t.Errorf("Wrong object privileges!\n(-expected, +got):\n%s", diff)
				}

				gotColumnPrivileges := result.Get().ColumnPrivileges
				sort.Sort(gotColumnPrivileges)
				sort.Sort(testSpec.WantColumn)
				if diff := cmp.Diff(testSpec.WantColumn, gotColumnPrivileges); diff != "" {
					t.Errorf("Wrong column privileges!\n(-expected, +got):\n%s", diff)
				}
			})
		}
	}
}
