// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package statedb

import (
	"embed"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

const (
	migrationConnectTimeout   = 10 * time.Second
	migrationStatementTimeout = 5 * time.Minute
)

//go:embed migrations/postgresql/*.sql
var migrations embed.FS

// migrationConnectionString fixes migration metadata and bounds database waits.
func migrationConnectionString(connectionString string) (string, error) {
	u, err := url.Parse(connectionString)
	if err != nil {
		return "", fmt.Errorf("parse PostgreSQL migration connection string: %w", err)
	}
	parameters := u.Query()
	statementTimeout := strconv.FormatInt(migrationStatementTimeout.Milliseconds(), 10)
	parameters.Set("connect_timeout", strconv.Itoa(int(migrationConnectTimeout.Seconds())))
	parameters.Set("statement_timeout", statementTimeout)
	parameters.Set("x-statement-timeout", statementTimeout)
	parameters.Set("x-migrations-table", `"public"."schema_migrations"`)
	parameters.Set("x-migrations-table-quoted", "true")
	u.RawQuery = parameters.Encode()
	return u.String(), nil
}

// MigratePostgreSQL explicitly applies all embedded PostgreSQL state migrations.
func MigratePostgreSQL(connectionString string) error {
	if err := validatePostgreSQLTLS(connectionString); err != nil {
		return err
	}
	connectionString, err := migrationConnectionString(connectionString)
	if err != nil {
		return err
	}
	source, err := iofs.New(migrations, "migrations/postgresql")
	if err != nil {
		return fmt.Errorf("open embedded migrations: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", source, connectionString)
	if err != nil {
		return fmt.Errorf("open state migrations: %w", err)
	}
	defer func() { _, _ = m.Close() }()
	if err = m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("apply state migrations: %w", err)
	}
	return nil
}
