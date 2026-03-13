package postgresql

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"log/slog"
	"time"
)

type PostgreSQL struct {
	db  *pgxpool.Pool
	log *slog.Logger
}

func New(ctx context.Context, databaseURL string, log *slog.Logger) (*PostgreSQL, error) {
	log.Info("Connecting to database...")

	conn, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("error connecting to database: %w", err)
	}

	ctxPing, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := conn.Ping(ctxPing); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}
	log.Info("Successfully connected to database")

	return &PostgreSQL{
		db:  conn,
		log: log,
	}, nil
}

func (pgsql *PostgreSQL) Close() {
	pgsql.db.Close()
}
