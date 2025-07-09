package db

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type (
	Querier interface {
		QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	}

	pgxQuerier struct {
		pgx *pgxpool.Pool
	}
)

func NewQuerier(pool *pgxpool.Pool) Querier {
	return &pgxQuerier{pgx: pool}
}

func (p *pgxQuerier) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return p.pgx.QueryRow(ctx, sql, args...)
}
