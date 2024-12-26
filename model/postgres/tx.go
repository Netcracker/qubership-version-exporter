// Copyright 2024-2025 NetCracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package postgres

import (
	"context"

	"github.com/driftprogramming/pgxpoolmock"
	"github.com/jackc/pgx/v4"
	"github.com/pkg/errors"
)

type TxManager struct {
	connPool pgxpoolmock.PgxPool
}

func NewTxManager(pool pgxpoolmock.PgxPool) *TxManager {
	return &TxManager{connPool: pool}
}

func (mgr *TxManager) BeginRo(ctx context.Context) (pgx.Tx, error) {
	tx, err := mgr.connPool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	return tx, errors.WithStack(err)
}

func (mgr *TxManager) SendBatch(ctx context.Context, tx pgx.Tx, batch *pgx.Batch) pgx.BatchResults {
	if tx == nil {
		return mgr.connPool.SendBatch(ctx, batch)
	}
	return tx.SendBatch(ctx, batch)
}

func (mgr *TxManager) Query(ctx context.Context, br pgx.BatchResults, sql string) (pgx.Rows, error) {
	if br == nil {
		return mgr.connPool.Query(ctx, sql)
	}
	return br.Query()
}

func (mgr *TxManager) GetValues(ctx context.Context, rows pgx.Rows, br pgx.BatchResults) ([]interface{}, error) {
	if br == nil {
		var values []interface{}
		for _, v := range rows.RawValues() {
			values = append(values, string(v))
		}
		return values, nil
	}

	return rows.Values()
}

func (mgr *TxManager) Commit(ctx context.Context, tx pgx.Tx) error {
	if tx == nil {
		return nil
	}
	return errors.WithStack(tx.Commit(ctx))
}

func (mgr *TxManager) BatchResultClose(ctx context.Context, br pgx.BatchResults) error {
	if br == nil {
		return nil
	}
	return errors.WithStack(br.Close())
}

func (mgr *TxManager) Rollback(ctx context.Context, tx pgx.Tx) error {
	if tx == nil {
		return nil
	}
	return errors.WithStack(tx.Rollback(ctx))
}

func (mgr *TxManager) Close() {
	mgr.connPool.Close()
}
