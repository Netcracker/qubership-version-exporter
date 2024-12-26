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

package collector

import (
	"context"
	"regexp"
	"testing"

	"qubership-version-exporter/model/postgres"
	"github.com/driftprogramming/pgxpoolmock"
	"github.com/golang/mock/gomock"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
)

const (
	pgUrl        = "postgres://localhost:5432/postgres?sslmode=disable"
	pgStatExt    = "pg_stat_statements"
	pgStatExtVer = "1.7"
	pgVersion    = "12.7"
	pgNSpace     = "2200"
)

func TestApplyMetricConfigLabel(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	nameLabel := model.LabelName(extensionName)
	mName := Metric{
		FieldName: extName,
		Label:     &nameLabel,
	}

	versionLabel := model.LabelName(extensionVersion)
	mVersion := Metric{
		FieldName: extVersion,
		Label:     &versionLabel,
	}

	mNamespace := Metric{
		FieldName: extNamespace,
	}

	req := Request{
		MetricName: pgMetricName,
		Sql:        pgExtensionVersionClusterSql,
		Metrics:    []Metric{mName, mVersion, mNamespace},
	}

	mockPool := pgxpoolmock.NewMockPgxPool(ctrl)
	columns := []string{extName, extVersion, extNamespace}
	pgxRows := pgxpoolmock.NewRows(columns).AddRow([]byte(pgStatExt), []byte(pgStatExtVer), []byte(pgNSpace)).ToPgxRows()
	mockPool.EXPECT().BeginTx(gomock.Any(), gomock.Any())
	mockPool.EXPECT().SendBatch(gomock.Any(), gomock.Any())
	mockPool.EXPECT().Query(ctx, req.Sql, gomock.Any()).Return(pgxRows, nil)

	txMgr := postgres.NewTxManager(mockPool)

	pgClient := PostgresClient{
		TxManager: txMgr,
		Url:       pgUrl,
		Requests:  []*Request{&req},
	}

	labelPair := Scrape(ctx, pgClient, t)

	assert.Equal(t, 5, len(labelPair))
	assert.Equal(t, uri, *labelPair[0].Name)
	assert.Equal(t, pgUrl, *labelPair[0].Value)
	assert.Equal(t, commonLabel, *labelPair[1].Name)
	assert.Equal(t, commonLabelValue, *labelPair[1].Value)
	assert.Equal(t, extensionName, *labelPair[2].Name)
	assert.Equal(t, pgStatExt, *labelPair[2].Value)
	assert.Equal(t, extensionVersion, *labelPair[3].Name)
	assert.Equal(t, pgStatExtVer, *labelPair[3].Value)
	assert.Equal(t, extNamespace, *labelPair[4].Name)
	assert.Equal(t, pgNSpace, *labelPair[4].Value)
}

func TestApplyMetricConfigNamedCaptureGroups(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	m := Metric{
		FieldName:   "version",
		ValueRegexp: regexp.MustCompile(`\s((?P<major>\d+).(?P<minor>\d+))\son\s(?P<platform>.*?),`),
	}
	req := Request{
		Sql:        pgVersionClusterSql,
		MetricName: pgMetricName,
		Metrics:    []Metric{m},
	}

	mockPool := pgxpoolmock.NewMockPgxPool(ctrl)
	columns := []string{"version"}
	pgxRows := pgxpoolmock.NewRows(columns).AddRow([]byte("PostgreSQL 12.7 on x86_64-pc-linux-gnu, compiled by gcc (GCC) 4.8.5 20150623 (Red Hat 4.8.5-44), 64-bit")).ToPgxRows()
	mockPool.EXPECT().BeginTx(gomock.Any(), gomock.Any())
	mockPool.EXPECT().SendBatch(gomock.Any(), gomock.Any())
	mockPool.EXPECT().Query(ctx, req.Sql, gomock.Any()).Return(pgxRows, nil)

	txMgr := postgres.NewTxManager(mockPool)

	pgClient := PostgresClient{
		TxManager: txMgr,
		Url:       pgUrl,
		Requests:  []*Request{&req},
	}

	labelPair := Scrape(ctx, pgClient, t)

	assert.Equal(t, 5, len(labelPair))
	assert.Equal(t, uri, *labelPair[0].Name)
	assert.Equal(t, pgUrl, *labelPair[0].Value)
	assert.Equal(t, commonLabel, *labelPair[1].Name)
	assert.Equal(t, commonLabelValue, *labelPair[1].Value)
	assert.Equal(t, "major", *labelPair[2].Name)
	assert.Equal(t, "12", *labelPair[2].Value)
	assert.Equal(t, "minor", *labelPair[3].Name)
	assert.Equal(t, "7", *labelPair[3].Value)
	assert.Equal(t, "platform", *labelPair[4].Name)
	assert.Equal(t, "x86_64-pc-linux-gnu", *labelPair[4].Value)
}

func TestApplyMetricConfigRegexp(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	m := Metric{
		FieldName:   metricServerFieldName,
		ValueRegexp: regexp.MustCompile(`((\d+).(\d+))`),
	}
	req := Request{
		MetricName: pgMetricName,
		Sql:        pgVersionSql,
		Metrics:    []Metric{m},
	}

	mockPool := pgxpoolmock.NewMockPgxPool(ctrl)
	columns := []string{metricServerFieldName}
	pgxRows := pgxpoolmock.NewRows(columns).AddRow([]byte(pgVersion)).ToPgxRows()
	mockPool.EXPECT().BeginTx(gomock.Any(), gomock.Any())
	mockPool.EXPECT().SendBatch(gomock.Any(), gomock.Any())
	mockPool.EXPECT().Query(ctx, req.Sql, gomock.Any()).Return(pgxRows, nil)

	txMgr := postgres.NewTxManager(mockPool)

	pgClient := PostgresClient{
		TxManager: txMgr,
		Url:       pgUrl,
		Requests:  []*Request{&req},
	}

	labelPair := Scrape(ctx, pgClient, t)

	assert.Equal(t, 3, len(labelPair))
	assert.Equal(t, uri, *labelPair[0].Name)
	assert.Equal(t, pgUrl, *labelPair[0].Value)
	assert.Equal(t, commonLabel, *labelPair[1].Name)
	assert.Equal(t, commonLabelValue, *labelPair[1].Value)
	assert.Equal(t, metricServerFieldName, *labelPair[2].Name)
	assert.Equal(t, pgVersion, *labelPair[2].Value)
}

func TestApplyMetricConfigLabelRegexp(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	label := model.LabelName("pg_server_version")
	m := Metric{
		FieldName:   metricServerFieldName,
		Label:       &label,
		ValueRegexp: regexp.MustCompile(`((\d+).(\d+))`),
	}
	req := Request{
		MetricName: pgMetricName,
		Sql:        pgVersionSql,
		Metrics:    []Metric{m},
	}

	mockPool := pgxpoolmock.NewMockPgxPool(ctrl)
	columns := []string{metricServerFieldName}
	pgxRows := pgxpoolmock.NewRows(columns).AddRow([]byte(pgVersion)).ToPgxRows()
	mockPool.EXPECT().BeginTx(gomock.Any(), gomock.Any())
	mockPool.EXPECT().SendBatch(gomock.Any(), gomock.Any())
	mockPool.EXPECT().Query(ctx, req.Sql, gomock.Any()).Return(pgxRows, nil)

	txMgr := postgres.NewTxManager(mockPool)

	pgClient := PostgresClient{
		TxManager: txMgr,
		Url:       pgUrl,
		Requests:  []*Request{&req},
	}

	labelPair := Scrape(ctx, pgClient, t)

	assert.Equal(t, 3, len(labelPair))
	assert.Equal(t, uri, *labelPair[0].Name)
	assert.Equal(t, pgUrl, *labelPair[0].Value)
	assert.Equal(t, commonLabel, *labelPair[1].Name)
	assert.Equal(t, commonLabelValue, *labelPair[1].Value)
	assert.Equal(t, "pg_server_version", *labelPair[2].Name)
	assert.Equal(t, pgVersion, *labelPair[2].Value)
}

func TestApplyMetricConfigIncorrectFieldName(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	nameLabel := model.LabelName(extensionName)
	mName := Metric{
		FieldName: extensionName,
		Label:     &nameLabel,
	}

	versionLabel := model.LabelName(extensionVersion)
	mVersion := Metric{
		FieldName: extVersion,
		Label:     &versionLabel,
	}

	mNamespace := Metric{
		FieldName: extNamespace,
	}

	req := Request{
		MetricName: pgMetricName,
		Sql:        pgExtensionVersionClusterSql,
		Metrics:    []Metric{mName, mVersion, mNamespace},
	}

	mockPool := pgxpoolmock.NewMockPgxPool(ctrl)
	columns := []string{extName, extVersion, extNamespace}
	pgxRows := pgxpoolmock.NewRows(columns).AddRow([]byte(pgStatExt), []byte(pgStatExtVer), []byte(pgNSpace)).ToPgxRows()
	mockPool.EXPECT().BeginTx(gomock.Any(), gomock.Any())
	mockPool.EXPECT().SendBatch(gomock.Any(), gomock.Any())
	mockPool.EXPECT().Query(ctx, req.Sql, gomock.Any()).Return(pgxRows, nil)

	txMgr := postgres.NewTxManager(mockPool)

	pgClient := PostgresClient{
		TxManager: txMgr,
		Url:       pgUrl,
		Requests:  []*Request{&req},
	}

	labelPair := Scrape(ctx, pgClient, t)

	assert.Equal(t, 4, len(labelPair))
	assert.Equal(t, uri, *labelPair[0].Name)
	assert.Equal(t, pgUrl, *labelPair[0].Value)
	assert.Equal(t, commonLabel, *labelPair[1].Name)
	assert.Equal(t, commonLabelValue, *labelPair[1].Value)
	assert.Equal(t, extensionVersion, *labelPair[2].Name)
	assert.Equal(t, pgStatExtVer, *labelPair[2].Value)
	assert.Equal(t, extNamespace, *labelPair[3].Name)
	assert.Equal(t, pgNSpace, *labelPair[3].Value)
}

func TestApplyMetricConfigEmptyMetrics(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	req := Request{
		MetricName: pgMetricName,
		Sql:        pgExtensionVersionSql,
		Metrics:    []Metric{},
	}

	mockPool := pgxpoolmock.NewMockPgxPool(ctrl)
	mockPool.EXPECT().BeginTx(gomock.Any(), gomock.Any())
	mockPool.EXPECT().SendBatch(gomock.Any(), gomock.Any())

	txMgr := postgres.NewTxManager(mockPool)

	pgClient := PostgresClient{
		TxManager: txMgr,
		Url:       pgUrl,
		Requests:  []*Request{&req},
	}

	labelPair := Scrape(ctx, pgClient, t)

	assert.Equal(t, 0, len(labelPair))
}

func Scrape(ctx context.Context, pgClient PostgresClient, t *testing.T) (labelPair []*dto.LabelPair) {
	metricCh := make(chan prometheus.Metric)
	endCh := make(chan struct{})
	defer close(metricCh)

	go func() {
		err := pgClient.doScrape(ctx, metricCh)
		assert.Empty(t, err)
		close(endCh)
	}()

	for {
		select {
		case mt := <-metricCh:
			metric := &dto.Metric{}
			err := mt.Write(metric)
			assert.Empty(t, err)
			assert.True(t, len(metric.Label) > 1) // more than collector.commonLabel
			labelPair = append(labelPair, metric.Label...)
			continue
		case <-endCh:
			break
		}
		break
	}

	return
}
