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
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"qubership-version-exporter/model/postgres"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/log/kitlogadapter"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const uri = "URI"

// check interface
var (
	_ Collector = &PostgresVersionScraper{}
)

func init() {
	registerCollector(Postgres.String(), defaultEnabled, newPostgresCollector)
}

func newPostgresCollector(logger log.Logger) (Collector, error) {
	return &PostgresVersionScraper{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", Postgres.String()),
			"List of postgres versions",
			nil, nil),
		ValueType: prometheus.GaugeValue,
		Logger:    logger,
	}, nil
}

type (
	PostgresClient struct {
		TxManager *postgres.TxManager
		Url       string
		Requests  []*Request
	}

	Request struct {
		Sql         string
		MetricName  string
		Metrics     []Metric
		Description string
	}

	Metric struct {
		FieldName   string
		Label       *model.LabelName
		ValueRegexp *regexp.Regexp
	}

	PostgresVersionScraper struct {
		Desc      *prometheus.Desc
		ValueType prometheus.ValueType
		Logger    log.Logger
		PgClients []*PostgresClient
	}
)

func (spv *PostgresVersionScraper) Close() {
	for _, pgClient := range spv.PgClients {
		pgClient.TxManager.Close()
	}

	spv.PgClients = spv.PgClients[:0]
}

func (spv *PostgresVersionScraper) Type() Type {
	return Postgres
}

// Name of the Scraper. Should be unique.
func (spv *PostgresVersionScraper) Name() string {
	return Postgres.String()
}

func (spv *PostgresVersionScraper) Initialize(ctx context.Context, config interface{}) error {
	var connOptions postgres.PgConnections
	cfg := reflect.ValueOf(config)
	switch cfg.Kind() {
	case reflect.Struct:
		connOptions = config.(postgres.PgConnections)
	default:
		return errors.Errorf("unsupported type: %v", cfg.Type())
	}

	for _, connOption := range connOptions.Connections {
		pgClient := spv.InitPostgres(ctx, connOption)
		if pgClient != nil {
			spv.PgClients = append(spv.PgClients, pgClient)
		}
	}

	return nil
}

// Scrape collects data from Postgres and sends it over channel as prometheus metric.
func (spv *PostgresVersionScraper) Scrape(ctx context.Context, metrics *Metrics, ch chan<- prometheus.Metric) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	for _, pgClient := range spv.PgClients {
		wg.Add(1)
		go func(pgClient *PostgresClient) {
			defer wg.Done()
			errs := pgClient.doScrape(ctx, ch)
			if errs != nil {
				label := collectorPrefix + spv.Name() + "_" + pgClient.Url
				for _, err := range errs {
					_ = level.Error(spv.Logger).Log("msg", fmt.Sprintf("Error from scraper: %s %s", spv.Name(), pgClient.Url), "err", err)
					metrics.ScrapeErrors.WithLabelValues(label).Inc()
				}
				metrics.Error.Set(1)
			}
		}(pgClient)
	}

	_ = level.Debug(spv.Logger).Log(Postgres.String(), "done")
	return nil
}

func (spv *PostgresVersionScraper) InitPostgres(ctx context.Context, connOptions postgres.ConnOptions) *PostgresClient {
	userSecret, err := connOptions.Credentials.ClientSet.CoreV1().Secrets(connOptions.Credentials.Namespace).Get(ctx, connOptions.Credentials.User.Name, metav1.GetOptions{})
	if err != nil {
		_ = level.Error(spv.Logger).Log("msg", "can't get pg user data", "err", err)
		return nil
	}

	var pswdSecret *corev1.Secret
	if connOptions.Credentials.User.Name != connOptions.Credentials.Password.Name {
		pswdSecret, err = connOptions.Credentials.ClientSet.CoreV1().Secrets(connOptions.Credentials.Namespace).Get(ctx, connOptions.Credentials.Password.Name, metav1.GetOptions{})
		if err != nil {
			_ = level.Error(spv.Logger).Log("msg", "can't get pg secret data", "err", err)
			return nil
		}
	} else {
		pswdSecret = userSecret
	}

	pgUri := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=disable",
		string(userSecret.Data[connOptions.Credentials.User.Key]), string(pswdSecret.Data[connOptions.Credentials.Password.Key]),
		connOptions.Host, connOptions.Port, connOptions.DbName)

	pgClient, err := spv.InitPostgresClient(ctx, pgUri, connOptions.Timeout)
	if err != nil {
		_ = level.Error(spv.Logger).Log("msg", "can't create postgres client", "err", err)
		return nil
	}

	pgUri = fmt.Sprintf("postgres://%v:%v/%v", connOptions.Host, connOptions.Port, connOptions.DbName)
	pgClient.Url = pgUri

	for _, req := range connOptions.Requests {
		var metrics []Metric

		for _, metric := range req.Metrics {
			var regXp *regexp.Regexp
			var label *model.LabelName

			if metric.Regexp != "" {
				regXp = regexp.MustCompile(metric.Regexp)
			}

			if metric.Label != "" {
				if model.LabelName(metric.Label).IsValid() {
					l := model.LabelName(metric.Label)
					label = &l
				} else {
					_ = level.Error(spv.Logger).Log("msg", fmt.Sprintf("label name - %s is not a valid", string(*label)))
					return nil
				}
			}

			m := Metric{
				FieldName:   metric.FieldName,
				Label:       label,
				ValueRegexp: regXp,
			}
			metrics = append(metrics, m)
		}
		request := &Request{
			Sql:         req.Sql,
			MetricName:  req.MetricName,
			Metrics:     metrics,
			Description: req.Description,
		}
		pgClient.Requests = append(pgClient.Requests, request)
	}

	return pgClient
}

func (spv *PostgresVersionScraper) InitPostgresClient(ctx context.Context, pgUri string, timeout model.Duration) (*PostgresClient, error) {
	cfg, err := pgxpool.ParseConfig(pgUri)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create connection to %v", pgUri)
	}
	cfg.MaxConnLifetime = time.Duration(timeout)

	cfg.ConnConfig.Logger = kitlogadapter.NewLogger(log.With(spv.Logger, "pg_caller", log.Caller(5)))
	logLevel, err := pgx.LogLevelFromString(os.Getenv("LOG_LEVEL"))
	if err == nil && logLevel >= pgx.LogLevelDebug {
		cfg.ConnConfig.LogLevel = logLevel
	} else {
		cfg.ConnConfig.LogLevel = pgx.LogLevelWarn
	}

	pool, err := pgxpool.ConnectConfig(context.Background(), cfg)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create connection to %v", pgUri)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to acquires a connection to %v from the pool", pgUri)
	}

	err = tx.Conn().Ping(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to ping connection to %v", pgUri)
	}

	var version string
	err = tx.QueryRow(context.Background(), "show server_version").Scan(&version)
	if err != nil {
		return nil, errors.Wrapf(err, "could not retrieve postgres version")
	}
	_ = level.Info(spv.Logger).Log("msg", fmt.Sprintf("Successfully connected to Postgres. Version: %s", version))

	err = tx.Commit(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to commit the transaction: %v", pgUri)
	}

	txMgr := postgres.NewTxManager(pool)

	return &PostgresClient{
		TxManager: txMgr,
	}, nil
}

func (pgClient *PostgresClient) doScrape(ctx context.Context, ch chan<- prometheus.Metric) (errs []error) {
	tx, err := pgClient.TxManager.BeginRo(ctx)
	if err != nil {
		errs = append(errs, err)
		return
	}
	defer func(TxManager *postgres.TxManager, ctx context.Context, tx pgx.Tx) {
		err = TxManager.Commit(ctx, tx)
		if err != nil {
			errs = append(errs, err)
		}
	}(pgClient.TxManager, ctx, tx)

	batch := &pgx.Batch{}
	for _, req := range pgClient.Requests {
		batch.Queue(req.Sql)
	}
	br := pgClient.TxManager.SendBatch(context.Background(), tx, batch)
	defer func(TxManager *postgres.TxManager, ctx context.Context, br pgx.BatchResults) {
		err = pgClient.TxManager.BatchResultClose(ctx, br)
		if err != nil {
			errs = append(errs, err)
		}
	}(pgClient.TxManager, ctx, br)

	for _, req := range pgClient.Requests {
		if len(req.Metrics) == 0 {
			continue
		}
		var rows pgx.Rows
		rows, err = pgClient.TxManager.Query(ctx, br, req.Sql)
		if err != nil {
			errs = append(errs, err)
			err = pgClient.TxManager.Rollback(ctx, tx)
			if err != nil {
				errs = append(errs, err)
			}
			return
		}

		var names []string
		for _, fd := range rows.FieldDescriptions() {
			names = append(names, string(fd.Name))
		}

		for rows.Next() {
			var val []interface{}
			var values []string
			nValues := make(map[string]string)

			val, err = pgClient.TxManager.GetValues(ctx, rows, br)
			if err != nil {
				errs = append(errs, err)
				err = pgClient.TxManager.Rollback(ctx, tx)
				if err != nil {
					errs = append(errs, err)
				}
				return
			}

			for _, v := range val {
				values = append(values, fmt.Sprintf("%v", v))
			}

			for i, name := range names {
				nValues[name] = values[i]
			}
			var labels, labelValues []string
			labels, labelValues, err = req.ApplyMetricConfig(ctx, nValues)
			if err != nil {
				errs = append(errs, err)
				err = pgClient.TxManager.Rollback(ctx, tx)
				if err != nil {
					errs = append(errs, err)
				}
				return
			}
			req.sendMetrics(labels, labelValues, pgClient.Url, ch)
		}
		if rows.Err() != nil {
			errs = append(errs, rows.Err())
			err = pgClient.TxManager.Rollback(ctx, tx)
			if err != nil {
				errs = append(errs, err)
			}
			return
		}
	}

	return
}

func (request *Request) ApplyMetricConfig(ctx context.Context, fieldNV map[string]string) (labels, labelValues []string, err error) {

	for _, metric := range request.Metrics {
		if val, find := fieldNV[metric.FieldName]; find {
			var lbls, lblvs []string

			value := val
			label := metric.FieldName

			if metric.ValueRegexp == nil {
				if metric.Label != nil {
					label = string(*metric.Label)
				}
			} else {
				subNames := deleteEmpty(metric.ValueRegexp.SubexpNames())
				if len(subNames) == 0 {
					if metric.Label != nil {
						label = string(*metric.Label)
					}
					value = metric.ValueRegexp.FindString(value)
				} else {
					subNames = metric.ValueRegexp.SubexpNames()
					res := metric.ValueRegexp.FindStringSubmatch(value)
					for k, v := range subNames {
						if v != "" {
							lbls = append(lbls, v)
							lblvs = append(lblvs, res[k])
						}
					}
				}
			}

			if len(lbls) != 0 {
				labels = append(labels, lbls...)
				labelValues = append(labelValues, lblvs...)
			} else {
				labels = append(labels, label)
				labelValues = append(labelValues, value)
			}
		}
	}

	return
}

func (request *Request) sendMetrics(labels, labelValues []string, pgUrl string, ch chan<- prometheus.Metric) {
	labels = append(labels, commonLabel)
	labelValues = append(labelValues, commonLabelValue)

	labels = append([]string{uri}, labels...)
	labelValues = append([]string{pgUrl}, labelValues...)

	help := "A metric generated by version-exporter postgres collector."
	if len(strings.TrimSpace(request.Description)) > 0 {
		help = fmt.Sprintf("%s Description: %s.", help, request.Description)
	}

	buildInfo := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: request.MetricName,
			Help: help,
		},
		labels,
	)
	buildInfo.WithLabelValues(labelValues...).Inc()
	buildInfo.MetricVec.Collect(ch)
}

func deleteEmpty(s []string) []string {
	var r []string
	for _, str := range s {
		if str != "" {
			r = append(r, str)
		}
	}
	return r
}
