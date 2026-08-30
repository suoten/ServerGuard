package storage

import (
	"fmt"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// Downsampler implements 搂8.6: Data Lifecycle and Downsampling.
// Converts: second-level raw data 鈫?1min aggregates 鈫?1h aggregates.
// This keeps the SQLite database small (~36MB for 90 days).
type Downsampler struct {
	mu      sync.Mutex
	storage *Storage
	// Buffer for raw second-level data
	rawBuffer    map[string][]MetricSample // metric key -> samples
	bufferMaxAge time.Duration             // max age before flushing
}

// MetricSample represents a single metric sample.
type MetricSample struct {
	Value     float64
	Timestamp time.Time
}

// NewDownsampler creates a new Downsampler.
func NewDownsampler(store *Storage) *Downsampler {
	return &Downsampler{
		storage:      store,
		rawBuffer:    make(map[string][]MetricSample),
		bufferMaxAge: 1 * time.Hour,
	}
}

// AddRawMetric adds a raw second-level metric sample to the buffer.
func (d *Downsampler) AddRawMetric(key string, value float64, ts time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rawBuffer[key] = append(d.rawBuffer[key], MetricSample{Value: value, Timestamp: ts})
}

// RunHourlyDownsample runs the hourly downsampling job.
// It takes all raw second-level data older than 1 hour,
// aggregates it to 1-minute granularity, writes it to the 1min table,
// and deletes the raw data.
func (d *Downsampler) RunHourlyDownsample() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	db := d.storage.DB()

	cutoff1h := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		INSERT INTO metrics_1m (type, name, avg, min, max, p95, count, unit, labels, timestamp)
		SELECT
			type, name,
			AVG(value) as min_avg,
			MIN(value) as min_min,
			MAX(value) as min_max,
			NULL as min_p95,
			COUNT(*) as min_count,
			unit, labels,
			datetime(strftime('%s', timestamp)/60*60, 'unixepoch') as min_ts
		FROM metrics
		WHERE granularity = 'raw' AND timestamp < ?
		GROUP BY type, name, labels, min_ts
	`, cutoff1h)
	if err != nil {
		return fmt.Errorf("aggregate raw to 1m: %w", err)
	}

	_, err = tx.Exec("DELETE FROM metrics WHERE granularity = 'raw' AND timestamp < ?", cutoff1h)
	if err != nil {
		return fmt.Errorf("delete old raw data: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit hourly downsample: %w", err)
	}

	for key, samples := range d.rawBuffer {
		minuteBuckets := make(map[time.Time][]MetricSample)
		cutoff := time.Now().Add(-1 * time.Hour)

		var retained []MetricSample
		for _, sample := range samples {
			if sample.Timestamp.Before(cutoff) {
				minuteStart := sample.Timestamp.Truncate(time.Minute)
				minuteBuckets[minuteStart] = append(minuteBuckets[minuteStart], sample)
			} else {
				retained = append(retained, sample)
			}
		}
		d.rawBuffer[key] = retained

		for minuteStart, bucketSamples := range minuteBuckets {
			agg := d.aggregate(bucketSamples)
			d.storage.SaveMetric(types.Metric{
				Name:      key,
				Value:     agg.Avg,
				Timestamp: minuteStart,
				Unit:      "",
				Labels: map[string]string{
					"granularity": "1min",
					"min":         fmt.Sprintf("%.2f", agg.Min),
					"max":         fmt.Sprintf("%.2f", agg.Max),
					"p95":         fmt.Sprintf("%.2f", agg.P95),
					"count":       fmt.Sprintf("%d", agg.Count),
				},
			})
		}
	}

	return nil
}

// RunDailyDownsample runs the daily downsampling job.
// It takes all 1-minute data older than 7 days,
// aggregates it to 1-hour granularity, and deletes the 1-minute data.
func (d *Downsampler) RunDailyDownsample() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	db := d.storage.DB()

	cutoff7d := time.Now().Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339)

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		INSERT INTO metrics_1h (type, name, avg, min, max, p95, count, unit, labels, timestamp)
		SELECT
			type, name,
			AVG(avg) as hour_avg,
			MIN(min) as hour_min,
			MAX(max) as hour_max,
			AVG(p95) as hour_p95,
			SUM(count) as hour_count,
			unit, labels,
			datetime(strftime('%s', timestamp)/3600*3600, 'unixepoch') as hour_ts
		FROM metrics_1m
		WHERE timestamp < datetime(?)
		GROUP BY type, name, labels, hour_ts
	`, cutoff7d)
	if err != nil {
		return fmt.Errorf("aggregate 1m to 1h: %w", err)
	}

	_, err = tx.Exec("DELETE FROM metrics_1m WHERE timestamp < datetime(?)", cutoff7d)
	if err != nil {
		return fmt.Errorf("delete old 1m data: %w", err)
	}

	return tx.Commit()
}

// RunCleanup deletes data older than retention periods.
// - 1min data: 7 days
// - 1h data: 90 days
// - raw metrics: 24 hours
// - events: 180 days
// - audit logs: 365 days
func (d *Downsampler) RunCleanup() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	db := d.storage.DB()

	now := time.Now()
	cutoff24h := now.Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	cutoff7d := now.Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	cutoff90d := now.Add(-90 * 24 * time.Hour).UTC().Format(time.RFC3339)
	cutoff180d := now.Add(-180 * 24 * time.Hour).UTC().Format(time.RFC3339)
	cutoff365d := now.Add(-365 * 24 * time.Hour).UTC().Format(time.RFC3339)

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM metrics WHERE granularity = 'raw' AND timestamp < ?", cutoff24h); err != nil {
		return fmt.Errorf("cleanup raw metrics: %w", err)
	}

	if _, err := tx.Exec("DELETE FROM metrics_1m WHERE timestamp < datetime(?)", cutoff7d); err != nil {
		return fmt.Errorf("cleanup 1m metrics: %w", err)
	}

	if _, err := tx.Exec("DELETE FROM metrics_1h WHERE timestamp < datetime(?)", cutoff90d); err != nil {
		return fmt.Errorf("cleanup 1h metrics: %w", err)
	}

	if _, err := tx.Exec("DELETE FROM alerts WHERE timestamp < ?", cutoff180d); err != nil {
		return fmt.Errorf("cleanup alerts: %w", err)
	}

	if _, err := tx.Exec("DELETE FROM actions WHERE timestamp < ?", cutoff180d); err != nil {
		return fmt.Errorf("cleanup actions: %w", err)
	}

	if _, err := tx.Exec("DELETE FROM findings WHERE status IN ('fixed', 'ignored', 'false_positive') AND updated_at < ?", cutoff365d); err != nil {
		return fmt.Errorf("cleanup findings: %w", err)
	}

	if _, err := tx.Exec("DELETE FROM attack_events WHERE created_at < ?", cutoff180d); err != nil {
		return fmt.Errorf("cleanup attack events: %w", err)
	}

	return tx.Commit()
}

// aggregate calculates min, max, avg, p95 from a set of samples.
func (d *Downsampler) aggregate(samples []MetricSample) AggregatedMetric {
	if len(samples) == 0 {
		return AggregatedMetric{}
	}

	var sum, min, max float64
	min = samples[0].Value
	max = samples[0].Value

	for _, s := range samples {
		sum += s.Value
		if s.Value < min {
			min = s.Value
		}
		if s.Value > max {
			max = s.Value
		}
	}

	n := len(samples)
	avg := sum / float64(n)

	// Calculate P95
	values := make([]float64, n)
	for i, s := range samples {
		values[i] = s.Value
	}
	d.sortFloats(values)
	p95Idx := int(float64(n) * 0.95)
	if p95Idx >= n {
		p95Idx = n - 1
	}

	return AggregatedMetric{
		Min:   min,
		Max:   max,
		Avg:   avg,
		P95:   values[p95Idx],
		Count: n,
	}
}

// AggregatedMetric represents aggregated statistics.
type AggregatedMetric struct {
	Min   float64
	Max   float64
	Avg   float64
	P95   float64
	P99   float64
	Count int
}

// sortFloats sorts a slice of float64 in ascending order (insertion sort).
func (d *Downsampler) sortFloats(a []float64) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1] > a[j]; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}

// Start starts the downsampler with periodic execution.
// 纾佺洏姘翠綅鎰熺煡锛歨igh 鍔犻€熼檷閲囨牱锛宑ritical 鍒犲喎鏁版嵁锛宯ormal 甯歌娓呯悊銆?
func (d *Downsampler) Start(stop <-chan struct{}) {
	hourlyTicker := time.NewTicker(1 * time.Hour)
	defer hourlyTicker.Stop()

	dailyTicker := time.NewTicker(24 * time.Hour)
	defer dailyTicker.Stop()

	cleanupTicker := time.NewTicker(1 * time.Hour)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-hourlyTicker.C:
			if err := d.RunHourlyDownsample(); err != nil {
				_ = fmt.Errorf("hourly downsample failed: %w", err)
			}
		case <-dailyTicker.C:
			if err := d.RunDailyDownsample(); err != nil {
				_ = fmt.Errorf("daily downsample failed: %w", err)
			}
			if err := d.RunWithWatermarkAwareness(); err != nil {
				_ = fmt.Errorf("watermark-aware cleanup failed: %w", err)
			}
		case <-cleanupTicker.C:
			d.RunWithWatermarkAwareness()
		}
	}
}

// AccelerateOnHighWatermark 鍦ㄧ鐩橀珮姘翠綅(>80%)鏃跺姞閫熼檷閲囨牱銆?
// 灏?1min 鏁版嵁鎻愬墠鑱氬悎涓?1h锛屽皢 raw 鏁版嵁鎻愬墠鑱氬悎涓?1min锛屽噺灏戝瓨鍌ㄥ崰鐢ㄣ€?
func (d *Downsampler) AccelerateOnHighWatermark() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	db := d.storage.DB()
	now := time.Now()

	// 鎻愬墠灏?3 澶╁墠鐨?1min 鏁版嵁鑱氬悎涓?1h锛堟甯告槸 7 澶╋級
	cutoff3d := now.Add(-3 * 24 * time.Hour).UTC().Format(time.RFC3339)

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		INSERT INTO metrics_1h (type, name, avg, min, max, p95, count, unit, labels, timestamp)
		SELECT
			type, name,
			AVG(avg), MIN(min), MAX(max), AVG(p95), SUM(count),
			unit, labels,
			datetime(strftime('%s', timestamp)/3600*3600, 'unixepoch')
		FROM metrics_1m
		WHERE timestamp < datetime(?)
		GROUP BY type, name, labels, datetime(strftime('%s', timestamp)/3600*3600, 'unixepoch')
	`, cutoff3d)
	if err != nil {
		return fmt.Errorf("accelerate 1m to 1h: %w", err)
	}

	if _, err := tx.Exec("DELETE FROM metrics_1m WHERE timestamp < datetime(?)", cutoff3d); err != nil {
		return fmt.Errorf("delete accelerated 1m data: %w", err)
	}

	// 鎻愬墠灏?30 鍒嗛挓鍓嶇殑 raw 鏁版嵁鑱氬悎涓?1min锛堟甯告槸 1 灏忔椂锛?
	cutoff30m := now.Add(-30 * time.Minute).UTC().Format(time.RFC3339)
	_, err = tx.Exec(`
		INSERT INTO metrics_1m (type, name, avg, min, max, p95, count, unit, labels, timestamp)
		SELECT
			type, name,
			AVG(value), MIN(value), MAX(value), NULL, COUNT(*),
			unit, labels,
			datetime(strftime('%s', timestamp)/60*60, 'unixepoch')
		FROM metrics
		WHERE granularity = 'raw' AND timestamp < ?
		GROUP BY type, name, labels, datetime(strftime('%s', timestamp)/60*60, 'unixepoch')
	`, cutoff30m)
	if err != nil {
		return fmt.Errorf("accelerate raw to 1m: %w", err)
	}

	if _, err := tx.Exec("DELETE FROM metrics WHERE granularity = 'raw' AND timestamp < ?", cutoff30m); err != nil {
		return fmt.Errorf("delete accelerated raw data: %w", err)
	}

	return tx.Commit()
}

// PurgeColdDataOnCritical 鍦ㄧ鐩樹复鐣?>90%)鏃跺垹闄ら潪瀹¤鍐锋暟鎹紝鍙繚鐣?7 澶┿€?
// 瀹¤琛?audit_log)涓嶅彈褰卞搷锛岀鍚?WORM 瑕佹眰銆?
func (d *Downsampler) PurgeColdDataOnCritical() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	db := d.storage.DB()
	now := time.Now()
	cutoff7d := now.Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339)

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	// 鍒犻櫎 7 澶╁墠鐨勬墍鏈夐潪瀹¤鏁版嵁
	if _, err := tx.Exec("DELETE FROM metrics WHERE timestamp < ?", cutoff7d); err != nil {
		return fmt.Errorf("purge cold metrics: %w", err)
	}
	if _, err := tx.Exec("DELETE FROM metrics_1m WHERE timestamp < datetime(?)", cutoff7d); err != nil {
		return fmt.Errorf("purge cold 1m metrics: %w", err)
	}
	if _, err := tx.Exec("DELETE FROM metrics_1h WHERE timestamp < datetime(?)", cutoff7d); err != nil {
		return fmt.Errorf("purge cold 1h metrics: %w", err)
	}
	if _, err := tx.Exec("DELETE FROM alerts WHERE timestamp < ?", cutoff7d); err != nil {
		return fmt.Errorf("purge cold alerts: %w", err)
	}
	if _, err := tx.Exec("DELETE FROM actions WHERE timestamp < ?", cutoff7d); err != nil {
		return fmt.Errorf("purge cold actions: %w", err)
	}
	if _, err := tx.Exec("DELETE FROM attack_events WHERE created_at < ?", cutoff7d); err != nil {
		_ = err // 琛ㄥ彲鑳戒笉瀛樺湪
	}
	if _, err := tx.Exec("DELETE FROM findings WHERE status IN ('fixed', 'ignored', 'false_positive') AND updated_at < ?", cutoff7d); err != nil {
		_ = err
	}
	if _, err := tx.Exec("DELETE FROM snapshots WHERE expires_at < ?", now.UTC().Format(time.RFC3339)); err != nil {
		_ = err
	}

	// 娉ㄦ剰锛歛udit_log 琛ㄤ笉鍒犻櫎锛學ORM 璇箟

	return tx.Commit()
}

// RunWithWatermarkAwareness 鏍规嵁纾佺洏姘翠綅鑷€傚簲鎵ц闄嶉噰鏍峰拰娓呯悊銆?
// high: 鍔犻€熼檷閲囨牱, critical: 鍒犲喎鏁版嵁, normal: 甯歌娓呯悊銆?
func (d *Downsampler) RunWithWatermarkAwareness() error {
	wm := d.storage.CheckDiskWatermark()
	switch wm.Level {
	case WatermarkCritical:
		if err := d.PurgeColdDataOnCritical(); err != nil {
			return fmt.Errorf("purge cold data on critical: %w", err)
		}
		// critical 鏃跺悓鏃跺姞閫熼檷閲囨牱
		return d.AccelerateOnHighWatermark()
	case WatermarkHigh:
		return d.AccelerateOnHighWatermark()
	default:
		return d.RunCleanup()
	}
}
