package log

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type LogAutoScanner struct {
	mu         sync.RWMutex
	discovered []string
}

func NewLogAutoScanner() *LogAutoScanner {
	return &LogAutoScanner{}
}

func (s *LogAutoScanner) AutoDiscover() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var logs []string
	searchDirs := []string{"/var/log", "/var/log/nginx", "/var/log/apache2", "/var/log/httpd"}
	if runtime.GOOS == "windows" {
		searchDirs = []string{`C:\inetpub\logs`, `C:\Windows\System32\LogFiles`}
	}

	for _, dir := range searchDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if strings.HasSuffix(name, ".log") || strings.HasSuffix(name, ".log.gz") {
				logs = append(logs, filepath.Join(dir, name))
			}
		}
	}

	s.discovered = logs
	return logs, nil
}

func (s *LogAutoScanner) GetDiscovered() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.discovered
}

type LogQuotaManager struct {
	mu     sync.RWMutex
	quotas map[string]int64
}

func NewLogQuotaManager() *LogQuotaManager {
	return &LogQuotaManager{
		quotas: make(map[string]int64),
	}
}

func (q *LogQuotaManager) SetQuota(dir string, maxBytes int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.quotas[dir] = maxBytes
}

func (q *LogQuotaManager) CheckQuota(dir string) (currentSize int64, quota int64, exceeded bool, err error) {
	q.mu.RLock()
	quota = q.quotas[dir]
	q.mu.RUnlock()

	if quota == 0 {
		return 0, 0, false, nil
	}

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			currentSize += info.Size()
		}
		return nil
	})
	exceeded = currentSize > quota
	return
}

func (q *LogQuotaManager) EnforceQuota(dir string) (deletedFiles int, err error) {
	currentSize, quota, exceeded, e := q.CheckQuota(dir)
	if e != nil {
		return 0, e
	}
	if !exceeded {
		return 0, nil
	}

	type fileInfo struct {
		path    string
		size    int64
		modTime time.Time
	}
	var files []fileInfo

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		files = append(files, fileInfo{path, info.Size(), info.ModTime()})
		return nil
	})

	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.Before(files[j].modTime)
	})

	for _, f := range files {
		if currentSize <= quota {
			break
		}
		os.Remove(f.path)
		currentSize -= f.size
		deletedFiles++
	}
	return deletedFiles, nil
}

type LogWriteRateMonitor struct {
	mu          sync.RWMutex
	rates       map[string]*rateInfo
	thresholdMB float64
}

type rateInfo struct {
	lastSize  int64
	lastTime  time.Time
	rateMBps  float64
}

func NewLogWriteRateMonitor() *LogWriteRateMonitor {
	return &LogWriteRateMonitor{
		rates:       make(map[string]*rateInfo),
		thresholdMB: 10,
	}
}

func (m *LogWriteRateMonitor) Check(path string) (exceeded bool, rateMBps float64, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, 0, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if r, exists := m.rates[path]; exists {
		elapsed := now.Sub(r.lastTime).Seconds()
		if elapsed > 0 {
			r.rateMBps = float64(info.Size()-r.lastSize) / 1024 / 1024 / elapsed
		}
	} else {
		m.rates[path] = &rateInfo{lastSize: info.Size(), lastTime: now}
		return false, 0, nil
	}

	r := m.rates[path]
	r.lastSize = info.Size()
	r.lastTime = now

	return r.rateMBps > m.thresholdMB, r.rateMBps, nil
}

type LogRotateChecker struct{}

func NewLogRotateChecker() *LogRotateChecker { return &LogRotateChecker{} }

func (c *LogRotateChecker) IsManagedByLogrotate(path string) bool {
	dirs := []string{"/etc/logrotate.d", "/etc/logrotate.conf"}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			content, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}
			if strings.Contains(string(content), path) {
				return true
			}
		}
	}
	return false
}

func (c *LogRotateChecker) GenerateConfigTemplate(format string) string {
	switch format {
	case "logback":
		return `<configuration>
  <appender name="ROLLING" class="ch.qos.logback.core.rolling.RollingFileAppender">
    <file>/var/log/app/app.log</file>
    <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
      <fileNamePattern>/var/log/app/app.%d{yyyy-MM-dd}.%i.log.gz</fileNamePattern>
      <maxFileSize>100MB</maxFileSize>
      <maxHistory>30</maxHistory>
      <totalSizeCap>10GB</totalSizeCap>
    </rollingPolicy>
  </appender>
</configuration>`
	case "log4j":
		return `<RollingFile name="RollingFile" fileName="/var/log/app/app.log"
  filePattern="/var/log/app/app.%d{yyyy-MM-dd}.%i.log.gz">
  <Policies>
    <SizeBasedTriggeringPolicy size="100MB"/>
    <TimeBasedTriggeringPolicy/>
  </Policies>
  <DefaultRolloverStrategy max="30"/>
</RollingFile>`
	case "winston":
		return `const winston = require('winston');
const logger = winston.createLogger({
  transports: [
    new winston.transports.File({
      filename: '/var/log/app/app.log',
      maxsize: 100 * 1024 * 1024,
      maxFiles: 30,
    })
  ]
});`
	default:
		return fmt.Sprintf("# Log rotation config for %s\n# Please configure your logging framework", format)
	}
}