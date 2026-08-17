package selfmonitor

import (
	"os"
	"path/filepath"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	logger  *zap.Logger
	sugared *zap.SugaredLogger
	logMu   sync.Mutex
)

// InitLogger 初始化 zap 结构化日志
// level: debug, info, warn, error
func InitLogger(level string) *zap.Logger {
	logMu.Lock()
	defer logMu.Unlock()

	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "module",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.MillisDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	config := zap.Config{
		Level:            zap.NewAtomicLevelAt(zapLevel),
		Encoding:         "json",
		EncoderConfig:    encoderConfig,
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}

	if isJournal {
		config.OutputPaths = []string{"stdout"}
	}

	l, err := config.Build(zap.AddCallerSkip(0))
	if err != nil {
		// 降级到基本日志
		l = zap.NewNop()
	}

	logger = l
	sugared = l.Sugar()
	return l
}

var isJournal = false

// SetJournalOutput 设置日志输出到 systemd journal
func SetJournalOutput(enabled bool) {
	isJournal = enabled
}

// GetLogger 获取全局 logger
func GetLogger() *zap.Logger {
	if logger == nil {
		return InitLogger("info")
	}
	return logger
}

// GetSugaredLogger 获取全局 sugared logger
func GetSugaredLogger() *zap.SugaredLogger {
	if sugared == nil {
		InitLogger("info")
	}
	return sugared
}

// SetLevel 动态调整日志级别（不重启 Agent）
func SetLevel(level string) {
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		return
	}
	GetLogger().Core().Enabled(zapLevel)
}

// WithTraceID 创建带 trace_id 的 logger
func WithTraceID(traceID string) *zap.Logger {
	return GetLogger().With(zap.String("trace_id", traceID))
}

// Sync 刷新日志缓冲
func Sync() {
	if logger != nil {
		_ = logger.Sync()
	}
}

// ReplaceLogger 替换全局 logger（用于测试）
func ReplaceLogger(l *zap.Logger) {
	logMu.Lock()
	defer logMu.Unlock()
	logger = l
	sugared = l.Sugar()
}

// IsInitialized 检查 logger 是否已初始化
func IsInitialized() bool {
	return logger != nil
}

// WriteToFile 同时输出到文件
func WriteToFile(path string) error {
	dir := filepath.Dir(path)
	return os.MkdirAll(dir, 0750)
}
