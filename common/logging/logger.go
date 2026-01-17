package logging

import (
	"fmt"
	"sync"
	"time"

	"github.com/fatih/color"
)

// LogEntry 日志条目
type LogEntry struct {
	Level    LogLevel               `json:"level"`
	Time     time.Time              `json:"time"`
	Content  string                 `json:"content"`
	Source   string                 `json:"source"`
	Metadata map[string]interface{} `json:"metadata"`
}

// LoggerConfig 日志器配置
type LoggerConfig struct {
	Level        LogLevel                 `json:"level"`
	EnableColor  bool                     `json:"enable_color"`
	SlowOutput   bool                     `json:"slow_output"`
	ShowProgress bool                     `json:"show_progress"`
	StartTime    time.Time                `json:"start_time"`
	LevelColors  map[LogLevel]interface{} `json:"-"`
}

// DefaultLoggerConfig 默认日志器配置
func DefaultLoggerConfig() *LoggerConfig {
	return &LoggerConfig{
		Level:        DefaultLevel,
		EnableColor:  DefaultEnableColor,
		SlowOutput:   DefaultSlowOutput,
		ShowProgress: DefaultShowProgress,
		StartTime:    time.Now(),
		LevelColors:  GetDefaultLevelColors(),
	}
}

// Logger 简化的日志管理器
type Logger struct {
	mu                sync.RWMutex
	config            *LoggerConfig
	startTime         time.Time
	coordinatedOutput func(string)
	initialized       bool
}

// NewLogger 创建新的日志管理器
func NewLogger(config *LoggerConfig) *Logger {
	if config == nil {
		config = DefaultLoggerConfig()
	}

	return &Logger{
		config:      config,
		startTime:   config.StartTime,
		initialized: true,
	}
}

// Initialize 初始化日志器
func (l *Logger) Initialize() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.initialized = true
}

// SetCoordinatedOutput 设置协调输出函数
func (l *Logger) SetCoordinatedOutput(outputFunc func(string)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.coordinatedOutput = outputFunc
}

// Debug 输出调试信息
func (l *Logger) Debug(msg string) {
	l.log(LevelDebug, msg)
}

// Base 输出基础信息
func (l *Logger) Base(msg string) {
	l.log(LevelBase, msg)
}

// Info 输出信息
func (l *Logger) Info(msg string) {
	l.log(LevelInfo, msg)
}

// Success 输出成功信息
func (l *Logger) Success(msg string) {
	l.log(LevelSuccess, msg)
}

// Vuln 输出漏洞/重要发现信息
func (l *Logger) Vuln(msg string) {
	l.log(LevelVuln, msg)
}

// Error 输出错误信息
func (l *Logger) Error(msg string) {
	l.log(LevelError, msg)
}

// log 内部日志处理方法
func (l *Logger) log(level LogLevel, content string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.shouldLog(level) {
		return
	}

	// 格式化消息
	timeStr := l.formatElapsedTime(time.Since(l.startTime))
	prefix := l.getLevelPrefix(level)
	logMsg := fmt.Sprintf("[%s] %s %s", timeStr, prefix, content)

	// 输出消息
	l.outputMessage(level, logMsg)

	// 根据慢速输出设置决定是否添加延迟
	if l.config.SlowOutput {
		time.Sleep(SlowOutputDelay)
	}
}

// shouldLog 检查是否应该记录该级别的日志
func (l *Logger) shouldLog(level LogLevel) bool {
	switch l.config.Level {
	case LevelAll:
		return true
	case LevelError:
		return level == LevelError
	case LevelVuln:
		return level == LevelVuln
	case LevelBase:
		return level == LevelBase
	case LevelInfo:
		return level == LevelInfo
	case LevelSuccess:
		return level == LevelSuccess
	case LevelDebug:
		return level == LevelDebug
	case LevelInfoSuccess:
		return level == LevelInfo || level == LevelSuccess || level == LevelVuln
	case LevelBaseInfoSuccess:
		return level == LevelBase || level == LevelInfo || level == LevelSuccess || level == LevelVuln
	default:
		// 向后兼容：字符串"debug"显示所有
		if string(l.config.Level) == "debug" {
			return true
		}
		return level == LevelInfo || level == LevelSuccess || level == LevelVuln
	}
}

// outputMessage 输出消息
func (l *Logger) outputMessage(level LogLevel, logMsg string) {
	if l.coordinatedOutput != nil {
		// 使用协调输出（与进度条配合）
		if l.config.EnableColor {
			if colorAttr, ok := l.config.LevelColors[level]; ok {
				if attr, ok := colorAttr.(color.Attribute); ok {
					coloredMsg := color.New(attr).Sprint(logMsg)
					l.coordinatedOutput(coloredMsg)
					return
				}
			}
		}
		l.coordinatedOutput(logMsg)
	} else {
		// 直接输出
		if l.config.EnableColor {
			if colorAttr, ok := l.config.LevelColors[level]; ok {
				if attr, ok := colorAttr.(color.Attribute); ok {
					_, _ = color.New(attr).Println(logMsg)
					return
				}
			}
		}
		fmt.Println(logMsg)
	}
}

// formatElapsedTime 格式化经过的时间
func (l *Logger) formatElapsedTime(elapsed time.Duration) string {
	switch {
	case elapsed < MaxMillisecondDisplay:
		return fmt.Sprintf("%dms", elapsed.Milliseconds())
	case elapsed < MaxSecondDisplay:
		return fmt.Sprintf("%.1fs", elapsed.Seconds())
	case elapsed < MaxMinuteDisplay:
		minutes := int(elapsed.Minutes())
		seconds := int(elapsed.Seconds()) % 60
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	default:
		hours := int(elapsed.Hours())
		minutes := int(elapsed.Minutes()) % 60
		seconds := int(elapsed.Seconds()) % 60
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	}
}

// getLevelPrefix 获取日志级别前缀
func (l *Logger) getLevelPrefix(level LogLevel) string {
	switch level {
	case LevelVuln:
		return PrefixVuln
	case LevelSuccess:
		return PrefixSuccess
	case LevelInfo:
		return PrefixInfo
	case LevelError:
		return PrefixError
	default:
		return PrefixDefault
	}
}
