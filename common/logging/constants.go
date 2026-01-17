package logging

/*
constants.go - 日志系统常量定义

统一管理common/logging包中的所有常量，便于查看和编辑。
*/

import (
	"time"

	"github.com/fatih/color"
)

// =============================================================================
// 日志级别常量 (从Types.go迁移)
// =============================================================================

// LogLevel 日志级别类型
type LogLevel string

// 定义系统支持的日志级别常量
const (
	LevelAll             LogLevel = "ALL"               // 显示所有级别日志
	LevelError           LogLevel = "ERROR"             // 仅显示错误日志
	LevelBase            LogLevel = "BASE"              // 仅显示基础信息日志
	LevelInfo            LogLevel = "INFO"              // 仅显示信息日志
	LevelSuccess         LogLevel = "SUCCESS"           // 仅显示成功日志（Web指纹等）
	LevelVuln            LogLevel = "VULN"              // 漏洞和重要发现（密码成功、漏洞等）
	LevelDebug           LogLevel = "DEBUG"             // 仅显示调试日志
	LevelInfoSuccess     LogLevel = "INFO_SUCCESS"      // 仅显示信息和成功日志
	LevelBaseInfoSuccess LogLevel = "BASE_INFO_SUCCESS" // 显示基础、信息和成功日志
)

// =============================================================================
// 时间显示常量 (从Formatter.go迁移)
// =============================================================================

const (
	// MaxMillisecondDisplay 毫秒显示的最大时长
	MaxMillisecondDisplay = time.Second
	// MaxSecondDisplay 秒显示的最大时长
	MaxSecondDisplay = time.Minute
	// MaxMinuteDisplay 分钟显示的最大时长
	MaxMinuteDisplay = time.Hour

	// SlowOutputDelay 慢速输出延迟
	SlowOutputDelay = 50 * time.Millisecond

	// ProgressClearDelay 进度条清除延迟
	ProgressClearDelay = 10 * time.Millisecond
)

// =============================================================================
// 日志前缀常量 (从Formatter.go迁移)
// =============================================================================

const (
	// PrefixSuccess 成功日志前缀
	PrefixSuccess = "[+]"
	// PrefixVuln 漏洞/重要发现前缀
	PrefixVuln = "[!]"
	// PrefixInfo 信息日志前缀
	PrefixInfo = "[*]"
	// PrefixError 错误日志前缀
	PrefixError = "[-]"
	// PrefixDefault 默认日志前缀
	PrefixDefault = "   "
)

// =============================================================================
// 默认配置常量
// =============================================================================

const (
	// DefaultLevel 默认日志级别
	DefaultLevel = LevelAll
	// DefaultEnableColor 默认启用彩色输出
	DefaultEnableColor = true
	// DefaultSlowOutput 默认不启用慢速输出
	DefaultSlowOutput = false
	// DefaultShowProgress 默认显示进度条
	DefaultShowProgress = true
)

// =============================================================================
// 默认颜色映射
// =============================================================================

// GetDefaultLevelColors 获取默认的日志级别颜色映射
func GetDefaultLevelColors() map[LogLevel]interface{} {
	return map[LogLevel]interface{}{
		LevelError:   color.FgRed,    // 错误日志显示红色
		LevelVuln:    color.FgRed,    // 漏洞/重要发现显示红色（密码成功、漏洞等）
		LevelBase:    color.FgWhite,  // 基础日志显示白色（普通信息）
		LevelInfo:    color.FgWhite,  // 信息日志显示白色（普通信息）
		LevelSuccess: color.FgGreen,  // 成功日志显示绿色（Web指纹等）
		LevelDebug:   color.FgWhite,  // 调试日志显示白色
	}
}
