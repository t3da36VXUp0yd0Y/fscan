package common

import (
	"github.com/shadow1ng/fscan/common/logging"
)

/*
parse.go - 解析相关工具函数

重构后只保留：
- RemoveDuplicate    - 字符串去重
- applyLogLevel      - 日志级别应用
- 辅助函数
*/

// RemoveDuplicate 去重函数
func RemoveDuplicate(old []string) []string {
	if len(old) <= 1 {
		return old
	}

	temp := make(map[string]struct{}, len(old))
	result := make([]string, 0, len(old))

	for _, item := range old {
		if _, exists := temp[item]; !exists {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}

// logLevelMap 日志级别字符串到级别的映射
var logLevelMap = map[string]logging.LogLevel{
	LogLevelAll:             logging.LevelAll,
	LogLevelError:           logging.LevelError,
	LogLevelBase:            logging.LevelBase,
	LogLevelInfo:            logging.LevelInfo,
	LogLevelSuccess:         logging.LevelSuccess,
	LogLevelDebug:           logging.LevelDebug,
	LogLevelInfoSuccess:     logging.LevelInfoSuccess,
	LogLevelBaseInfoSuccess: logging.LevelBaseInfoSuccess,
	// 旧格式（大写，向后兼容）
	"ALL":     logging.LevelAll,
	"ERROR":   logging.LevelError,
	"BASE":    logging.LevelBase,
	"INFO":    logging.LevelInfo,
	"SUCCESS": logging.LevelSuccess,
	"DEBUG":   logging.LevelDebug,
}

// applyLogLevel 应用LogLevel配置到日志系统
func applyLogLevel() {
	fv := GetFlagVars()
	logLevel := fv.LogLevel
	if logLevel == "" {
		return
	}

	level, ok := logLevelMap[logLevel]
	if !ok {
		return
	}

	if globalLogger != nil {
		config := &logging.LoggerConfig{
			Level:        level,
			EnableColor:  !fv.NoColor,
			SlowOutput:   false,
			ShowProgress: !fv.DisableProgress,
			StartTime:    GetGlobalState().GetStartTime(),
			LevelColors:  logging.GetDefaultLevelColors(),
		}

		newLogger := logging.NewLogger(config)
		newLogger.SetCoordinatedOutput(LogWithProgress)
		globalLogger = newLogger
	}
}
