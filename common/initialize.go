package common

import (
	"fmt"
)

/*
initialize.go - 统一初始化入口

将分散的初始化步骤整合为单一入口，简化 main.go。
*/

// InitResult 初始化结果
type InitResult struct {
	Config *Config
	State  *State
	Info   *HostInfo
}

// Initialize 统一初始化函数
// 封装 Parse → InitGlobalConfigAndState → InitOutput 流程
// 返回可直接使用的 Config 和 State 对象
func Initialize(info *HostInfo) (*InitResult, error) {
	// 初始化日志系统
	InitLogger()

	// 解析和验证参数（会更新 globalConfig 的凭据信息）
	if err := Parse(info); err != nil {
		return nil, fmt.Errorf("参数解析失败: %w", err)
	}

	// 获取 Parse 更新过的凭据信息
	parsedCreds := GetGlobalConfig().Credentials

	// 从 FlagVars 构建 Config（新架构）
	cfg := BuildConfigFromFlags(flagVars)
	state := NewState()

	// 关键修复：应用 Parse 解析的凭据结果到新 Config
	// Parse 会根据 -user/-pwd/-usera/-pwda 等参数更新凭据
	if len(parsedCreds.UserPassPairs) > 0 {
		cfg.Credentials.UserPassPairs = parsedCreds.UserPassPairs
	}
	if len(parsedCreds.Userdict) > 0 {
		cfg.Credentials.Userdict = parsedCreds.Userdict
	}
	if len(parsedCreds.Passwords) > 0 {
		cfg.Credentials.Passwords = parsedCreds.Passwords
	}
	if len(parsedCreds.HashValues) > 0 {
		cfg.Credentials.HashValues = parsedCreds.HashValues
	}
	if len(parsedCreds.HashBytes) > 0 {
		cfg.Credentials.HashBytes = parsedCreds.HashBytes
	}

	// 设置全局实例
	SetGlobalConfig(cfg)
	SetGlobalState(state)

	// 初始化输出系统
	if err := InitOutput(); err != nil {
		return nil, fmt.Errorf("输出初始化失败: %w", err)
	}

	return &InitResult{
		Config: cfg,
		State:  state,
		Info:   info,
	}, nil
}

// ValidateExclusiveParams 验证互斥参数
// 检查 -h、-u、-local 只能指定一个
func ValidateExclusiveParams(info *HostInfo) error {
	paramCount := 0
	var activeParam string

	fv := GetFlagVars()

	if info.Host != "" {
		paramCount++
		activeParam = "-h"
	}
	if fv.TargetURL != "" {
		paramCount++
		if activeParam != "" {
			activeParam += " 和 -u"
		} else {
			activeParam = "-u"
		}
	}
	if fv.LocalPlugin != "" {
		paramCount++
		if activeParam != "" {
			activeParam += " 和 -local"
		} else {
			activeParam = "-local"
		}
	}

	if paramCount > 1 {
		return fmt.Errorf("参数 %s 互斥，请只指定一个扫描目标\n  -h: 网络主机扫描\n  -u: Web URL扫描\n  -local: 本地信息收集", activeParam)
	}

	return nil
}

// Cleanup 清理资源
// 应该在程序退出前调用
func Cleanup() error {
	return CloseOutput()
}
