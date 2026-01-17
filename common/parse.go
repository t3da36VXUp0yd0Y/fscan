package common

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/common/logging"
	"github.com/shadow1ng/fscan/common/parsers"
)

// ParsedConfiguration 解析后的完整配置（兼容旧代码）
type ParsedConfiguration struct {
	*parsers.ParsedConfig
}

// Parser 主解析器
type Parser struct {
	mu               sync.RWMutex
	fileReader       *parsers.FileReader
	credentialParser *parsers.CredentialParser
	targetParser     *parsers.TargetParser
	networkParser    *parsers.NetworkParser
	validationParser *parsers.ValidationParser
	options          *parsers.ParserOptions
	initialized      bool
}

// NewParser 创建新的解析器实例
func NewParser(options *parsers.ParserOptions) *Parser {
	if options == nil {
		options = parsers.DefaultParserOptions()
	}

	// 创建文件读取器
	fileReader := parsers.NewFileReader(nil)

	// 创建各个子解析器
	credentialParser := parsers.NewCredentialParser(fileReader, nil)
	targetParser := parsers.NewTargetParser(fileReader, nil)
	networkParser := parsers.NewNetworkParser(nil)
	validationParser := parsers.NewValidationParser(nil)

	return &Parser{
		fileReader:       fileReader,
		credentialParser: credentialParser,
		targetParser:     targetParser,
		networkParser:    networkParser,
		validationParser: validationParser,
		options:          options,
		initialized:      true,
	}
}

// 全局解析器实例
var globalParser *Parser
var parseOnce sync.Once

// getGlobalParser 获取全局解析器实例
func getGlobalParser() *Parser {
	parseOnce.Do(func() {
		globalParser = NewParser(nil)
	})
	return globalParser
}

// Parse 主解析函数 - 保持与原版本兼容的接口
func Parse(Info *HostInfo) error {
	// 首先应用LogLevel配置到日志系统
	applyLogLevel()

	parser := getGlobalParser()
	fv := GetFlagVars() // 从 FlagVars 获取命令行参数

	// 检查是否为host:port格式，如果是则清空端口字段避免双重扫描
	ports := fv.Ports
	if Info.Host != "" && strings.Contains(Info.Host, ":") {
		if _, portStr, err := net.SplitHostPort(Info.Host); err == nil {
			if port, portErr := strconv.Atoi(portStr); portErr == nil && port >= 1 && port <= 65535 {
				// 这是有效的host:port格式，清空端口字段
				ports = ""
				fv.Ports = "" // 更新 FlagVars，避免插件适用性检查使用默认端口
			}
		}
	}

	// 构建输入参数（从 FlagVars 读取）
	input := &AllInputs{
		Credential: &parsers.CredentialInput{
			Username:      fv.Username,
			Password:      fv.Password,
			AddUsers:      fv.AddUsers,
			AddPasswords:  fv.AddPasswords,
			HashValue:     fv.HashValue,
			SSHKeyPath:    fv.SSHKeyPath,
			Domain:        fv.Domain,
			UsersFile:     fv.UsersFile,
			PasswordsFile: fv.PasswordsFile,
			UserPassFile:  fv.UserPassFile,
			HashFile:      fv.HashFile,
		},
		Target: &parsers.TargetInput{
			Host:             Info.Host,
			HostsFile:        fv.HostsFile,
			ExcludeHosts:     fv.ExcludeHosts,
			ExcludeHostsFile: fv.ExcludeHostsFile,
			Ports:            ports,
			PortsFile:        fv.PortsFile,
			AddPorts:         fv.AddPorts,
			ExcludePorts:     fv.ExcludePorts,
			TargetURL:        fv.TargetURL,
			URLsFile:         fv.URLsFile,
			HostPort:         nil, // 由解析器填充
			LocalMode:        fv.LocalPlugin != "",
		},
		Network: &parsers.NetworkInput{
			HTTPProxy:   fv.HTTPProxy,
			Socks5Proxy: fv.Socks5Proxy,
			Timeout:     fv.TimeoutSec,
			WebTimeout:  fv.WebTimeout,
			DisablePing: fv.DisablePing,
			DNSLog:      fv.DNSLog,
			UserAgent:   fv.UserAgent,
			Cookie:      fv.Cookie,
		},
	}

	// 执行解析
	result, err := parser.ParseAll(input)
	if err != nil {
		return fmt.Errorf("配置解析失败: %w", err)
	}

	// 检查解析结果中的错误（关键修复：防止静默失败）
	if !result.Success || len(result.Errors) > 0 {
		LogError("配置解析失败，发现以下错误：")
		for i, parseErr := range result.Errors {
			LogError(fmt.Sprintf("  [%d] %v", i+1, parseErr))
		}
		return fmt.Errorf("配置解析失败，共%d个错误", len(result.Errors))
	}

	// 更新全局变量以保持兼容性
	if err := updateGlobalVariables(result.Config, Info); err != nil {
		return fmt.Errorf("更新全局变量失败: %w", err)
	}

	// 报告警告
	for _, warning := range result.Warnings {
		LogBase(warning)
	}

	// 显示解析结果摘要
	showParseSummary(result.Config)

	return nil
}

// AllInputs 所有输入参数的集合
type AllInputs struct {
	Credential *parsers.CredentialInput `json:"credential"`
	Target     *parsers.TargetInput     `json:"target"`
	Network    *parsers.NetworkInput    `json:"network"`
}

// ParseAll 解析所有配置
func (p *Parser) ParseAll(input *AllInputs) (*parsers.ParseResult, error) {
	if input == nil {
		return nil, errors.New(i18n.GetText("parse_error_empty_input"))
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.initialized {
		return nil, errors.New(i18n.GetText("parse_error_parser_not_init"))
	}

	startTime := time.Now()
	result := &parsers.ParseResult{
		Config:  &parsers.ParsedConfig{},
		Success: true,
	}

	var allErrors []error
	var allWarnings []string

	// 解析凭据配置
	if input.Credential != nil {
		credResult, err := p.credentialParser.Parse(input.Credential, p.options)
		if err != nil {
			allErrors = append(allErrors, fmt.Errorf("凭据解析失败: %w", err))
		} else {
			result.Config.Credentials = credResult.Config.Credentials
			allErrors = append(allErrors, credResult.Errors...)
			allWarnings = append(allWarnings, credResult.Warnings...)
		}
	}

	// 解析目标配置
	if input.Target != nil {
		targetResult, err := p.targetParser.Parse(input.Target, p.options)
		if err != nil {
			allErrors = append(allErrors, fmt.Errorf("目标解析失败: %w", err))
		} else {
			result.Config.Targets = targetResult.Config.Targets
			allErrors = append(allErrors, targetResult.Errors...)
			allWarnings = append(allWarnings, targetResult.Warnings...)
		}
	}

	// 解析网络配置
	if input.Network != nil {
		networkResult, err := p.networkParser.Parse(input.Network, p.options)
		if err != nil {
			allErrors = append(allErrors, fmt.Errorf("网络配置解析失败: %w", err))
		} else {
			result.Config.Network = networkResult.Config.Network
			allErrors = append(allErrors, networkResult.Errors...)
			allWarnings = append(allWarnings, networkResult.Warnings...)
		}
	}

	// 执行验证
	fv := GetFlagVars()
	validationInput := &parsers.ValidationInput{
		ScanMode:       fv.ScanMode,
		LocalMode:      fv.LocalPlugin != "",
		HasHosts:       input.Target != nil && (input.Target.Host != "" || input.Target.HostsFile != ""),
		HasURLs:        input.Target != nil && (input.Target.TargetURL != "" || input.Target.URLsFile != ""),
		HasPorts:       input.Target != nil && (input.Target.Ports != "" || input.Target.PortsFile != ""),
		HasProxy:       input.Network != nil && (input.Network.HTTPProxy != "" || input.Network.Socks5Proxy != ""),
		DisablePing:    input.Network != nil && input.Network.DisablePing,
		HasCredentials: input.Credential != nil && (input.Credential.Username != "" || input.Credential.UsersFile != ""),
	}

	validationResult, err := p.validationParser.Parse(validationInput, result.Config, p.options)
	if err != nil {
		allErrors = append(allErrors, fmt.Errorf("参数验证失败: %w", err))
	} else {
		result.Config.Validation = validationResult.Config.Validation
		allErrors = append(allErrors, validationResult.Errors...)
		allWarnings = append(allWarnings, validationResult.Warnings...)
	}

	// 汇总结果
	result.Errors = allErrors
	result.Warnings = allWarnings
	result.ParseTime = time.Since(startTime)
	result.Success = len(allErrors) == 0

	return result, nil
}

// updateGlobalVariables 更新运行时数据和FlagVars以保持向后兼容性
func updateGlobalVariables(config *parsers.ParsedConfig, info *HostInfo) error {
	if config == nil {
		return nil
	}

	fv := GetFlagVars()

	// 更新全局Config的凭据数据
	globalCfg := GetGlobalConfig()
	if config.Credentials != nil {
		if len(config.Credentials.Usernames) > 0 {
			// 更新全局Config中的用户字典
			for serviceName := range globalCfg.Credentials.Userdict {
				globalCfg.Credentials.Userdict[serviceName] = config.Credentials.Usernames
			}
		}

		if len(config.Credentials.Passwords) > 0 {
			globalCfg.Credentials.Passwords = config.Credentials.Passwords
		}

		if len(config.Credentials.UserPassPairs) > 0 {
			globalCfg.Credentials.UserPassPairs = config.Credentials.UserPassPairs
		}

		if len(config.Credentials.HashValues) > 0 {
			globalCfg.Credentials.HashValues = config.Credentials.HashValues
		}

		if len(config.Credentials.HashBytes) > 0 {
			globalCfg.Credentials.HashBytes = config.Credentials.HashBytes
		}
	}

	// 更新目标相关数据
	if config.Targets != nil {
		state := GetGlobalState()

		if len(config.Targets.Hosts) > 0 {
			// 如果info.Host已经有值，说明解析结果来自info.Host，不需要重复设置
			// 只有当info.Host为空时才设置（如从文件读取的情况）
			if info.Host == "" {
				info.Host = joinStrings(config.Targets.Hosts, ",")
			}
		}

		if len(config.Targets.URLs) > 0 {
			state.SetURLs(config.Targets.URLs)
			// 如果info.Url为空且只有一个URL，将其设置到info.URL
			if info.URL == "" && len(config.Targets.URLs) == 1 {
				info.URL = config.Targets.URLs[0]
			}
		}

		if len(config.Targets.Ports) > 0 {
			fv.Ports = joinInts(config.Targets.Ports, ",")
		}

		if len(config.Targets.ExcludePorts) > 0 {
			fv.ExcludePorts = joinInts(config.Targets.ExcludePorts, ",")
		}

		if len(config.Targets.HostPorts) > 0 {
			state.SetHostPorts(config.Targets.HostPorts)
		}
	}

	// 更新网络相关FlagVars
	if config.Network != nil {
		if config.Network.HTTPProxy != "" {
			fv.HTTPProxy = config.Network.HTTPProxy
		}

		if config.Network.Socks5Proxy != "" {
			fv.Socks5Proxy = config.Network.Socks5Proxy
		}

		if config.Network.Timeout > 0 {
			fv.TimeoutSec = int64(config.Network.Timeout.Seconds())
		}

		if config.Network.WebTimeout > 0 {
			fv.WebTimeout = int64(config.Network.WebTimeout.Seconds())
		}

		if config.Network.UserAgent != "" {
			fv.UserAgent = config.Network.UserAgent
		}

		if config.Network.Cookie != "" {
			fv.Cookie = config.Network.Cookie
		}

		fv.DisablePing = config.Network.DisablePing
		fv.DNSLog = config.Network.EnableDNSLog
	}

	return nil
}

// RemoveDuplicate 去重函数 - 恢复原始高效实现
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

// 辅助函数

// joinStrings 连接字符串切片
func joinStrings(slice []string, sep string) string {
	return strings.Join(slice, sep)
}

// joinInts 连接整数切片
func joinInts(slice []int, sep string) string {
	if len(slice) == 0 {
		return ""
	}
	strs := make([]string, len(slice))
	for i, v := range slice {
		strs[i] = strconv.Itoa(v)
	}
	return strings.Join(strs, sep)
}

// showParseSummary 显示解析结果摘要（已精简，不再输出冗余信息）
func showParseSummary(config *parsers.ParsedConfig) {
	// 不再输出开局配置信息，减少干扰
}

// logLevelMap 日志级别字符串到级别的映射（支持新旧格式）
var logLevelMap = map[string]logging.LogLevel{
	// 新格式（小写）
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
		return // 使用默认级别
	}

	// 查找日志级别
	level, ok := logLevelMap[logLevel]
	if !ok {
		return // 无效的级别，保持默认
	}

	// 更新全局日志管理器的级别
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

		// 设置协调输出函数，使用LogWithProgress
		newLogger.SetCoordinatedOutput(LogWithProgress)

		// 更新全局日志管理器
		globalLogger = newLogger
		// status变量已移除，如需获取状态请直接调用newLogger.GetScanStatus()
	}
}
