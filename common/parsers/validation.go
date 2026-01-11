package parsers

import (
	"fmt"
	"sync"
	"time"
)

// ValidationParser 参数验证解析器
type ValidationParser struct {
	mu      sync.RWMutex //nolint:unused // reserved for future thread safety
	options *ValidationParserOptions
}

// ValidationParserOptions 验证解析器选项
type ValidationParserOptions struct {
	StrictMode      bool `json:"strict_mode"`      // 严格模式
	AllowEmpty      bool `json:"allow_empty"`      // 允许空配置
	CheckConflicts  bool `json:"check_conflicts"`  // 检查参数冲突
	ValidateTargets bool `json:"validate_targets"` // 验证目标有效性
	ValidateNetwork bool `json:"validate_network"` // 验证网络配置
	MaxErrorCount   int  `json:"max_error_count"`  // 最大错误数量
}

// DefaultValidationParserOptions 默认验证解析器选项
func DefaultValidationParserOptions() *ValidationParserOptions {
	return &ValidationParserOptions{
		StrictMode:      DefaultStrictMode,
		AllowEmpty:      DefaultAllowEmpty,
		CheckConflicts:  DefaultCheckConflicts,
		ValidateTargets: DefaultValidateTargets,
		ValidateNetwork: DefaultValidateNetwork,
		MaxErrorCount:   DefaultMaxErrorCount,
	}
}

// NewValidationParser 创建验证解析器
func NewValidationParser(options *ValidationParserOptions) *ValidationParser {
	if options == nil {
		options = DefaultValidationParserOptions()
	}

	return &ValidationParser{
		options: options,
	}
}

// ValidationInput 验证输入参数
type ValidationInput struct {
	// 扫描模式
	ScanMode  string `json:"scan_mode"`
	LocalMode bool   `json:"local_mode"`

	// 目标配置
	HasHosts bool `json:"has_hosts"`
	HasURLs  bool `json:"has_urls"`
	HasPorts bool `json:"has_ports"`

	// 网络配置
	HasProxy    bool `json:"has_proxy"`
	DisablePing bool `json:"disable_ping"`

	// 凭据配置
	HasCredentials bool `json:"has_credentials"`

	// 特殊模式
	PocScan   bool `json:"poc_scan"`
	BruteScan bool `json:"brute_scan"`
	LocalScan bool `json:"local_scan"`
}

// ConflictRule 冲突规则
type ConflictRule struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Fields      []string `json:"fields"`
	Severity    string   `json:"severity"` // error, warning, info
}

// ValidationRule 验证规则
type ValidationRule struct {
	Name        string                             `json:"name"`
	Description string                             `json:"description"`
	Validator   func(input *ValidationInput) error `json:"-"`
	Severity    string                             `json:"severity"`
}

// Parse 执行参数验证
func (vp *ValidationParser) Parse(input *ValidationInput, config *ParsedConfig, options *ParserOptions) (*ParseResult, error) {
	if input == nil {
		return nil, NewParseError(ErrorTypeInputError, "验证输入为空", "", 0, ErrEmptyInput)
	}

	startTime := time.Now()
	result := &ParseResult{
		Config: &ParsedConfig{
			Validation: &ValidationConfig{
				ScanMode:        input.ScanMode,
				ConflictChecked: true,
			},
		},
		Success: true,
	}

	var errors []error
	var warnings []string

	// 基础验证
	basicErrors, basicWarnings := vp.validateBasic(input)
	errors = append(errors, basicErrors...)
	warnings = append(warnings, basicWarnings...)

	// 冲突检查
	if vp.options.CheckConflicts {
		conflictErrors, conflictWarnings := vp.checkConflicts(input)
		errors = append(errors, conflictErrors...)
		warnings = append(warnings, conflictWarnings...)
	}

	// 逻辑验证
	logicErrors, logicWarnings := vp.validateLogic(input, config)
	errors = append(errors, logicErrors...)
	warnings = append(warnings, logicWarnings...)

	// 性能建议
	performanceWarnings := vp.checkPerformance(input, config)
	warnings = append(warnings, performanceWarnings...)

	// 检查错误数量限制
	if len(errors) > vp.options.MaxErrorCount {
		errors = errors[:vp.options.MaxErrorCount]
		warnings = append(warnings, fmt.Sprintf("错误数量过多，仅显示前%d个", vp.options.MaxErrorCount))
	}

	// 更新结果
	result.Config.Validation.Errors = errors
	result.Config.Validation.Warnings = warnings
	result.Errors = errors
	result.Warnings = warnings
	result.ParseTime = time.Since(startTime)
	result.Success = len(errors) == 0

	return result, nil
}

// validateBasic 基础验证
func (vp *ValidationParser) validateBasic(input *ValidationInput) ([]error, []string) {
	var errors []error
	var warnings []string

	// 检查是否有任何目标
	if !input.HasHosts && !input.HasURLs && !input.LocalMode {
		if !vp.options.AllowEmpty {
			errors = append(errors, NewParseError("VALIDATION_ERROR", "未指定任何扫描目标", "basic", 0, nil))
		} else {
			warnings = append(warnings, "未指定扫描目标，将使用默认配置")
		}
	}

	// 检查扫描模式
	if input.ScanMode != "" {
		if err := vp.validateScanMode(input.ScanMode); err != nil {
			if vp.options.StrictMode {
				errors = append(errors, err)
			} else {
				warnings = append(warnings, err.Error())
			}
		}
	}

	return errors, warnings
}

// checkConflicts 检查参数冲突
func (vp *ValidationParser) checkConflicts(input *ValidationInput) ([]error, []string) {
	var errors []error
	var warnings []string

	// 定义冲突规则 (预留用于扩展)
	_ = []ConflictRule{
		{
			Name:        "multiple_scan_modes",
			Description: "不能同时使用多种扫描模式",
			Fields:      []string{"hosts", "urls", "local_mode"},
			Severity:    "error",
		},
		{
			Name:        "proxy_with_ping",
			Description: "使用代理时建议禁用Ping检测",
			Fields:      []string{"proxy", "ping"},
			Severity:    "warning",
		},
	}

	// 检查扫描模式冲突
	scanModes := 0
	if input.HasHosts {
		scanModes++
	}
	if input.HasURLs {
		scanModes++
	}
	if input.LocalMode {
		scanModes++
	}

	if scanModes > 1 {
		errors = append(errors, NewParseError("CONFLICT_ERROR",
			"不能同时指定多种扫描模式(主机扫描、URL扫描、本地模式)", "validation", 0, nil))
	}

	// 检查代理和Ping冲突
	if input.HasProxy && !input.DisablePing {
		warnings = append(warnings, "代理模式下Ping检测可能失效")
	}

	return errors, warnings
}

// validateLogic 逻辑验证
func (vp *ValidationParser) validateLogic(input *ValidationInput, config *ParsedConfig) ([]error, []string) {
	var errors []error
	var warnings []string

	// 验证目标配置逻辑
	if vp.options.ValidateTargets && config != nil && config.Targets != nil {
		// 检查排除端口配置
		if len(config.Targets.ExcludePorts) > 0 && len(config.Targets.Ports) == 0 {
			warnings = append(warnings, "排除端口无效")
		}
	}

	return errors, warnings
}

// checkPerformance 性能检查
func (vp *ValidationParser) checkPerformance(input *ValidationInput, config *ParsedConfig) []string {
	var warnings []string

	if config == nil {
		return warnings
	}

	// 检查目标数量
	if config.Targets != nil {
		totalTargets := len(config.Targets.Hosts) * len(config.Targets.Ports)
		if totalTargets > MaxTargetsThreshold {
			warnings = append(warnings, fmt.Sprintf("大量目标(%d)，可能耗时较长", totalTargets))
		}

		// 检查端口范围
		if len(config.Targets.Ports) > PortCountWarningThreshold {
			warnings = append(warnings, "端口数量过多")
		}
	}

	// 检查超时配置
	if config.Network != nil {
		if config.Network.Timeout < MinTimeoutThreshold {
			warnings = append(warnings, "超时过短")
		}
		if config.Network.Timeout > MaxTimeoutThreshold {
			warnings = append(warnings, "超时过长")
		}
	}

	return warnings
}

// validateScanMode 验证扫描模式
func (vp *ValidationParser) validateScanMode(scanMode string) error { //nolint:unparam
	validModes := []string{"all", "icmp"}

	// 检查是否为预定义模式
	for _, mode := range validModes {
		if scanMode == mode {
			return nil
		}
	}

	// 允许插件名称作为扫描模式，实际插件验证在运行时进行
	// 这里不做严格验证，避免维护两套插件列表
	return nil
}

// =============================================================================================
// 已删除的死代码（未使用）：Validate 和 GetStatistics 方法
// =============================================================================================
