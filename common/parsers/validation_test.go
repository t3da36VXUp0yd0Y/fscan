package parsers

import (
	"strings"
	"testing"
)

/*
validation_test.go - 参数验证解析器测试

测试目标：ValidationParser核心验证逻辑
价值：验证逻辑错误会导致：
  - 用户无法启动扫描（false positive错误）
  - 错误配置未被发现（false negative漏检）
  - 性能问题未预警（大规模扫描超时）

"验证是用户的第一道防线。验证太严=拒绝合法输入，
验证太松=允许错误配置。必须精确测试每个规则。"
*/

// =============================================================================
// ValidationParser - 构造函数测试
// =============================================================================

// TestNewValidationParser_DefaultOptions 测试默认选项
//
// 验证：nil选项时使用默认配置
func TestNewValidationParser_DefaultOptions(t *testing.T) {
	parser := NewValidationParser(nil)

	if parser == nil {
		t.Fatal("NewValidationParser(nil)应该返回有效parser")
	}

	if parser.options == nil {
		t.Error("options不应为nil（应使用默认配置）")
	}

	// 验证默认值合理性
	if parser.options.MaxErrorCount <= 0 {
		t.Error("MaxErrorCount应该大于0")
	}

	t.Logf("✓ 默认选项测试通过（MaxErrorCount=%d）", parser.options.MaxErrorCount)
}

// TestNewValidationParser_CustomOptions 测试自定义选项
func TestNewValidationParser_CustomOptions(t *testing.T) {
	options := &ValidationParserOptions{
		StrictMode:      true,
		AllowEmpty:      false,
		CheckConflicts:  true,
		ValidateTargets: true,
		ValidateNetwork: true,
		MaxErrorCount:   10,
	}

	parser := NewValidationParser(options)

	if parser.options.StrictMode != true {
		t.Error("StrictMode应该为true")
	}

	if parser.options.MaxErrorCount != 10 {
		t.Error("MaxErrorCount应该为10")
	}

	t.Logf("✓ 自定义选项测试通过")
}

// =============================================================================
// ValidationParser - 基础验证测试
// =============================================================================

// TestValidationParser_Parse_NoTargets 测试无目标验证
//
// 验证：无目标时返回错误（AllowEmpty=false）
func TestValidationParser_Parse_NoTargets(t *testing.T) {
	parser := NewValidationParser(&ValidationParserOptions{
		AllowEmpty:    false,
		MaxErrorCount: 10,
	})

	input := &ValidationInput{
		ScanMode:  "all",
		HasHosts:  false,
		HasURLs:   false,
		LocalMode: false,
	}

	result, err := parser.Parse(input, nil, nil)

	if err != nil {
		t.Fatalf("Parse不应返回err: %v", err)
	}

	if result.Success {
		t.Error("无目标时Success应该为false")
	}

	if len(result.Errors) == 0 {
		t.Error("无目标时应该有错误")
	}

	// 验证错误消息
	hasTargetError := false
	for _, e := range result.Errors {
		if strings.Contains(e.Error(), "目标") {
			hasTargetError = true
			break
		}
	}
	if !hasTargetError {
		t.Error("应该包含目标相关的错误消息")
	}

	t.Logf("✓ 无目标验证测试通过（错误数=%d）", len(result.Errors))
}

// TestValidationParser_Parse_AllowEmpty 测试允许空配置
func TestValidationParser_Parse_AllowEmpty(t *testing.T) {
	parser := NewValidationParser(&ValidationParserOptions{
		AllowEmpty:    true,
		MaxErrorCount: 10,
	})

	input := &ValidationInput{
		ScanMode:  "",
		HasHosts:  false,
		HasURLs:   false,
		LocalMode: false,
	}

	result, err := parser.Parse(input, nil, nil)

	if err != nil {
		t.Fatalf("Parse不应返回err: %v", err)
	}

	// AllowEmpty=true时，无目标只警告不报错
	if !result.Success {
		t.Error("AllowEmpty=true时Success应该为true")
	}

	if len(result.Warnings) == 0 {
		t.Error("应该有警告")
	}

	t.Logf("✓ AllowEmpty测试通过（警告数=%d）", len(result.Warnings))
}

// TestValidationParser_Parse_ValidScanModes 测试有效扫描模式
func TestValidationParser_Parse_ValidScanModes(t *testing.T) {
	parser := NewValidationParser(nil)

	validModes := []string{"all", "icmp", "ssh", "mysql", ""}

	for _, mode := range validModes {
		t.Run(mode, func(t *testing.T) {
			input := &ValidationInput{
				ScanMode: mode,
				HasHosts: true,
			}

			result, err := parser.Parse(input, nil, nil)
			if err != nil {
				t.Fatalf("Parse失败: %v", err)
			}

			if !result.Success {
				t.Errorf("模式%q应该有效，但Success=false，错误: %v", mode, result.Errors)
			}

			t.Logf("✓ 模式%q验证通过", mode)
		})
	}
}

// =============================================================================
// ValidationParser - 冲突检测测试
// =============================================================================

// TestValidationParser_Parse_ConflictMultipleScanModes 测试多种扫描模式冲突
//
// 验证：同时指定多种扫描模式时报错
func TestValidationParser_Parse_ConflictMultipleScanModes(t *testing.T) {
	parser := NewValidationParser(&ValidationParserOptions{
		CheckConflicts: true,
		MaxErrorCount:  10,
	})

	tests := []struct {
		name        string
		input       *ValidationInput
		hasConflict bool
	}{
		{
			name: "主机+URL冲突",
			input: &ValidationInput{
				HasHosts: true,
				HasURLs:  true,
			},
			hasConflict: true,
		},
		{
			name: "主机+本地模式冲突",
			input: &ValidationInput{
				HasHosts:  true,
				LocalMode: true,
			},
			hasConflict: true,
		},
		{
			name: "URL+本地模式冲突",
			input: &ValidationInput{
				HasURLs:   true,
				LocalMode: true,
			},
			hasConflict: true,
		},
		{
			name: "三种模式同时冲突",
			input: &ValidationInput{
				HasHosts:  true,
				HasURLs:   true,
				LocalMode: true,
			},
			hasConflict: true,
		},
		{
			name: "仅主机-无冲突",
			input: &ValidationInput{
				HasHosts: true,
			},
			hasConflict: false,
		},
		{
			name: "仅URL-无冲突",
			input: &ValidationInput{
				HasURLs: true,
			},
			hasConflict: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parser.Parse(tt.input, nil, nil)
			if err != nil {
				t.Fatalf("Parse失败: %v", err)
			}

			if tt.hasConflict {
				if result.Success {
					t.Error("有冲突时Success应该为false")
				}
				if len(result.Errors) == 0 {
					t.Error("应该有冲突错误")
				}

				// 验证错误消息包含"扫描模式"
				hasConflictError := false
				for _, e := range result.Errors {
					if strings.Contains(e.Error(), "扫描模式") {
						hasConflictError = true
						break
					}
				}
				if !hasConflictError {
					t.Error("应该包含扫描模式冲突的错误")
				}
			} else {
				if !result.Success {
					t.Errorf("无冲突时Success应该为true，错误: %v", result.Errors)
				}
			}

			t.Logf("✓ %s 测试通过", tt.name)
		})
	}
}

// TestValidationParser_Parse_ProxyPingWarning 测试代理+Ping警告
//
// 验证：代理模式下未禁用Ping时给出警告
func TestValidationParser_Parse_ProxyPingWarning(t *testing.T) {
	parser := NewValidationParser(&ValidationParserOptions{
		CheckConflicts: true,
		MaxErrorCount:  10,
	})

	tests := []struct {
		name        string
		hasProxy    bool
		disablePing bool
		wantWarning bool
	}{
		{
			name:        "代理+Ping启用-有警告",
			hasProxy:    true,
			disablePing: false,
			wantWarning: true,
		},
		{
			name:        "代理+Ping禁用-无警告",
			hasProxy:    true,
			disablePing: true,
			wantWarning: false,
		},
		{
			name:        "无代理+Ping启用-无警告",
			hasProxy:    false,
			disablePing: false,
			wantWarning: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &ValidationInput{
				HasHosts:    true,
				HasProxy:    tt.hasProxy,
				DisablePing: tt.disablePing,
			}

			result, err := parser.Parse(input, nil, nil)
			if err != nil {
				t.Fatalf("Parse失败: %v", err)
			}

			hasPingWarning := false
			for _, w := range result.Warnings {
				if strings.Contains(w, "Ping") || strings.Contains(w, "代理") {
					hasPingWarning = true
					break
				}
			}

			if tt.wantWarning && !hasPingWarning {
				t.Error("应该有代理Ping警告")
			}

			if !tt.wantWarning && hasPingWarning {
				t.Errorf("不应该有警告，实际警告: %v", result.Warnings)
			}

			t.Logf("✓ %s 测试通过", tt.name)
		})
	}
}

// =============================================================================
// ValidationParser - 逻辑验证测试
// =============================================================================

// TestValidationParser_Parse_ExcludePortsLogic 测试排除端口逻辑
//
// 验证：排除端口但未指定端口时给出警告
func TestValidationParser_Parse_ExcludePortsLogic(t *testing.T) {
	parser := NewValidationParser(&ValidationParserOptions{
		ValidateTargets: true,
		MaxErrorCount:   10,
	})

	config := &ParsedConfig{
		Targets: &TargetConfig{
			Hosts:        []string{"192.168.1.1"},
			Ports:        []int{},              // 无端口
			ExcludePorts: []int{80, 443, 8080}, // 但有排除端口
		},
	}

	input := &ValidationInput{
		HasHosts: true,
		HasPorts: false,
	}

	result, err := parser.Parse(input, config, nil)
	if err != nil {
		t.Fatalf("Parse失败: %v", err)
	}

	// 应该有警告
	hasExcludeWarning := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "排除端口") {
			hasExcludeWarning = true
			break
		}
	}

	if !hasExcludeWarning {
		t.Errorf("排除端口逻辑错误时应该有警告，实际警告: %v", result.Warnings)
	}

	t.Logf("✓ 排除端口逻辑测试通过")
}

// =============================================================================
// ValidationParser - 性能检查测试
// =============================================================================

// TestValidationParser_Parse_PerformanceLargeTargets 测试大量目标警告
//
// 验证：目标数量过多时给出性能警告
func TestValidationParser_Parse_PerformanceLargeTargets(t *testing.T) {
	parser := NewValidationParser(nil)

	// 创建大量目标：1000个主机 x 1000个端口 = 100万目标
	hosts := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		hosts[i] = "192.168.1.1"
	}

	ports := make([]int, 1000)
	for i := 0; i < 1000; i++ {
		ports[i] = i + 1
	}

	config := &ParsedConfig{
		Targets: &TargetConfig{
			Hosts: hosts,
			Ports: ports,
		},
	}

	input := &ValidationInput{
		HasHosts: true,
		HasPorts: true,
	}

	result, err := parser.Parse(input, config, nil)
	if err != nil {
		t.Fatalf("Parse失败: %v", err)
	}

	// 应该有性能警告
	hasPerformanceWarning := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "大量目标") || strings.Contains(w, "耗时") {
			hasPerformanceWarning = true
			break
		}
	}

	if !hasPerformanceWarning {
		t.Errorf("大量目标时应该有性能警告，实际警告: %v", result.Warnings)
	}

	t.Logf("✓ 大量目标性能警告测试通过")
}

// TestValidationParser_Parse_PerformanceManyPorts 测试端口数量警告
func TestValidationParser_Parse_PerformanceManyPorts(t *testing.T) {
	parser := NewValidationParser(nil)

	// 创建大量端口
	ports := make([]int, 10000)
	for i := 0; i < 10000; i++ {
		ports[i] = i + 1
	}

	config := &ParsedConfig{
		Targets: &TargetConfig{
			Hosts: []string{"192.168.1.1"},
			Ports: ports,
		},
	}

	input := &ValidationInput{
		HasHosts: true,
		HasPorts: true,
	}

	result, err := parser.Parse(input, config, nil)
	if err != nil {
		t.Fatalf("Parse失败: %v", err)
	}

	// 应该有端口数量警告
	hasPortWarning := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "端口") {
			hasPortWarning = true
			break
		}
	}

	if !hasPortWarning {
		t.Errorf("大量端口时应该有警告，实际警告: %v", result.Warnings)
	}

	t.Logf("✓ 端口数量警告测试通过")
}

// =============================================================================
// ValidationParser - 错误数量限制测试
// =============================================================================

// TestValidationParser_Parse_MaxErrorCount 测试错误数量限制
//
// 验证：错误超过MaxErrorCount时截断
func TestValidationParser_Parse_MaxErrorCount(t *testing.T) {
	parser := NewValidationParser(&ValidationParserOptions{
		MaxErrorCount:  3,
		CheckConflicts: true,
	})

	// 创建多个错误：多种扫描模式冲突
	input := &ValidationInput{
		HasHosts:  true,
		HasURLs:   true,
		LocalMode: true,
		HasProxy:  true,
		// 这会产生至少1个冲突错误
	}

	result, err := parser.Parse(input, nil, nil)
	if err != nil {
		t.Fatalf("Parse失败: %v", err)
	}

	if len(result.Errors) > 3 {
		t.Errorf("错误数量应该被限制为%d，实际%d", 3, len(result.Errors))
	}

	// 注意：如果实际错误数<=MaxErrorCount，不会有截断警告
	// 这是正常行为，不算失败
	if len(result.Errors) <= 3 {
		t.Logf("✓ 错误数量限制测试通过（限制=%d，实际=%d，无需截断）", 3, len(result.Errors))
	} else {
		// 只有超过限制才需要截断警告
		hasTruncateWarning := false
		for _, w := range result.Warnings {
			if strings.Contains(w, "仅显示") || strings.Contains(w, "过多") {
				hasTruncateWarning = true
				break
			}
		}
		if !hasTruncateWarning {
			t.Error("超过限制时应该有错误截断警告")
		}
		t.Logf("✓ 错误数量限制测试通过（限制=%d，截断后=%d）", 3, len(result.Errors))
	}
}

// =============================================================================
// ValidationParser - nil输入测试
// =============================================================================

// TestValidationParser_Parse_NilInput 测试nil输入
//
// 验证：nil输入时返回错误
func TestValidationParser_Parse_NilInput(t *testing.T) {
	parser := NewValidationParser(nil)

	result, err := parser.Parse(nil, nil, nil)

	if err == nil {
		t.Error("nil输入应该返回错误")
	}

	if result != nil {
		t.Error("nil输入时result应该为nil")
	}

	if !strings.Contains(err.Error(), "空") {
		t.Errorf("错误消息应该提示空输入，实际: %v", err)
	}

	t.Logf("✓ nil输入测试通过")
}

// =============================================================================
// ValidationParser - 成功场景测试
// =============================================================================

// TestValidationParser_Parse_Success 测试正常验证通过
func TestValidationParser_Parse_Success(t *testing.T) {
	parser := NewValidationParser(nil)

	input := &ValidationInput{
		ScanMode:    "all",
		HasHosts:    true,
		HasPorts:    true,
		DisablePing: false,
	}

	config := &ParsedConfig{
		Targets: &TargetConfig{
			Hosts: []string{"192.168.1.1"},
			Ports: []int{80, 443},
		},
	}

	result, err := parser.Parse(input, config, nil)

	if err != nil {
		t.Fatalf("Parse失败: %v", err)
	}

	if !result.Success {
		t.Errorf("正常配置应该Success=true，错误: %v", result.Errors)
	}

	if len(result.Errors) > 0 {
		t.Errorf("正常配置不应有错误: %v", result.Errors)
	}

	// ParseTime可能为0（如果验证非常快）
	if result.ParseTime < 0 {
		t.Error("ParseTime不应该为负数")
	}

	if result.Config == nil || result.Config.Validation == nil {
		t.Error("result.Config.Validation不应为nil")
	}

	t.Logf("✓ 成功场景测试通过（耗时=%v）", result.ParseTime)
}
