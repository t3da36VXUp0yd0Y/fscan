package parsers

import (
	"strings"
	"testing"
	"time"
)

// =============================================================================
// NetworkParser 构造函数测试
// =============================================================================

func TestNewNetworkParser(t *testing.T) {
	tests := []struct {
		name    string
		options *NetworkParserOptions
		wantNil bool
	}{
		{
			name:    "使用默认选项",
			options: nil,
			wantNil: false,
		},
		{
			name: "使用自定义选项",
			options: &NetworkParserOptions{
				ValidateProxies: false,
				AllowInsecure:   true,
			},
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewNetworkParser(tt.options)

			if tt.wantNil && parser != nil {
				t.Error("期望parser为nil，但不是")
			}
			if !tt.wantNil && parser == nil {
				t.Error("期望parser不为nil，但是nil")
			}

			if parser != nil && parser.options == nil {
				t.Error("parser.options为nil")
			}
		})
	}
}

// =============================================================================
// Parse 主函数测试
// =============================================================================

func TestNetworkParser_Parse(t *testing.T) {
	parser := NewNetworkParser(nil)

	tests := []struct {
		name        string
		input       *NetworkInput
		wantSuccess bool
		wantError   bool
	}{
		{
			name:        "空输入",
			input:       nil,
			wantSuccess: false,
			wantError:   true,
		},
		{
			name: "完整HTTPS代理配置",
			input: &NetworkInput{
				HTTPProxy: "https://127.0.0.1:8443",
			},
			wantSuccess: true,
		},
		{
			name: "Socks5代理配置",
			input: &NetworkInput{
				Socks5Proxy: "socks5://127.0.0.1:1080",
			},
			wantSuccess: true,
		},
		{
			name: "自定义超时",
			input: &NetworkInput{
				Timeout:    60,
				WebTimeout: 30,
			},
			wantSuccess: true,
		},
		{
			name: "自定义User-Agent",
			input: &NetworkInput{
				UserAgent: "Custom-Agent/1.0",
			},
			wantSuccess: true,
		},
		{
			name: "Cookie配置",
			input: &NetworkInput{
				Cookie: "session=abc123; token=xyz789",
			},
			wantSuccess: true,
		},
		{
			name: "禁用Ping",
			input: &NetworkInput{
				DisablePing: true,
			},
			wantSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parser.Parse(tt.input, nil)

			if tt.wantError {
				if err == nil {
					t.Error("期望错误，但没有错误")
				}
				return
			}

			if err != nil {
				t.Errorf("意外错误: %v", err)
				return
			}

			if result == nil {
				t.Fatal("result为nil")
			}

			if result.Success != tt.wantSuccess {
				t.Errorf("Success = %v, want %v (errors: %v)", result.Success, tt.wantSuccess, result.Errors)
			}
		})
	}
}

// =============================================================================
// normalizeHttpProxy 测试
// =============================================================================

func TestNetworkParser_NormalizeHttpProxy(t *testing.T) {
	parser := NewNetworkParser(nil)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "快捷方式1",
			input:    "1",
			expected: "http://127.0.0.1:8080",
		},
		{
			name:     "快捷方式2",
			input:    "2",
			expected: "socks5://127.0.0.1:1080",
		},
		{
			name:     "只有IP和端口",
			input:    "192.168.1.1:8080",
			expected: "http://192.168.1.1:8080",
		},
		{
			name:     "只有端口号",
			input:    "8080",
			expected: "http://127.0.0.1:8080",
		},
		{
			name:     "完整HTTP URL",
			input:    "http://proxy.example.com:8080",
			expected: "http://proxy.example.com:8080",
		},
		{
			name:     "完整HTTPS URL",
			input:    "https://proxy.example.com:8443",
			expected: "https://proxy.example.com:8443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.normalizeHTTPProxy(tt.input)

			if result != tt.expected {
				t.Errorf("normalizeHTTPProxy(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// normalizeSocks5Proxy 测试
// =============================================================================

func TestNetworkParser_NormalizeSocks5Proxy(t *testing.T) {
	parser := NewNetworkParser(nil)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "IP和端口",
			input:    "192.168.1.1:1080",
			expected: "socks5://192.168.1.1:1080",
		},
		{
			name:     "只有端口号",
			input:    "1080",
			expected: "socks5://127.0.0.1:1080",
		},
		{
			name:     "已有socks5前缀",
			input:    "socks5://proxy.example.com:1080",
			expected: "socks5://proxy.example.com:1080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.normalizeSocks5Proxy(tt.input)

			if result != tt.expected {
				t.Errorf("normalizeSocks5Proxy(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// validateProxyURL 测试
// =============================================================================

func TestNetworkParser_ValidateProxyURL(t *testing.T) {
	// 使用AllowInsecure选项测试HTTP代理
	parser := NewNetworkParser(&NetworkParserOptions{
		ValidateProxies: true,
		AllowInsecure:   true,
	})

	tests := []struct {
		name      string
		proxyURL  string
		wantError bool
	}{
		{
			name:      "有效HTTP代理（AllowInsecure=true）",
			proxyURL:  "http://127.0.0.1:8080",
			wantError: false,
		},
		{
			name:      "有效HTTPS代理",
			proxyURL:  "https://proxy.example.com:8443",
			wantError: false,
		},
		{
			name:      "有效Socks5代理",
			proxyURL:  "socks5://127.0.0.1:1080",
			wantError: false,
		},
		{
			name:      "空URL",
			proxyURL:  "",
			wantError: false, // 空URL被认为是有效的（无代理）
		},
		{
			name:      "不支持的协议",
			proxyURL:  "ftp://proxy.example.com:21",
			wantError: true,
		},
		{
			name:      "缺少主机名",
			proxyURL:  "http://:8080",
			wantError: true,
		},
		{
			name:      "无效端口号",
			proxyURL:  "http://127.0.0.1:99999",
			wantError: true,
		},
		{
			name:      "端口号为0",
			proxyURL:  "http://127.0.0.1:0",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parser.validateProxyURL(tt.proxyURL)

			if tt.wantError && err == nil {
				t.Error("期望错误，但没有错误")
			}
			if !tt.wantError && err != nil {
				t.Errorf("意外错误: %v", err)
			}
		})
	}
}

// =============================================================================
// validateProxyURL 不允许不安全代理测试
// =============================================================================

func TestNetworkParser_ValidateProxyURL_Insecure(t *testing.T) {
	parser := NewNetworkParser(&NetworkParserOptions{
		ValidateProxies: true,
		AllowInsecure:   false,
	})

	err := parser.validateProxyURL("http://proxy.example.com:8080")

	if err == nil {
		t.Error("期望错误（不允许HTTP代理），但没有错误")
	}
}

// =============================================================================
// parseTimeouts 测试
// =============================================================================

func TestNetworkParser_ParseTimeouts(t *testing.T) {
	parser := NewNetworkParser(nil)

	tests := []struct {
		name           string
		timeout        int64
		webTimeout     int64
		wantTimeout    time.Duration
		wantWebTimeout time.Duration
		wantWarnings   int
	}{
		{
			name:           "使用默认超时",
			timeout:        0,
			webTimeout:     0,
			wantTimeout:    DefaultNetworkTimeout,
			wantWebTimeout: DefaultWebTimeout,
			wantWarnings:   0,
		},
		{
			name:           "自定义超时",
			timeout:        60,
			webTimeout:     30,
			wantTimeout:    60 * time.Second,
			wantWebTimeout: 30 * time.Second,
			wantWarnings:   0,
		},
		{
			name:           "超时过长（警告）",
			timeout:        400,
			webTimeout:     200,
			wantTimeout:    400 * time.Second,
			wantWebTimeout: 200 * time.Second,
			wantWarnings:   2,
		},
		{
			name:           "Web超时远大于普通超时（警告）",
			timeout:        10,
			webTimeout:     100,
			wantTimeout:    10 * time.Second,
			wantWebTimeout: 100 * time.Second,
			wantWarnings:   1, // 只有Web超时远大于普通超时警告
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timeout, webTimeout, _, warnings := parser.parseTimeouts(tt.timeout, tt.webTimeout)

			if timeout != tt.wantTimeout {
				t.Errorf("timeout = %v, want %v", timeout, tt.wantTimeout)
			}

			if webTimeout != tt.wantWebTimeout {
				t.Errorf("webTimeout = %v, want %v", webTimeout, tt.wantWebTimeout)
			}

			if len(warnings) != tt.wantWarnings {
				t.Errorf("警告数量 = %d, want %d (warnings: %v)", len(warnings), tt.wantWarnings, warnings)
			}
		})
	}
}

// =============================================================================
// parseUserAgent 测试
// =============================================================================

func TestNetworkParser_ParseUserAgent(t *testing.T) {
	parser := NewNetworkParser(nil)

	tests := []struct {
		name      string
		userAgent string
		wantUA    string
		wantError bool
	}{
		{
			name:      "使用默认User-Agent",
			userAgent: "",
			wantUA:    DefaultUserAgent,
			wantError: false,
		},
		{
			name:      "自定义User-Agent",
			userAgent: "Custom-Bot/1.0",
			wantError: false,
		},
		{
			name:      "过长的User-Agent",
			userAgent: strings.Repeat("a", 600),
			wantError: true,
		},
		{
			name:      "包含非法字符的User-Agent",
			userAgent: "Agent\nWith\nNewlines",
			wantError: true,
		},
		{
			name:      "包含制表符的User-Agent",
			userAgent: "Agent\tWith\tTabs",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ua, errors, _ := parser.parseUserAgent(tt.userAgent)

			if tt.wantError {
				if len(errors) == 0 {
					t.Error("期望错误，但没有错误")
				}
				return
			}

			if len(errors) > 0 {
				t.Errorf("意外错误: %v", errors)
				return
			}

			if tt.userAgent == "" && ua != tt.wantUA {
				t.Errorf("使用默认UA失败: got %s, want %s", ua, tt.wantUA)
			}
		})
	}
}

// =============================================================================
// parseCookie 测试
// =============================================================================

func TestNetworkParser_ParseCookie(t *testing.T) {
	parser := NewNetworkParser(nil)

	tests := []struct {
		name      string
		cookie    string
		wantError bool
	}{
		{
			name:      "空Cookie",
			cookie:    "",
			wantError: false,
		},
		{
			name:      "单个Cookie",
			cookie:    "session=abc123",
			wantError: false,
		},
		{
			name:      "多个Cookie",
			cookie:    "session=abc123; token=xyz789; user=admin",
			wantError: false,
		},
		{
			name:      "过长的Cookie",
			cookie:    strings.Repeat("a", 5000),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errors, _ := parser.parseCookie(tt.cookie)

			if tt.wantError && len(errors) == 0 {
				t.Error("期望错误，但没有错误")
			}
			if !tt.wantError && len(errors) > 0 {
				t.Errorf("意外错误: %v", errors)
			}
		})
	}
}

// =============================================================================
// isValidUserAgent 测试
// =============================================================================

func TestNetworkParser_IsValidUserAgent(t *testing.T) {
	parser := NewNetworkParser(nil)

	tests := []struct {
		name      string
		userAgent string
		wantValid bool
	}{
		{
			name:      "包含Mozilla",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			wantValid: true,
		},
		{
			name:      "包含Chrome",
			userAgent: "Chrome/104.0.0.0",
			wantValid: true,
		},
		{
			name:      "包含Safari",
			userAgent: "Safari/537.36",
			wantValid: true,
		},
		{
			name:      "包含Firefox",
			userAgent: "Firefox/100.0",
			wantValid: true,
		},
		{
			name:      "自定义Agent（不在列表中）",
			userAgent: "CustomBot/1.0",
			wantValid: false,
		},
		{
			name:      "空User-Agent",
			userAgent: "",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := parser.isValidUserAgent(tt.userAgent)

			if valid != tt.wantValid {
				t.Errorf("isValidUserAgent(%s) = %v, want %v", tt.userAgent, valid, tt.wantValid)
			}
		})
	}
}

// =============================================================================
// isValidCookie 测试
// =============================================================================

func TestNetworkParser_IsValidCookie(t *testing.T) {
	parser := NewNetworkParser(nil)

	tests := []struct {
		name      string
		cookie    string
		wantValid bool
	}{
		{
			name:      "有效的简单Cookie",
			cookie:    "session=abc123",
			wantValid: true,
		},
		{
			name:      "有效的多Cookie",
			cookie:    "session=abc123; token=xyz789",
			wantValid: true,
		},
		{
			name:      "带空格的Cookie",
			cookie:    "session=abc123;  token=xyz789",
			wantValid: true,
		},
		{
			name:      "无值Cookie",
			cookie:    "session=; token=xyz",
			wantValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := parser.isValidCookie(tt.cookie)

			if valid != tt.wantValid {
				t.Errorf("isValidCookie(%s) = %v, want %v", tt.cookie, valid, tt.wantValid)
			}
		})
	}
}

// =============================================================================
// 代理冲突警告测试
// =============================================================================

func TestNetworkParser_ProxyConflictWarning(t *testing.T) {
	parser := NewNetworkParser(&NetworkParserOptions{
		AllowInsecure: true, // 允许HTTP代理以测试冲突警告
	})

	input := &NetworkInput{
		HTTPProxy:   "http://127.0.0.1:8080",
		Socks5Proxy: "socks5://127.0.0.1:1080",
	}

	result, err := parser.Parse(input, nil)
	if err != nil {
		t.Errorf("意外错误: %v", err)
		return
	}

	// 应该有警告（同时配置了两种代理+Socks5建议）
	if len(result.Warnings) < 2 {
		t.Errorf("期望至少有2个警告，但只有 %d 个", len(result.Warnings))
	}
}

// =============================================================================
// Socks5代理建议测试
// =============================================================================

func TestNetworkParser_Socks5ProxyHint(t *testing.T) {
	parser := NewNetworkParser(nil)

	input := &NetworkInput{
		Socks5Proxy: "socks5://127.0.0.1:1080",
	}

	result, err := parser.Parse(input, nil)
	if err != nil {
		t.Errorf("意外错误: %v", err)
		return
	}

	// 应该有建议禁用Ping的警告
	foundPingHint := false
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "Ping") || strings.Contains(warning, "ping") {
			foundPingHint = true
			break
		}
	}

	if !foundPingHint {
		t.Errorf("未找到Ping建议警告，warnings: %v", result.Warnings)
	}
}

// =============================================================================
// 完整配置测试
// =============================================================================

func TestNetworkParser_FullConfiguration(t *testing.T) {
	parser := NewNetworkParser(nil)

	input := &NetworkInput{
		HTTPProxy:   "https://proxy.example.com:8443",
		Timeout:     60,
		WebTimeout:  30,
		DisablePing: true,
		DNSLog:      true,
		UserAgent:   "Mozilla/5.0",
		Cookie:      "session=test123; token=abc",
	}

	result, err := parser.Parse(input, nil)
	if err != nil {
		t.Errorf("意外错误: %v", err)
		return
	}

	if !result.Success {
		t.Errorf("解析失败，错误: %v", result.Errors)
	}

	config := result.Config.Network

	if config.HTTPProxy != "https://proxy.example.com:8443" {
		t.Errorf("HTTPProxy = %s, want https://proxy.example.com:8443", config.HTTPProxy)
	}

	if config.Timeout != 60*time.Second {
		t.Errorf("Timeout = %v, want 60s", config.Timeout)
	}

	if config.WebTimeout != 30*time.Second {
		t.Errorf("WebTimeout = %v, want 30s", config.WebTimeout)
	}

	if !config.DisablePing {
		t.Error("DisablePing应为true")
	}

	if !config.EnableDNSLog {
		t.Error("EnableDNSLog应为true")
	}

	if config.UserAgent != "Mozilla/5.0" {
		t.Errorf("UserAgent = %s, want Mozilla/5.0", config.UserAgent)
	}

	if config.Cookie != "session=test123; token=abc" {
		t.Errorf("Cookie = %s, want session=test123; token=abc", config.Cookie)
	}
}
