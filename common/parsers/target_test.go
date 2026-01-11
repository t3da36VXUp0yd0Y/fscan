package parsers

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// =============================================================================
// 测试辅助函数
// =============================================================================

// createTestFile 创建临时测试文件
func createTestFile(t *testing.T, content string) string {
	t.Helper()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")

	if err := os.WriteFile(tmpFile, []byte(content), 0600); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	return tmpFile
}

// =============================================================================
// TargetParser 构造函数测试
// =============================================================================

func TestNewTargetParser(t *testing.T) {
	tests := []struct {
		name    string
		options *TargetParserOptions
		wantNil bool
	}{
		{
			name:    "使用默认选项",
			options: nil,
			wantNil: false,
		},
		{
			name: "使用自定义选项",
			options: &TargetParserOptions{
				MaxTargets:      5000,
				MaxPortRange:    500,
				AllowPrivateIPs: false,
			},
			wantNil: false,
		},
	}

	fileReader := NewFileReader(nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewTargetParser(fileReader, tt.options)

			if tt.wantNil && parser != nil {
				t.Error("期望parser为nil，但不是")
			}
			if !tt.wantNil && parser == nil {
				t.Error("期望parser不为nil，但是nil")
			}

			if parser != nil {
				if parser.options == nil {
					t.Error("parser.options为nil")
				}
				if parser.ipRegex == nil {
					t.Error("parser.ipRegex为nil")
				}
			}
		})
	}
}

// =============================================================================
// Parse 主函数测试
// =============================================================================

func TestTargetParser_Parse(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewTargetParser(fileReader, nil)

	tests := []struct {
		name        string
		input       *TargetInput
		wantSuccess bool
		wantHosts   int
		wantPorts   int
		wantURLs    int
		wantError   bool
	}{
		{
			name:        "空输入",
			input:       nil,
			wantSuccess: false,
			wantError:   true,
		},
		{
			name: "单个IP",
			input: &TargetInput{
				Host: "192.168.1.1",
			},
			wantSuccess: true,
			wantHosts:   1,
		},
		{
			name: "多个IP（逗号分隔）",
			input: &TargetInput{
				Host: "192.168.1.1,192.168.1.2,192.168.1.3",
			},
			wantSuccess: true,
			wantHosts:   3,
		},
		{
			name: "单个端口",
			input: &TargetInput{
				Ports: "80",
			},
			wantSuccess: true,
			wantPorts:   1,
		},
		{
			name: "端口范围",
			input: &TargetInput{
				Ports: "80-85",
			},
			wantSuccess: true,
			wantPorts:   6,
		},
		{
			name: "URL输入",
			input: &TargetInput{
				TargetURL: "http://example.com",
			},
			wantSuccess: true,
			wantURLs:    1,
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
				t.Errorf("Success = %v, want %v", result.Success, tt.wantSuccess)
			}

			if tt.wantHosts > 0 && len(result.Config.Targets.Hosts) != tt.wantHosts {
				t.Errorf("Hosts数量 = %d, want %d", len(result.Config.Targets.Hosts), tt.wantHosts)
			}

			if tt.wantPorts > 0 && len(result.Config.Targets.Ports) != tt.wantPorts {
				t.Errorf("Ports数量 = %d, want %d", len(result.Config.Targets.Ports), tt.wantPorts)
			}

			if tt.wantURLs > 0 && len(result.Config.Targets.URLs) != tt.wantURLs {
				t.Errorf("URLs数量 = %d, want %d", len(result.Config.Targets.URLs), tt.wantURLs)
			}
		})
	}
}

// =============================================================================
// parseHostList 测试 - CIDR解析
// =============================================================================

func TestTargetParser_ParseHostList_CIDR(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewTargetParser(fileReader, nil)

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantError bool
	}{
		{
			name:      "标准/24 CIDR",
			input:     "192.168.1.0/24",
			wantCount: 254, // 排除网络地址和广播地址
			wantError: false,
		},
		{
			name:      "标准/30 CIDR",
			input:     "192.168.1.0/30",
			wantCount: 2, // 4个地址减去网络和广播
			wantError: false,
		},
		{
			name:      "192网段简写",
			input:     "192",
			wantCount: 65534, // /16网段
			wantError: false,
		},
		{
			name:      "172网段简写",
			input:     "172",
			wantCount: 1048574, // /12网段（被MaxTargets限制）
			wantError: false,
		},
		{
			name:      "10网段简写",
			input:     "10",
			wantCount: 16777214, // /8网段（被MaxTargets限制）
			wantError: false,
		},
		{
			name:      "无效CIDR",
			input:     "192.168.1.0/33",
			wantCount: 0,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hosts, err := parser.parseHostList(tt.input)

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

			// 由于MaxTargets限制，实际数量可能小于预期
			if len(hosts) > parser.options.MaxTargets {
				t.Errorf("主机数量 %d 超过MaxTargets %d", len(hosts), parser.options.MaxTargets)
			}

			// 对于小网段，检查准确数量
			if tt.wantCount < parser.options.MaxTargets && len(hosts) != tt.wantCount {
				t.Errorf("主机数量 = %d, want %d", len(hosts), tt.wantCount)
			}
		})
	}
}

// =============================================================================
// parseHostList 测试 - IP范围解析
// =============================================================================

func TestTargetParser_ParseHostList_IPRange(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewTargetParser(fileReader, nil)

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantFirst string
		wantLast  string
		wantError bool
	}{
		{
			name:      "简写范围（同网段）",
			input:     "192.168.1.1-10",
			wantCount: 10,
			wantFirst: "192.168.1.1",
			wantLast:  "192.168.1.10",
			wantError: false,
		},
		{
			name:      "简写范围（单个IP）",
			input:     "192.168.1.5-5",
			wantCount: 1,
			wantFirst: "192.168.1.5",
			wantLast:  "192.168.1.5",
			wantError: false,
		},
		{
			name:      "完整范围",
			input:     "192.168.1.1-192.168.1.5",
			wantCount: 5,
			wantFirst: "192.168.1.1",
			wantLast:  "192.168.1.5",
			wantError: false,
		},
		{
			name:      "反向范围（错误：起始大于结束）",
			input:     "192.168.1.10-192.168.1.5",
			wantCount: 0,
			wantError: true,
		},
		{
			name:      "无效范围（格式错误）",
			input:     "192.168.1.1-300",
			wantCount: 0,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hosts, err := parser.parseHostList(tt.input)

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

			if len(hosts) != tt.wantCount {
				t.Errorf("主机数量 = %d, want %d", len(hosts), tt.wantCount)
			}

			if len(hosts) > 0 {
				if hosts[0] != tt.wantFirst {
					t.Errorf("第一个主机 = %s, want %s", hosts[0], tt.wantFirst)
				}
				if hosts[len(hosts)-1] != tt.wantLast {
					t.Errorf("最后一个主机 = %s, want %s", hosts[len(hosts)-1], tt.wantLast)
				}
			}
		})
	}
}

// =============================================================================
// parsePortList 测试
// =============================================================================

func TestTargetParser_ParsePortList(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewTargetParser(fileReader, nil)

	tests := []struct {
		name      string
		input     string
		wantPorts []int
		wantError bool
	}{
		{
			name:      "单个端口",
			input:     "80",
			wantPorts: []int{80},
			wantError: false,
		},
		{
			name:      "多个端口（逗号分隔）",
			input:     "80,443,8080",
			wantPorts: []int{80, 443, 8080},
			wantError: false,
		},
		{
			name:      "端口范围",
			input:     "8000-8005",
			wantPorts: []int{8000, 8001, 8002, 8003, 8004, 8005},
			wantError: false,
		},
		{
			name:      "混合格式",
			input:     "80,443,8000-8002",
			wantPorts: []int{80, 443, 8000, 8001, 8002},
			wantError: false,
		},
		{
			name:      "无效端口号",
			input:     "99999",
			wantPorts: nil,
			wantError: true,
		},
		{
			name:      "无效端口范围",
			input:     "abc-def",
			wantPorts: nil,
			wantError: true,
		},
		{
			name:      "端口范围过大",
			input:     "1-70000",
			wantPorts: nil,
			wantError: true, // 超过MaxPortRange限制(65535)
		},
		{
			name:      "空输入",
			input:     "",
			wantPorts: nil,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports, err := parser.parsePortList(tt.input)

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

			if len(ports) != len(tt.wantPorts) {
				t.Errorf("端口数量 = %d, want %d", len(ports), len(tt.wantPorts))
				return
			}

			for i, port := range ports {
				if port != tt.wantPorts[i] {
					t.Errorf("端口[%d] = %d, want %d", i, port, tt.wantPorts[i])
				}
			}
		})
	}
}

// =============================================================================
// validateHost 测试
// =============================================================================

func TestTargetParser_ValidateHost(t *testing.T) {
	fileReader := NewFileReader(nil)

	tests := []struct {
		name      string
		host      string
		options   *TargetParserOptions
		wantValid bool
	}{
		{
			name:      "有效IPv4地址",
			host:      "192.168.1.1",
			options:   nil,
			wantValid: true,
		},
		{
			name:      "有效域名",
			host:      "example.com",
			options:   nil,
			wantValid: true,
		},
		{
			name:      "有效子域名",
			host:      "www.example.com",
			options:   nil,
			wantValid: true,
		},
		{
			name:      "空主机",
			host:      "",
			options:   nil,
			wantValid: false,
		},
		{
			name: "私有IP（不允许）",
			host: "192.168.1.1",
			options: &TargetParserOptions{
				AllowPrivateIPs: false,
			},
			wantValid: false,
		},
		{
			name: "回环地址（不允许）",
			host: "127.0.0.1",
			options: &TargetParserOptions{
				AllowLoopback: false,
			},
			wantValid: false,
		},
		{
			name: "回环地址（允许）",
			host: "127.0.0.1",
			options: &TargetParserOptions{
				AllowLoopback: true,
			},
			wantValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewTargetParser(fileReader, tt.options)

			valid, err := parser.validateHost(tt.host)

			if valid != tt.wantValid {
				t.Errorf("validateHost() = %v (err: %v), want %v", valid, err, tt.wantValid)
			}
		})
	}
}

// =============================================================================
// validateURL 测试
// =============================================================================

func TestTargetParser_ValidateURL(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewTargetParser(fileReader, nil)

	tests := []struct {
		name      string
		url       string
		wantValid bool
	}{
		{
			name:      "有效HTTP URL",
			url:       "http://example.com",
			wantValid: true,
		},
		{
			name:      "有效HTTPS URL",
			url:       "https://example.com",
			wantValid: true,
		},
		{
			name:      "带路径的URL",
			url:       "http://example.com/path/to/resource",
			wantValid: true,
		},
		{
			name:      "带端口的URL",
			url:       "http://example.com:8080",
			wantValid: true,
		},
		{
			name:      "带查询参数的URL",
			url:       "http://example.com?key=value",
			wantValid: true,
		},
		{
			name:      "空URL",
			url:       "",
			wantValid: false,
		},
		{
			name:      "无协议的URL",
			url:       "example.com",
			wantValid: false,
		},
		{
			name:      "FTP协议（不支持）",
			url:       "ftp://example.com",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := parser.validateURL(tt.url)

			if valid != tt.wantValid {
				t.Errorf("validateURL() = %v (err: %v), want %v", valid, err, tt.wantValid)
			}
		})
	}
}

// =============================================================================
// validateHostPort 测试
// =============================================================================

func TestTargetParser_ValidateHostPort(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewTargetParser(fileReader, nil)

	tests := []struct {
		name      string
		hostPort  string
		wantValid bool
	}{
		{
			name:      "有效IP:端口",
			hostPort:  "192.168.1.1:80",
			wantValid: true,
		},
		{
			name:      "有效域名:端口",
			hostPort:  "example.com:443",
			wantValid: true,
		},
		{
			name:      "缺少端口",
			hostPort:  "192.168.1.1",
			wantValid: false,
		},
		{
			name:      "无效端口号",
			hostPort:  "192.168.1.1:99999",
			wantValid: false,
		},
		{
			name:      "端口号为0",
			hostPort:  "192.168.1.1:0",
			wantValid: false,
		},
		{
			name:      "空字符串",
			hostPort:  "",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := parser.validateHostPort(tt.hostPort)

			if valid != tt.wantValid {
				t.Errorf("validateHostPort() = %v (err: %v), want %v", valid, err, tt.wantValid)
			}
		})
	}
}

// =============================================================================
// isPrivateIP 测试
// =============================================================================

func TestTargetParser_IsPrivateIP(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewTargetParser(fileReader, nil)

	tests := []struct {
		name        string
		ip          string
		wantPrivate bool
	}{
		{
			name:        "10.x.x.x网段",
			ip:          "10.0.0.1",
			wantPrivate: true,
		},
		{
			name:        "172.16.x.x网段（起始）",
			ip:          "172.16.0.1",
			wantPrivate: true,
		},
		{
			name:        "172.31.x.x网段（结束）",
			ip:          "172.31.255.254",
			wantPrivate: true,
		},
		{
			name:        "172.15.x.x（不在范围内）",
			ip:          "172.15.0.1",
			wantPrivate: false,
		},
		{
			name:        "172.32.x.x（不在范围内）",
			ip:          "172.32.0.1",
			wantPrivate: false,
		},
		{
			name:        "192.168.x.x网段",
			ip:          "192.168.1.1",
			wantPrivate: true,
		},
		{
			name:        "公网IP",
			ip:          "8.8.8.8",
			wantPrivate: false,
		},
		{
			name:        "公网IP（1.1.1.1）",
			ip:          "1.1.1.1",
			wantPrivate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("无效IP地址: %s", tt.ip)
			}

			isPrivate := parser.isPrivateIP(ip)

			if isPrivate != tt.wantPrivate {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, isPrivate, tt.wantPrivate)
			}
		})
	}
}

// =============================================================================
// 文件读取测试
// =============================================================================

func TestTargetParser_ParseFromFile(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewTargetParser(fileReader, nil)

	tests := []struct {
		name        string
		fileContent string
		wantHosts   int
	}{
		{
			name: "主机列表文件",
			fileContent: `192.168.1.1
192.168.1.2
192.168.1.3`,
			wantHosts: 3,
		},
		{
			name: "带注释的主机列表",
			fileContent: `# 这是注释
192.168.1.1
# 另一个注释
192.168.1.2`,
			wantHosts: 2,
		},
		{
			name: "带空行的主机列表",
			fileContent: `192.168.1.1

192.168.1.2

192.168.1.3`,
			wantHosts: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := createTestFile(t, tt.fileContent)

			input := &TargetInput{
				HostsFile: tmpFile,
			}

			result, err := parser.Parse(input, nil)
			if err != nil {
				t.Errorf("意外错误: %v", err)
				return
			}

			if !result.Success {
				t.Errorf("解析失败，错误: %v", result.Errors)
			}

			if len(result.Config.Targets.Hosts) != tt.wantHosts {
				t.Errorf("主机数量 = %d, want %d", len(result.Config.Targets.Hosts), tt.wantHosts)
			}
		})
	}

	// 端口文件测试
	t.Run("端口列表文件", func(t *testing.T) {
		portsFile := createTestFile(t, `80
443
8080
# 注释行
8443`)

		input := &TargetInput{
			PortsFile: portsFile,
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Errorf("意外错误: %v", err)
			return
		}

		if !result.Success {
			t.Errorf("解析失败，错误: %v", result.Errors)
		}

		// 应解析出4个端口（注释被跳过）
		if len(result.Config.Targets.Ports) != 4 {
			t.Errorf("端口数量 = %d, want 4", len(result.Config.Targets.Ports))
		}
	})

	// URL文件测试
	t.Run("URL列表文件", func(t *testing.T) {
		urlsFile := createTestFile(t, `http://example1.com
https://example2.com
# 注释
http://example3.com:8080
`)

		input := &TargetInput{
			URLsFile: urlsFile,
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Errorf("意外错误: %v", err)
			return
		}

		if !result.Success {
			t.Errorf("解析失败，错误: %v", result.Errors)
		}

		// 应解析出3个URL
		if len(result.Config.Targets.URLs) != 3 {
			t.Errorf("URL数量 = %d, want 3", len(result.Config.Targets.URLs))
		}
	})

	// 排除主机文件测试
	t.Run("排除主机列表", func(t *testing.T) {
		hostsFile := createTestFile(t, "192.168.1.1\n192.168.1.2\n192.168.1.3\n192.168.1.4\n192.168.1.5")
		excludeFile := createTestFile(t, "192.168.1.2\n192.168.1.4")

		input := &TargetInput{
			HostsFile:        hostsFile,
			ExcludeHostsFile: excludeFile,
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Errorf("意外错误: %v", err)
			return
		}

		// 5个主机 - 2个排除 = 3个
		if len(result.Config.Targets.Hosts) != 3 {
			t.Errorf("主机数量 = %d, want 3", len(result.Config.Targets.Hosts))
		}
	})

	// 混合输入：命令行+文件
	t.Run("混合输入（命令行+文件）", func(t *testing.T) {
		hostsFile := createTestFile(t, "192.168.1.10\n192.168.1.11")
		portsFile := createTestFile(t, "8080\n8443")

		input := &TargetInput{
			Host:      "192.168.1.1,192.168.1.2",
			HostsFile: hostsFile,
			Ports:     "80,443",
			PortsFile: portsFile,
			AddPorts:  "9000,9001",
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Errorf("意外错误: %v", err)
			return
		}

		// 主机: 2(命令行) + 2(文件) = 4
		if len(result.Config.Targets.Hosts) != 4 {
			t.Errorf("主机数量 = %d, want 4", len(result.Config.Targets.Hosts))
		}

		// 端口: 2(命令行) + 2(文件) + 2(AddPorts) = 6
		if len(result.Config.Targets.Ports) != 6 {
			t.Errorf("端口数量 = %d, want 6", len(result.Config.Targets.Ports))
		}
	})

	// 文件中的无效行测试
	t.Run("文件包含无效行（应产生警告）", func(t *testing.T) {
		hostsFile := createTestFile(t, `192.168.1.1
invalid!!!host!!!format
192.168.1.2
999.999.999.999
192.168.1.3`)

		input := &TargetInput{
			HostsFile: hostsFile,
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Errorf("意外错误: %v", err)
			return
		}

		// 999.999.999.999 应该被过滤掉，因为是无效IP
		// invalid!!!host!!!format 可能被识别为域名（取决于域名验证规则）
		// 至少应该有3个有效主机
		if len(result.Config.Targets.Hosts) < 3 {
			t.Errorf("主机数量 = %d, 应该至少有3个", len(result.Config.Targets.Hosts))
		}
	})
}

// =============================================================================
// excludeHosts 测试
// =============================================================================

func TestTargetParser_ExcludeHosts(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewTargetParser(fileReader, nil)

	hosts := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"}
	excludeList := []string{"192.168.1.2", "192.168.1.4"}

	result := parser.excludeHosts(hosts, excludeList)

	expected := []string{"192.168.1.1", "192.168.1.3"}

	if len(result) != len(expected) {
		t.Errorf("结果数量 = %d, want %d", len(result), len(expected))
	}

	for i, host := range result {
		if host != expected[i] {
			t.Errorf("主机[%d] = %s, want %s", i, host, expected[i])
		}
	}
}

// =============================================================================
// removeDuplicateStrings 测试
// =============================================================================

func TestTargetParser_RemoveDuplicateStrings(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewTargetParser(fileReader, nil)

	input := []string{"a", "b", "a", "c", "b", "d"}
	expected := []string{"a", "b", "c", "d"}

	result := parser.removeDuplicateStrings(input)

	if len(result) != len(expected) {
		t.Errorf("结果数量 = %d, want %d", len(result), len(expected))
	}

	// 检查所有预期元素都存在（顺序可能不同）
	resultMap := make(map[string]bool)
	for _, item := range result {
		resultMap[item] = true
	}

	for _, item := range expected {
		if !resultMap[item] {
			t.Errorf("缺少元素: %s", item)
		}
	}
}

// =============================================================================
// removeDuplicatePorts 测试
// =============================================================================

func TestTargetParser_RemoveDuplicatePorts(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewTargetParser(fileReader, nil)

	input := []int{80, 443, 80, 8080, 443, 22}
	expected := []int{80, 443, 8080, 22}

	result := parser.removeDuplicatePorts(input)

	if len(result) != len(expected) {
		t.Errorf("结果数量 = %d, want %d", len(result), len(expected))
	}

	// 检查所有预期元素都存在
	resultMap := make(map[int]bool)
	for _, port := range result {
		resultMap[port] = true
	}

	for _, port := range expected {
		if !resultMap[port] {
			t.Errorf("缺少端口: %d", port)
		}
	}
}

// =============================================================================
// parseSubnet8 测试（/8网段采样）
// =============================================================================

func TestTargetParser_ParseSubnet8(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewTargetParser(fileReader, nil)

	tests := []struct {
		name      string
		input     string
		wantError bool
	}{
		{
			name:      "/8网段采样",
			input:     "10.0.0.0/8",
			wantError: false,
		},
		{
			name:      "/8网段采样（另一个例子）",
			input:     "172.0.0.0/8",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hosts, err := parser.parseHostList(tt.input)

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

			// /8网段会被限制到MaxTargets
			if len(hosts) == 0 {
				t.Error("采样结果为空")
			}

			if len(hosts) > parser.options.MaxTargets {
				t.Errorf("主机数量 %d 超过MaxTargets %d", len(hosts), parser.options.MaxTargets)
			}

			// 验证生成的IP格式正确
			for i, host := range hosts {
				if net.ParseIP(host) == nil {
					t.Errorf("无效IP地址[%d]: %s", i, host)
					break
				}
			}
		})
	}
}

// =============================================================================
// host:port 组合测试
// =============================================================================

func TestTargetParser_HostPortCombination(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewTargetParser(fileReader, nil)

	tests := []struct {
		name          string
		input         *TargetInput
		wantHostPorts int
		wantHosts     int
		wantPorts     int
	}{
		{
			name: "单个host:port",
			input: &TargetInput{
				Host: "192.168.1.1:80",
			},
			wantHostPorts: 1,
			wantHosts:     0, // host:port不会被添加到hosts
			wantPorts:     0, // Ports应该为空，只扫描指定的host:port
		},
		{
			name: "多个host:port",
			input: &TargetInput{
				HostPort: []string{"192.168.1.1:80", "192.168.1.2:443"},
			},
			wantHostPorts: 2,
			wantHosts:     0,
			wantPorts:     0,
		},
		{
			name: "混合host:port和普通host",
			input: &TargetInput{
				Host: "192.168.1.1:80,192.168.1.2",
			},
			wantHostPorts: 1,
			wantHosts:     1, // 192.168.1.2
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parser.Parse(tt.input, nil)
			if err != nil {
				t.Errorf("意外错误: %v", err)
				return
			}

			if !result.Success {
				t.Errorf("解析失败，错误: %v", result.Errors)
			}

			if len(result.Config.Targets.HostPorts) != tt.wantHostPorts {
				t.Errorf("HostPorts数量 = %d, want %d", len(result.Config.Targets.HostPorts), tt.wantHostPorts)
			}

			if tt.wantHosts > 0 && len(result.Config.Targets.Hosts) != tt.wantHosts {
				t.Errorf("Hosts数量 = %d, want %d", len(result.Config.Targets.Hosts), tt.wantHosts)
			}
		})
	}
}

// =============================================================================
// 边界条件测试
// =============================================================================

func TestTargetParser_EdgeCases(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewTargetParser(fileReader, nil)

	t.Run("空字符串输入", func(t *testing.T) {
		hosts, err := parser.parseHostList("")
		if err != nil {
			t.Errorf("意外错误: %v", err)
		}
		if len(hosts) != 0 {
			t.Errorf("空输入应返回空列表，得到 %d 个主机", len(hosts))
		}
	})

	t.Run("只有逗号的输入", func(t *testing.T) {
		hosts, err := parser.parseHostList(",,,")
		if err != nil {
			t.Errorf("意外错误: %v", err)
		}
		if len(hosts) != 0 {
			t.Errorf("只有逗号的输入应返回空列表，得到 %d 个主机", len(hosts))
		}
	})

	t.Run("带空格的输入", func(t *testing.T) {
		hosts, err := parser.parseHostList(" 192.168.1.1 , 192.168.1.2 ")
		if err != nil {
			t.Errorf("意外错误: %v", err)
		}
		if len(hosts) != 2 {
			t.Errorf("应该解析出2个主机，得到 %d 个", len(hosts))
		}
	})

	t.Run("端口号边界值", func(t *testing.T) {
		tests := []struct {
			port      string
			wantError bool
		}{
			{"1", false},     // 最小端口
			{"65535", false}, // 最大端口
			{"0", true},      // 无效端口
			{"65536", true},  // 超出范围
			{"-1", true},     // 负数
		}

		for _, tt := range tests {
			t.Run("端口:"+tt.port, func(t *testing.T) {
				_, err := parser.parsePortList(tt.port)
				if tt.wantError && err == nil {
					t.Error("期望错误，但没有错误")
				}
				if !tt.wantError && err != nil {
					t.Errorf("意外错误: %v", err)
				}
			})
		}
	})

	t.Run("域名验证", func(t *testing.T) {
		tests := []struct {
			domain    string
			wantValid bool
		}{
			{"example.com", true},
			{"sub.example.com", true},
			{"example-with-dash.com", true},
			{"123.com", true},
			{"-invalid.com", false}, // 以连字符开头
			{"invalid-.com", false}, // 以连字符结尾
			{"too..many.dots.com", false},
		}

		for _, tt := range tests {
			t.Run(tt.domain, func(t *testing.T) {
				valid := parser.isValidDomain(tt.domain)
				if valid != tt.wantValid {
					t.Errorf("isValidDomain(%s) = %v, want %v", tt.domain, valid, tt.wantValid)
				}
			})
		}
	})
}

// =============================================================================
// 文件解析错误处理测试
// =============================================================================

func TestTargetParser_FileErrorHandling(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewTargetParser(fileReader, nil)

	t.Run("不存在的文件", func(t *testing.T) {
		input := &TargetInput{
			HostsFile: "/nonexistent/file/path.txt",
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Errorf("Parse不应返回错误: %v", err)
			return
		}

		if result.Success {
			t.Error("解析不应成功（文件不存在）")
		}

		if len(result.Errors) == 0 {
			t.Error("应该有错误记录")
		}
	})

	t.Run("空文件", func(t *testing.T) {
		tmpFile := createTestFile(t, "")

		input := &TargetInput{
			HostsFile: tmpFile,
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Errorf("意外错误: %v", err)
			return
		}

		if len(result.Config.Targets.Hosts) != 0 {
			t.Errorf("空文件应解析出0个主机，得到 %d 个", len(result.Config.Targets.Hosts))
		}
	})
}

// =============================================================================
// 复杂场景集成测试
// =============================================================================

func TestTargetParser_ComplexScenarios(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewTargetParser(fileReader, nil)

	t.Run("混合输入（IP+CIDR+范围+域名）", func(t *testing.T) {
		input := &TargetInput{
			Host:  "192.168.1.1,192.168.2.0/30,192.168.3.1-5,example.com",
			Ports: "80,443,8000-8002",
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Fatalf("意外错误: %v", err)
		}

		if !result.Success {
			t.Errorf("解析失败，错误: %v", result.Errors)
		}

		// 验证主机数量: 1(单IP) + 2(CIDR) + 5(范围) + 1(域名) = 9
		expectedHosts := 9
		if len(result.Config.Targets.Hosts) != expectedHosts {
			t.Errorf("主机数量 = %d, want %d", len(result.Config.Targets.Hosts), expectedHosts)
		}

		// 验证端口数量: 2(单端口) + 3(范围) = 5
		expectedPorts := 5
		if len(result.Config.Targets.Ports) != expectedPorts {
			t.Errorf("端口数量 = %d, want %d", len(result.Config.Targets.Ports), expectedPorts)
		}
	})

	t.Run("带排除的扫描", func(t *testing.T) {
		input := &TargetInput{
			Host:         "192.168.1.1-10",
			ExcludeHosts: "192.168.1.5,192.168.1.6",
			Ports:        "1-100",
			ExcludePorts: "22,23,24",
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Fatalf("意外错误: %v", err)
		}

		if !result.Success {
			t.Errorf("解析失败，错误: %v", result.Errors)
		}

		// 验证排除后的主机数量: 10 - 2 = 8
		if len(result.Config.Targets.Hosts) != 8 {
			t.Errorf("主机数量 = %d, want 8", len(result.Config.Targets.Hosts))
		}

		// 验证排除端口列表
		if len(result.Config.Targets.ExcludePorts) != 3 {
			t.Errorf("排除端口数量 = %d, want 3", len(result.Config.Targets.ExcludePorts))
		}
	})
}
