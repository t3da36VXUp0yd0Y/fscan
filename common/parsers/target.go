package parsers

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common/config"
)

// TargetParser 目标解析器
type TargetParser struct {
	fileReader *FileReader
	mu         sync.RWMutex //nolint:unused // reserved for future thread safety
	ipRegex    *regexp.Regexp
	portRegex  *regexp.Regexp
	urlRegex   *regexp.Regexp
	options    *TargetParserOptions
}

// TargetParserOptions 目标解析器选项
type TargetParserOptions struct {
	MaxTargets      int  `json:"max_targets"`
	MaxPortRange    int  `json:"max_port_range"`
	AllowPrivateIPs bool `json:"allow_private_ips"`
	AllowLoopback   bool `json:"allow_loopback"`
	ValidateURLs    bool `json:"validate_urls"`
	ResolveDomains  bool `json:"resolve_domains"`
}

// DefaultTargetParserOptions 默认目标解析器选项
func DefaultTargetParserOptions() *TargetParserOptions {
	return &TargetParserOptions{
		MaxTargets:      DefaultTargetMaxTargets,
		MaxPortRange:    DefaultMaxPortRange,
		AllowPrivateIPs: DefaultAllowPrivateIPs,
		AllowLoopback:   DefaultAllowLoopback,
		ValidateURLs:    DefaultValidateURLs,
		ResolveDomains:  DefaultResolveDomains,
	}
}

// NewTargetParser 创建目标解析器
func NewTargetParser(fileReader *FileReader, options *TargetParserOptions) *TargetParser {
	if options == nil {
		options = DefaultTargetParserOptions()
	}

	// 使用预编译的正则表达式
	ipRegex := CompiledIPv4Regex
	portRegex := CompiledPortRegex
	urlRegex := CompiledURLRegex

	return &TargetParser{
		fileReader: fileReader,
		ipRegex:    ipRegex,
		portRegex:  portRegex,
		urlRegex:   urlRegex,
		options:    options,
	}
}

// TargetInput 目标输入参数
type TargetInput struct {
	// 主机相关
	Host             string `json:"host"`
	HostsFile        string `json:"hosts_file"`
	ExcludeHosts     string `json:"exclude_hosts"`
	ExcludeHostsFile string `json:"exclude_hosts_file"`

	// 端口相关
	Ports        string `json:"ports"`
	PortsFile    string `json:"ports_file"`
	AddPorts     string `json:"add_ports"`
	ExcludePorts string `json:"exclude_ports"`

	// URL相关
	TargetURL string `json:"target_url"`
	URLsFile  string `json:"urls_file"`

	// 主机端口组合
	HostPort []string `json:"host_port"`

	// 模式标识
	LocalMode bool `json:"local_mode"`
}

// Parse 解析目标配置
func (tp *TargetParser) Parse(input *TargetInput, options *ParserOptions) (*ParseResult, error) {
	if input == nil {
		return nil, NewParseError(ErrorTypeInputError, "目标输入为空", "", 0, ErrEmptyInput)
	}

	startTime := time.Now()
	result := &ParseResult{
		Config: &ParsedConfig{
			Targets: &TargetConfig{
				LocalMode: input.LocalMode,
			},
		},
		Success: true,
	}

	var errors []error
	var warnings []string

	// 解析主机
	hosts, hostErrors, hostWarnings := tp.parseHosts(input)
	errors = append(errors, hostErrors...)
	warnings = append(warnings, hostWarnings...)

	// 解析URL
	urls, urlErrors, urlWarnings := tp.parseURLs(input)
	errors = append(errors, urlErrors...)
	warnings = append(warnings, urlWarnings...)

	// 解析端口
	ports, portErrors, portWarnings := tp.parsePorts(input)
	errors = append(errors, portErrors...)
	warnings = append(warnings, portWarnings...)

	// 解析排除端口
	excludePorts, excludeErrors, excludeWarnings := tp.parseExcludePorts(input)
	errors = append(errors, excludeErrors...)
	warnings = append(warnings, excludeWarnings...)

	// 解析主机端口组合
	hostPorts, hpErrors, hpWarnings := tp.parseHostPorts(input)
	errors = append(errors, hpErrors...)
	warnings = append(warnings, hpWarnings...)

	// 更新配置
	result.Config.Targets.Hosts = hosts
	result.Config.Targets.URLs = urls

	// 如果存在明确的host:port组合，则清空端口列表避免双重扫描
	if len(hostPorts) > 0 {
		result.Config.Targets.Ports = nil // 清空默认端口，只扫描指定的host:port
	} else {
		result.Config.Targets.Ports = ports
	}

	result.Config.Targets.ExcludePorts = excludePorts
	result.Config.Targets.HostPorts = hostPorts

	// 设置结果状态
	result.Errors = errors
	result.Warnings = warnings
	result.ParseTime = time.Since(startTime)
	result.Success = len(errors) == 0

	return result, nil
}

// parseHosts 解析主机
func (tp *TargetParser) parseHosts(input *TargetInput) ([]string, []error, []string) {
	var hosts []string
	var errors []error
	var warnings []string

	// 解析命令行主机
	if input.Host != "" {
		// 检查是否为host:port格式，直接添加到HostPort避免双重处理
		if strings.Contains(input.Host, ":") {
			if _, portStr, err := net.SplitHostPort(input.Host); err == nil {
				if port, portErr := strconv.Atoi(portStr); portErr == nil && port >= MinPort && port <= MaxPort {
					// 这是有效的host:port格式，直接添加到HostPort
					input.HostPort = append(input.HostPort, input.Host)
					// 清空Ports字段，避免解析默认端口
					input.Ports = ""
					// 不添加到hosts，避免双重处理
				} else {
					// 端口无效，作为普通主机处理
					hostList, parseErr := tp.parseHostList(input.Host)
					if parseErr != nil {
						errors = append(errors, NewParseError(ErrorTypeHostError, parseErr.Error(), "command line", 0, parseErr))
					} else {
						hosts = append(hosts, hostList...)
					}
				}
			} else {
				// 不是有效的host:port格式，作为普通主机处理
				hostList, parseErr := tp.parseHostList(input.Host)
				if parseErr != nil {
					errors = append(errors, NewParseError(ErrorTypeHostError, parseErr.Error(), "command line", 0, parseErr))
				} else {
					hosts = append(hosts, hostList...)
				}
			}
		} else {
			// 普通主机，正常处理
			hostList, err := tp.parseHostList(input.Host)
			if err != nil {
				errors = append(errors, NewParseError(ErrorTypeHostError, err.Error(), "command line", 0, err))
			} else {
				hosts = append(hosts, hostList...)
			}
		}
	}

	// 从文件读取主机
	if input.HostsFile != "" {
		fileResult, err := tp.fileReader.ReadFile(input.HostsFile)
		if err != nil {
			errors = append(errors, NewParseError(ErrorTypeFileError, "读取主机文件失败", input.HostsFile, 0, err))
		} else {
			for i, line := range fileResult.Lines {
				hostList, err := tp.parseHostList(line)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("主机文件第%d行解析失败: %s", i+1, err.Error()))
				} else {
					hosts = append(hosts, hostList...)
				}
			}
		}
	}

	// 处理排除主机
	var excludeList []string

	// 从命令行参数读取排除主机
	if input.ExcludeHosts != "" {
		cmdExclude, err := tp.parseHostList(input.ExcludeHosts)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("排除主机解析失败: %s", err.Error()))
		} else {
			excludeList = append(excludeList, cmdExclude...)
		}
	}

	// 从文件读取排除主机
	if input.ExcludeHostsFile != "" {
		fileResult, err := tp.fileReader.ReadFile(input.ExcludeHostsFile)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("读取排除主机文件失败: %s", err.Error()))
		} else {
			for i, line := range fileResult.Lines {
				fileExclude, err := tp.parseHostList(line)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("排除主机文件第%d行解析失败: %s", i+1, err.Error()))
				} else {
					excludeList = append(excludeList, fileExclude...)
				}
			}
		}
	}

	// 应用排除列表
	if len(excludeList) > 0 {
		hosts = tp.excludeHosts(hosts, excludeList)
	}

	// 去重和验证，同时分离host:port格式
	hosts = tp.removeDuplicateStrings(hosts)
	validHosts := make([]string, 0, len(hosts))
	hostPorts := make([]string, 0)

	for _, host := range hosts {
		// 检查是否为host:port格式
		if strings.Contains(host, ":") {
			if h, portStr, err := net.SplitHostPort(host); err == nil {
				// 验证端口号
				if port, portErr := strconv.Atoi(portStr); portErr == nil && port >= MinPort && port <= MaxPort {
					// 验证主机部分
					if valid, hostErr := tp.validateHost(h); valid {
						// 这是有效的host:port组合，添加到hostPorts
						hostPorts = append(hostPorts, host)
						continue
					} else if hostErr != nil {
						warnings = append(warnings, fmt.Sprintf("无效主机端口组合: %s - %s", host, hostErr.Error()))
						continue
					}
				}
			}
		}

		// 作为普通主机验证
		if valid, err := tp.validateHost(host); valid {
			validHosts = append(validHosts, host)
		} else if err != nil {
			warnings = append(warnings, fmt.Sprintf("无效主机: %s - %s", host, err.Error()))
		}
	}

	// 将找到的hostPorts合并到输入结果中（通过修改input结构）
	if len(hostPorts) > 0 {
		input.HostPort = append(input.HostPort, hostPorts...)
	}

	// 检查目标数量限制
	if len(validHosts) > tp.options.MaxTargets {
		warnings = append(warnings, fmt.Sprintf("主机数量超过限制，截取前%d个", tp.options.MaxTargets))
		validHosts = validHosts[:tp.options.MaxTargets]
	}

	return validHosts, errors, warnings
}

// parseURLs 解析URL
func (tp *TargetParser) parseURLs(input *TargetInput) ([]string, []error, []string) {
	var urls []string
	var errors []error
	var warnings []string

	// 解析命令行URL
	if input.TargetURL != "" {
		urlList := strings.Split(input.TargetURL, ",")
		for _, rawURL := range urlList {
			rawURL = strings.TrimSpace(rawURL)
			if rawURL != "" {
				normalizedURL := tp.normalizeURL(rawURL)
				if valid, err := tp.validateURL(normalizedURL); valid {
					urls = append(urls, normalizedURL)
				} else {
					warnings = append(warnings, fmt.Sprintf("无效URL: %s - %s", rawURL, err.Error()))
				}
			}
		}
	}

	// 从文件读取URL
	if input.URLsFile != "" {
		fileResult, err := tp.fileReader.ReadFile(input.URLsFile)
		if err != nil {
			errors = append(errors, NewParseError(ErrorTypeFileError, "读取URL文件失败", input.URLsFile, 0, err))
		} else {
			for i, line := range fileResult.Lines {
				normalizedURL := tp.normalizeURL(line)
				if valid, err := tp.validateURL(normalizedURL); valid {
					urls = append(urls, normalizedURL)
				} else {
					warnings = append(warnings, fmt.Sprintf("URL文件第%d行无效: %s", i+1, err.Error()))
				}
			}
		}
	}

	// 去重
	urls = tp.removeDuplicateStrings(urls)

	return urls, errors, warnings
}

// normalizeURL 规范化URL，自动补全协议头
func (tp *TargetParser) normalizeURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return rawURL
	}
	// 如果没有协议头，自动添加 http://
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return "http://" + rawURL
	}
	return rawURL
}

// parsePorts 解析端口
func (tp *TargetParser) parsePorts(input *TargetInput) ([]int, []error, []string) {
	var ports []int
	var errors []error
	var warnings []string

	// 解析命令行端口
	if input.Ports != "" {
		portList, err := tp.parsePortList(input.Ports)
		if err != nil {
			errors = append(errors, NewParseError(ErrorTypePortError, err.Error(), "command line", 0, err))
		} else {
			ports = append(ports, portList...)
		}
	}

	// 从文件读取端口
	if input.PortsFile != "" {
		fileResult, err := tp.fileReader.ReadFile(input.PortsFile)
		if err != nil {
			errors = append(errors, NewParseError(ErrorTypeFileError, "读取端口文件失败", input.PortsFile, 0, err))
		} else {
			for i, line := range fileResult.Lines {
				portList, err := tp.parsePortList(line)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("端口文件第%d行解析失败: %s", i+1, err.Error()))
				} else {
					ports = append(ports, portList...)
				}
			}
		}
	}

	// 处理额外端口
	if input.AddPorts != "" {
		addPortList, err := tp.parsePortList(input.AddPorts)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("额外端口解析失败: %s", err.Error()))
		} else {
			ports = append(ports, addPortList...)
		}
	}

	// 去重和排序
	ports = tp.removeDuplicatePorts(ports)

	return ports, errors, warnings
}

// parseExcludePorts 解析排除端口
func (tp *TargetParser) parseExcludePorts(input *TargetInput) ([]int, []error, []string) { //nolint:unparam
	var excludePorts []int
	var errors []error
	var warnings []string

	if input.ExcludePorts != "" {
		portList, err := tp.parsePortList(input.ExcludePorts)
		if err != nil {
			errors = append(errors, NewParseError(ErrorTypeExcludePortError, err.Error(), "command line", 0, err))
		} else {
			excludePorts = portList
		}
	}

	return excludePorts, errors, warnings
}

// parseHostPorts 解析主机端口组合
func (tp *TargetParser) parseHostPorts(input *TargetInput) ([]string, []error, []string) { //nolint:unparam
	var hostPorts []string
	var errors []error
	var warnings []string

	for _, hp := range input.HostPort {
		if hp != "" {
			if valid, err := tp.validateHostPort(hp); valid {
				hostPorts = append(hostPorts, hp)
			} else {
				warnings = append(warnings, fmt.Sprintf("无效主机端口组合: %s - %s", hp, err.Error()))
			}
		}
	}

	return hostPorts, errors, warnings
}

// parseHostList 解析主机列表
func (tp *TargetParser) parseHostList(hostStr string) ([]string, error) {
	if hostStr == "" {
		return nil, nil
	}

	var hosts []string
	hostItems := strings.Split(hostStr, ",")

	for _, item := range hostItems {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		// 检查各种IP格式
		switch {
		case item == PrivateNetwork192:
			// 常用内网段简写
			cidrHosts, err := tp.parseCIDR(PrivateNetwork192CIDR)
			if err != nil {
				return nil, fmt.Errorf("192网段解析失败: %w", err)
			}
			hosts = append(hosts, cidrHosts...)
		case item == PrivateNetwork172:
			// 常用内网段简写
			cidrHosts, err := tp.parseCIDR(PrivateNetwork172CIDR)
			if err != nil {
				return nil, fmt.Errorf("172网段解析失败: %w", err)
			}
			hosts = append(hosts, cidrHosts...)
		case item == PrivateNetwork10:
			// 常用内网段简写
			cidrHosts, err := tp.parseCIDR(PrivateNetwork10CIDR)
			if err != nil {
				return nil, fmt.Errorf("10网段解析失败: %w", err)
			}
			hosts = append(hosts, cidrHosts...)
		case strings.HasSuffix(item, "/8"):
			// 处理/8网段（使用采样方式）
			sampledHosts := tp.parseSubnet8(item)
			hosts = append(hosts, sampledHosts...)
		case strings.Contains(item, "/"):
			// CIDR表示法
			cidrHosts, err := tp.parseCIDR(item)
			if err != nil {
				return nil, fmt.Errorf("CIDR解析失败 %s: %w", item, err)
			}
			hosts = append(hosts, cidrHosts...)
		case strings.Contains(item, "-"):
			// IP范围表示法
			rangeHosts, err := tp.parseIPRange(item)
			if err != nil {
				return nil, fmt.Errorf("IP范围解析失败 %s: %w", item, err)
			}
			hosts = append(hosts, rangeHosts...)
		default:
			// 检查是否为host:port格式
			if strings.Contains(item, ":") {
				if _, portStr, err := net.SplitHostPort(item); err == nil {
					// 验证端口号
					if port, portErr := strconv.Atoi(portStr); portErr == nil && port >= MinPort && port <= MaxPort {
						// 这是有效的host:port格式，但在这里仍然作为主机处理
						// 在后续的processHostPorts函数中会被正确处理
						hosts = append(hosts, item)
					} else {
						// 端口无效，作为普通主机处理
						hosts = append(hosts, item)
					}
				} else {
					// 不是有效的host:port格式，作为普通主机处理
					hosts = append(hosts, item)
				}
			} else {
				// 单个IP或域名
				hosts = append(hosts, item)
			}
		}
	}

	return hosts, nil
}

// parsePortList 解析端口列表，支持预定义端口组
func (tp *TargetParser) parsePortList(portStr string) ([]int, error) {
	if portStr == "" {
		return nil, nil
	}

	// 检查是否为预定义端口组
	portStr = tp.expandPortGroups(portStr)

	var ports []int
	portItems := strings.Split(portStr, ",")

	for _, item := range portItems {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		if strings.Contains(item, "-") {
			// 端口范围
			rangePorts, err := tp.parsePortRange(item)
			if err != nil {
				return nil, fmt.Errorf("端口范围解析失败 %s: %w", item, err)
			}

			// 检查范围大小
			if len(rangePorts) > tp.options.MaxPortRange {
				return nil, fmt.Errorf("端口范围过大: %d, 最大允许: %d", len(rangePorts), tp.options.MaxPortRange)
			}

			ports = append(ports, rangePorts...)
		} else {
			// 单个端口
			port, err := strconv.Atoi(item)
			if err != nil {
				return nil, fmt.Errorf("无效端口号: %s", item)
			}

			if port < MinPort || port > MaxPort {
				return nil, fmt.Errorf("端口号超出范围: %d", port)
			}

			ports = append(ports, port)
		}
	}

	return ports, nil
}

// expandPortGroups 展开预定义端口组
func (tp *TargetParser) expandPortGroups(portStr string) string {
	// 使用预定义的端口组
	portGroups := config.GetPortGroups()

	if expandedPorts, exists := portGroups[portStr]; exists {
		return expandedPorts
	}
	return portStr
}

// parseCIDR 解析CIDR网段
func (tp *TargetParser) parseCIDR(cidr string) ([]string, error) {
	return parseIPCIDR(cidr, tp.options.MaxTargets)
}

// parseIPRange 解析IP范围，支持简写格式
func (tp *TargetParser) parseIPRange(rangeStr string) ([]string, error) {
	return parseIPRangeString(rangeStr, tp.options.MaxTargets)
}

// parseSubnet8 解析/8网段的IP地址，生成采样IP列表
func (tp *TargetParser) parseSubnet8(subnet string) []string {
	// 去除CIDR后缀获取基础IP
	baseIP := subnet[:len(subnet)-2]
	if net.ParseIP(baseIP) == nil {
		return nil
	}

	// 获取/8网段的第一段
	firstOctet := strings.Split(baseIP, ".")[0]
	var sampleIPs []string

	// 对常用网段进行更全面的扫描
	commonSecondOctets := GetCommonSecondOctets()

	// 对于每个选定的第二段，采样部分第三段
	for _, secondOctet := range commonSecondOctets {
		for thirdOctet := 0; thirdOctet < 256; thirdOctet += Subnet8ThirdOctetStep {
			// 添加常见的网关和服务器IP
			sampleIPs = append(sampleIPs, fmt.Sprintf("%s.%d.%d.%d", firstOctet, secondOctet, thirdOctet, DefaultGatewayLastOctet)) // 默认网关
			sampleIPs = append(sampleIPs, fmt.Sprintf("%s.%d.%d.%d", firstOctet, secondOctet, thirdOctet, RouterSwitchLastOctet))   // 通常用于路由器/交换机

			// 随机采样不同范围的主机IP
			fourthOctet := tp.randomInt(SamplingMinHost, SamplingMaxHost)
			sampleIPs = append(sampleIPs, fmt.Sprintf("%s.%d.%d.%d", firstOctet, secondOctet, thirdOctet, fourthOctet))
		}
	}

	// 对其他二级网段进行稀疏采样
	for secondOctet := 0; secondOctet < 256; secondOctet += Subnet8SamplingStep {
		for thirdOctet := 0; thirdOctet < 256; thirdOctet += Subnet8SamplingStep {
			// 对于采样的网段，取几个代表性IP
			sampleIPs = append(sampleIPs, fmt.Sprintf("%s.%d.%d.%d", firstOctet, secondOctet, thirdOctet, DefaultGatewayLastOctet))
			sampleIPs = append(sampleIPs, fmt.Sprintf("%s.%d.%d.%d", firstOctet, secondOctet, thirdOctet, tp.randomInt(SamplingMinHost, SamplingMaxHost)))
		}
	}

	// 限制采样数量
	if len(sampleIPs) > tp.options.MaxTargets {
		sampleIPs = sampleIPs[:tp.options.MaxTargets]
	}

	return sampleIPs
}

// randomInt 生成指定范围内的随机整数
func (tp *TargetParser) randomInt(min, max int) int {
	if min >= max || min < 0 || max <= 0 {
		return max
	}
	return min + (max-min)/2 // 简化版本，避免依赖rand
}

// parsePortRange 解析端口范围
func (tp *TargetParser) parsePortRange(rangeStr string) ([]int, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("无效的端口范围格式")
	}

	startPort, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	endPort, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))

	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("无效的端口号")
	}

	if startPort > endPort {
		startPort, endPort = endPort, startPort
	}

	if startPort < MinPort || endPort > MaxPort {
		return nil, fmt.Errorf("端口号超出范围")
	}

	var ports []int
	for port := startPort; port <= endPort; port++ {
		ports = append(ports, port)
	}

	return ports, nil
}

// validateHost 验证主机地址
func (tp *TargetParser) validateHost(host string) (bool, error) {
	if host == "" {
		return false, fmt.Errorf("主机地址为空")
	}

	// 检查是否为host:port格式
	if strings.Contains(host, ":") {
		// 可能是host:port格式，尝试分离
		if h, portStr, err := net.SplitHostPort(host); err == nil {
			// 验证端口号
			if port, portErr := strconv.Atoi(portStr); portErr == nil && port >= MinPort && port <= MaxPort {
				// 递归验证主机部分（不包含端口）
				return tp.validateHost(h)
			}
		}
		// 如果不是有效的host:port格式，继续按普通主机地址处理
	}

	// 检查是否为IP地址
	if ip := net.ParseIP(host); ip != nil {
		return tp.validateIP(ip)
	}

	// 检查是否为域名
	if tp.isValidDomain(host) {
		return true, nil
	}

	return false, fmt.Errorf("无效的主机地址格式")
}

// validateIP 验证IP地址
func (tp *TargetParser) validateIP(ip net.IP) (bool, error) {
	if ip == nil {
		return false, fmt.Errorf("IP地址为空")
	}

	// 检查是否为私有IP
	if !tp.options.AllowPrivateIPs && tp.isPrivateIP(ip) {
		return false, fmt.Errorf("不允许私有IP地址")
	}

	// 检查是否为回环地址
	if !tp.options.AllowLoopback && ip.IsLoopback() {
		return false, fmt.Errorf("不允许回环地址")
	}

	return true, nil
}

// validateURL 验证URL
func (tp *TargetParser) validateURL(rawURL string) (bool, error) {
	if rawURL == "" {
		return false, fmt.Errorf("URL为空")
	}

	if !tp.options.ValidateURLs {
		return true, nil
	}

	if !tp.urlRegex.MatchString(rawURL) {
		return false, fmt.Errorf("URL格式无效")
	}

	// 进一步验证URL格式
	_, err := url.Parse(rawURL)
	if err != nil {
		return false, fmt.Errorf("URL解析失败: %w", err)
	}

	return true, nil
}

// validateHostPort 验证主机端口组合
func (tp *TargetParser) validateHostPort(hostPort string) (bool, error) {
	parts := strings.Split(hostPort, ":")
	if len(parts) != 2 {
		return false, fmt.Errorf("主机端口格式无效，应为 host:port")
	}

	host := strings.TrimSpace(parts[0])
	portStr := strings.TrimSpace(parts[1])

	// 验证主机
	if valid, err := tp.validateHost(host); !valid {
		return false, fmt.Errorf("主机无效: %w", err)
	}

	// 验证端口
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false, fmt.Errorf("端口号无效: %s", portStr)
	}

	if port < MinPort || port > MaxPort {
		return false, fmt.Errorf("端口号超出范围: %d", port)
	}

	return true, nil
}

// isPrivateIP 检查是否为私有IP
func (tp *TargetParser) isPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= Private172StartSecondOctet && ip4[1] <= Private172EndSecondOctet {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == Private192SecondOctet {
			return true
		}
	}
	return false
}

// isValidDomain 检查是否为有效域名
func (tp *TargetParser) isValidDomain(domain string) bool {
	return CompiledDomainRegex.MatchString(domain) && len(domain) <= MaxDomainLength
}

// excludeHosts 排除指定主机
func (tp *TargetParser) excludeHosts(hosts, excludeList []string) []string {
	excludeMap := make(map[string]struct{})
	for _, exclude := range excludeList {
		excludeMap[exclude] = struct{}{}
	}

	var result []string
	for _, host := range hosts {
		if _, excluded := excludeMap[host]; !excluded {
			result = append(result, host)
		}
	}

	return result
}

// removeDuplicateStrings 去重字符串切片
func (tp *TargetParser) removeDuplicateStrings(slice []string) []string {
	seen := make(map[string]struct{})
	var result []string

	for _, item := range slice {
		if _, exists := seen[item]; !exists {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}

// removeDuplicatePorts 去重端口切片
func (tp *TargetParser) removeDuplicatePorts(slice []int) []int {
	seen := make(map[int]struct{})
	var result []int

	for _, item := range slice {
		if _, exists := seen[item]; !exists {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}

// =============================================================================
// 包级共享辅助函数（供 simple.go 和 target_parser.go 共用）
// =============================================================================

// incrementIP 计算下一个IP地址（统一的包级函数）
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// parseIPCIDR 解析CIDR网段（包级函数）
func parseIPCIDR(cidr string, maxTargets int) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	ip := make(net.IP, len(ipNet.IP))
	copy(ip, ipNet.IP)

	count := 0
	for ipNet.Contains(ip) {
		ips = append(ips, ip.String())
		count++

		// 防止生成过多IP
		if count >= maxTargets {
			break
		}

		incrementIP(ip)
	}

	// 移除网络地址和广播地址
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

// parseIPRangeString 解析IP范围字符串（包级函数）
func parseIPRangeString(rangeStr string, maxTargets int) ([]string, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("无效的IP范围格式: %s", rangeStr)
	}

	startIPStr := strings.TrimSpace(parts[0])
	endIPStr := strings.TrimSpace(parts[1])

	// 验证起始IP
	startIP := net.ParseIP(startIPStr)
	if startIP == nil {
		return nil, fmt.Errorf("无效的起始IP地址: %s", startIPStr)
	}

	// 处理简写格式 (如: 192.168.1.1-100)
	if len(endIPStr) < 4 || !strings.Contains(endIPStr, ".") {
		return parseIPShortRange(startIPStr, endIPStr)
	}

	// 处理完整格式 (如: 192.168.1.1-192.168.1.100)
	endIP := net.ParseIP(endIPStr)
	if endIP == nil {
		return nil, fmt.Errorf("无效的结束IP地址: %s", endIPStr)
	}

	return parseIPFullRange(startIP, endIP, maxTargets)
}

// parseIPShortRange 解析短格式IP范围（包级函数）
func parseIPShortRange(startIPStr, endSuffix string) ([]string, error) {
	// 将结束段转换为数字
	endNum, err := strconv.Atoi(endSuffix)
	if err != nil || endNum > MaxIPv4OctetValue {
		return nil, fmt.Errorf("无效的IP范围结束值: %s", endSuffix)
	}

	// 分解起始IP
	ipParts := strings.Split(startIPStr, ".")
	if len(ipParts) != IPv4OctetCount {
		return nil, fmt.Errorf("无效的IP地址格式: %s", startIPStr)
	}

	// 获取前缀和起始IP的最后一部分
	prefixIP := strings.Join(ipParts[0:3], ".")
	startNum, err := strconv.Atoi(ipParts[3])
	if err != nil || startNum > endNum {
		return nil, fmt.Errorf("无效的IP范围: %s-%s", startIPStr, endSuffix)
	}

	// 生成IP范围
	var allIP []string
	for i := startNum; i <= endNum; i++ {
		allIP = append(allIP, fmt.Sprintf("%s.%d", prefixIP, i))
	}

	return allIP, nil
}

// parseIPFullRange 解析完整格式的IP范围（包级函数）
func parseIPFullRange(startIP, endIP net.IP, maxTargets int) ([]string, error) {
	// 转换为IPv4
	start4 := startIP.To4()
	end4 := endIP.To4()
	if start4 == nil || end4 == nil {
		return nil, fmt.Errorf("仅支持IPv4地址范围")
	}

	// 计算IP地址的整数表示
	startInt := (int(start4[0]) << IPFirstOctetShift) | (int(start4[1]) << IPSecondOctetShift) | (int(start4[2]) << IPThirdOctetShift) | int(start4[3])
	endInt := (int(end4[0]) << IPFirstOctetShift) | (int(end4[1]) << IPSecondOctetShift) | (int(end4[2]) << IPThirdOctetShift) | int(end4[3])

	if startInt > endInt {
		return nil, fmt.Errorf("起始IP大于结束IP")
	}

	// 生成IP列表
	var ips []string
	current := make(net.IP, len(start4))
	copy(current, start4)

	count := 0
	for {
		ips = append(ips, current.String())
		count++

		if current.Equal(end4) || count >= maxTargets {
			break
		}

		incrementIP(current)
	}

	return ips, nil
}

// =============================================================================================
// 已删除的死代码（未使用）：Validate 和 GetStatistics 方法
// =============================================================================================
