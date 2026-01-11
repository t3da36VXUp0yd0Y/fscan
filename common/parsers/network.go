package parsers

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common/i18n"
)

// NetworkParser 网络配置解析器
type NetworkParser struct {
	mu      sync.RWMutex //nolint:unused // reserved for future thread safety
	options *NetworkParserOptions
}

// NetworkParserOptions 网络解析器选项
type NetworkParserOptions struct {
	ValidateProxies   bool          `json:"validate_proxies"`
	AllowInsecure     bool          `json:"allow_insecure"`
	DefaultTimeout    time.Duration `json:"default_timeout"`
	DefaultWebTimeout time.Duration `json:"default_web_timeout"`
	DefaultUserAgent  string        `json:"default_user_agent"`
}

// DefaultNetworkParserOptions 默认网络解析器选项
func DefaultNetworkParserOptions() *NetworkParserOptions {
	return &NetworkParserOptions{
		ValidateProxies:   DefaultValidateProxies,
		AllowInsecure:     DefaultAllowInsecure,
		DefaultTimeout:    DefaultNetworkTimeout,
		DefaultWebTimeout: DefaultWebTimeout,
		DefaultUserAgent:  DefaultUserAgent,
	}
}

// NewNetworkParser 创建网络配置解析器
func NewNetworkParser(options *NetworkParserOptions) *NetworkParser {
	if options == nil {
		options = DefaultNetworkParserOptions()
	}

	return &NetworkParser{
		options: options,
	}
}

// NetworkInput 网络配置输入参数
type NetworkInput struct {
	// 代理配置
	HTTPProxy   string `json:"http_proxy"`
	Socks5Proxy string `json:"socks5_proxy"`

	// 超时配置
	Timeout    int64 `json:"timeout"`
	WebTimeout int64 `json:"web_timeout"`

	// 网络选项
	DisablePing bool   `json:"disable_ping"`
	DNSLog      bool   `json:"dns_log"`
	UserAgent   string `json:"user_agent"`
	Cookie      string `json:"cookie"`
}

// Parse 解析网络配置
func (np *NetworkParser) Parse(input *NetworkInput, options *ParserOptions) (*ParseResult, error) {
	if input == nil {
		return nil, NewParseError("INPUT_ERROR", "网络配置输入为空", "", 0, ErrEmptyInput)
	}

	startTime := time.Now()
	result := &ParseResult{
		Config: &ParsedConfig{
			Network: &NetworkConfig{
				EnableDNSLog: input.DNSLog,
				DisablePing:  input.DisablePing,
			},
		},
		Success: true,
	}

	var errors []error
	var warnings []string

	// 解析HTTP代理
	httpProxy, httpErrors, httpWarnings := np.parseHTTPProxy(input.HTTPProxy)
	errors = append(errors, httpErrors...)
	warnings = append(warnings, httpWarnings...)

	// 解析Socks5代理
	socks5Proxy, socks5Errors, socks5Warnings := np.parseSocks5Proxy(input.Socks5Proxy)
	errors = append(errors, socks5Errors...)
	warnings = append(warnings, socks5Warnings...)

	// 解析超时配置
	timeout, webTimeout, timeoutErrors, timeoutWarnings := np.parseTimeouts(input.Timeout, input.WebTimeout)
	errors = append(errors, timeoutErrors...)
	warnings = append(warnings, timeoutWarnings...)

	// 解析用户代理
	userAgent, uaErrors, uaWarnings := np.parseUserAgent(input.UserAgent)
	errors = append(errors, uaErrors...)
	warnings = append(warnings, uaWarnings...)

	// 解析Cookie
	cookie, cookieErrors, cookieWarnings := np.parseCookie(input.Cookie)
	errors = append(errors, cookieErrors...)
	warnings = append(warnings, cookieWarnings...)

	// 检查代理冲突
	if httpProxy != "" && socks5Proxy != "" {
		warnings = append(warnings, "同时配置了HTTP代理和Socks5代理，Socks5代理将被优先使用")
	}

	// 更新配置
	result.Config.Network.HTTPProxy = httpProxy
	result.Config.Network.Socks5Proxy = socks5Proxy
	result.Config.Network.Timeout = timeout
	result.Config.Network.WebTimeout = webTimeout
	result.Config.Network.UserAgent = userAgent
	result.Config.Network.Cookie = cookie

	// 设置结果状态
	result.Errors = errors
	result.Warnings = warnings
	result.ParseTime = time.Since(startTime)
	result.Success = len(errors) == 0

	return result, nil
}

// parseHTTPProxy 解析HTTP代理配置
func (np *NetworkParser) parseHTTPProxy(proxyStr string) (string, []error, []string) {
	var errors []error
	var warnings []string

	if proxyStr == "" {
		return "", nil, nil
	}

	// 处理简写形式
	normalizedProxy := np.normalizeHTTPProxy(proxyStr)

	// 验证代理URL
	if np.options.ValidateProxies {
		if err := np.validateProxyURL(normalizedProxy); err != nil {
			errors = append(errors, NewParseError(ErrorTypeProxyError, err.Error(), "http_proxy", 0, err))
			return "", errors, warnings
		}
	}

	return normalizedProxy, errors, warnings
}

// parseSocks5Proxy 解析Socks5代理配置
func (np *NetworkParser) parseSocks5Proxy(proxyStr string) (string, []error, []string) {
	var errors []error
	var warnings []string

	if proxyStr == "" {
		return "", nil, nil
	}

	// 处理简写形式
	normalizedProxy := np.normalizeSocks5Proxy(proxyStr)

	// 验证代理URL
	if np.options.ValidateProxies {
		if err := np.validateProxyURL(normalizedProxy); err != nil {
			errors = append(errors, NewParseError(ErrorTypeProxyError, err.Error(), "socks5_proxy", 0, err))
			return "", errors, warnings
		}
	}

	// 使用Socks5代理时建议禁用Ping
	if normalizedProxy != "" {
		warnings = append(warnings, "使用Socks5代理时建议禁用Ping检测")
	}

	return normalizedProxy, errors, warnings
}

// parseTimeouts 解析超时配置
func (np *NetworkParser) parseTimeouts(timeout, webTimeout int64) (time.Duration, time.Duration, []error, []string) { //nolint:unparam
	var errors []error
	var warnings []string

	// 处理普通超时
	finalTimeout := np.options.DefaultTimeout
	if timeout > 0 {
		if timeout > MaxTimeoutSeconds {
			warnings = append(warnings, "超时时间过长，建议不超过300秒")
		}
		finalTimeout = time.Duration(timeout) * time.Second
	}

	// 处理Web超时
	finalWebTimeout := np.options.DefaultWebTimeout
	if webTimeout > 0 {
		if webTimeout > MaxWebTimeoutSeconds {
			warnings = append(warnings, "Web超时时间过长，建议不超过120秒")
		}
		finalWebTimeout = time.Duration(webTimeout) * time.Second
	}

	// 验证超时配置合理性：只有在Web超时显著大于普通超时时才警告
	// Web超时适当大于普通超时是合理的，因为Web请求包含更多步骤
	if finalWebTimeout > finalTimeout*2 {
		warnings = append(warnings, i18n.GetText("config_web_timeout_warning"))
	}

	return finalTimeout, finalWebTimeout, errors, warnings
}

// parseUserAgent 解析用户代理
func (np *NetworkParser) parseUserAgent(userAgent string) (string, []error, []string) {
	var errors []error
	var warnings []string

	if userAgent == "" {
		return np.options.DefaultUserAgent, errors, warnings
	}

	// 基本格式验证
	if len(userAgent) > MaxUserAgentLength {
		errors = append(errors, NewParseError(ErrorTypeUserAgentError, "用户代理字符串过长", "user_agent", 0, nil))
		return "", errors, warnings
	}

	// 检查是否包含特殊字符
	if strings.ContainsAny(userAgent, InvalidUserAgentChars) {
		errors = append(errors, NewParseError(ErrorTypeUserAgentError, "用户代理包含非法字符", "user_agent", 0, nil))
		return "", errors, warnings
	}

	// 检查是否为常见浏览器用户代理
	if !np.isValidUserAgent(userAgent) {
		warnings = append(warnings, "用户代理格式可能不被目标服务器识别")
	}

	return userAgent, errors, warnings
}

// parseCookie 解析Cookie
func (np *NetworkParser) parseCookie(cookie string) (string, []error, []string) {
	var errors []error
	var warnings []string

	if cookie == "" {
		return "", errors, warnings
	}

	// 基本格式验证
	if len(cookie) > MaxCookieLength { // HTTP Cookie长度限制
		errors = append(errors, NewParseError(ErrorTypeCookieError, "Cookie字符串过长", "cookie", 0, nil))
		return "", errors, warnings
	}

	// 检查Cookie格式
	if !np.isValidCookie(cookie) {
		warnings = append(warnings, "Cookie格式可能不正确")
	}

	return cookie, errors, warnings
}

// normalizeHTTPProxy 规范化HTTP代理URL
func (np *NetworkParser) normalizeHTTPProxy(proxy string) string {
	switch strings.ToLower(proxy) {
	case ProxyShortcut1:
		return ProxyShortcutHTTP
	case ProxyShortcut2:
		return ProxyShortcutSOCKS5
	default:
		// 如果没有协议前缀，默认使用HTTP
		if !strings.Contains(proxy, ProtocolPrefix) {
			if strings.Contains(proxy, ":") {
				return HTTPPrefix + proxy
			}
			return HTTPPrefix + "127.0.0.1:" + proxy
		}
		return proxy
	}
}

// normalizeSocks5Proxy 规范化Socks5代理URL
func (np *NetworkParser) normalizeSocks5Proxy(proxy string) string {
	// 如果没有协议前缀，添加SOCKS5协议
	if !strings.HasPrefix(proxy, SOCKS5Prefix) {
		if strings.Contains(proxy, ":") {
			return SOCKS5Prefix + proxy
		}
		return SOCKS5Prefix + "127.0.0.1:" + proxy
	}
	return proxy
}

// validateProxyURL 验证代理URL格式
func (np *NetworkParser) validateProxyURL(proxyURL string) error {
	if proxyURL == "" {
		return nil
	}

	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("代理URL格式无效: %w", err)
	}

	// 检查协议
	switch parsedURL.Scheme {
	case ProtocolHTTP, ProtocolHTTPS, ProtocolSOCKS5:
		// 支持的协议
	default:
		return fmt.Errorf("不支持的代理协议: %s", parsedURL.Scheme)
	}

	// 检查主机名
	if parsedURL.Hostname() == "" {
		return fmt.Errorf("代理主机名为空")
	}

	// 检查端口
	portStr := parsedURL.Port()
	if portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("代理端口号无效: %s", portStr)
		}
		if port < 1 || port > 65535 {
			return fmt.Errorf("代理端口号超出范围: %d", port)
		}
	}

	// 安全检查
	if !np.options.AllowInsecure && parsedURL.Scheme == ProtocolHTTP {
		return fmt.Errorf("不允许使用不安全的HTTP代理")
	}

	return nil
}

// isValidUserAgent 检查用户代理是否有效
func (np *NetworkParser) isValidUserAgent(userAgent string) bool {
	// 检查是否包含常见的浏览器标识
	commonBrowsers := GetCommonBrowsers()

	userAgentLower := strings.ToLower(userAgent)
	for _, browser := range commonBrowsers {
		if strings.Contains(userAgentLower, strings.ToLower(browser)) {
			return true
		}
	}

	return false
}

// isValidCookie 检查Cookie格式是否有效
func (np *NetworkParser) isValidCookie(cookie string) bool {
	// 基本Cookie格式检查 (name=value; name2=value2)
	return CompiledCookieRegex.MatchString(strings.TrimSpace(cookie))
}

// =============================================================================================
// 已删除的死代码（未使用）：Validate 和 GetStatistics 方法
// =============================================================================================
