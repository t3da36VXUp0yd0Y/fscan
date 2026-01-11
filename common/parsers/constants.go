package parsers

import (
	"regexp"
	"time"
)

/*
constants.go - 解析器系统常量定义

统一管理common/parsers包中的所有常量，便于查看和编辑。
*/

// =============================================================================
// 默认解析器选项常量 (从Types.go迁移)
// =============================================================================

const (
	// DefaultEnableConcurrency 解析器默认启用并发
	DefaultEnableConcurrency = true
	// DefaultMaxWorkers 默认最大工作线程数
	DefaultMaxWorkers = 4
	// DefaultTimeout 默认超时时间
	DefaultTimeout = 30 * time.Second
	// DefaultEnableValidation 默认启用验证
	DefaultEnableValidation = true
	// DefaultIgnoreErrors 默认不忽略错误
	DefaultIgnoreErrors = false
	// DefaultFileMaxSize 默认文件最大大小100MB
	DefaultFileMaxSize = 100 * 1024 * 1024
	// DefaultMaxTargets 默认最大目标数量10K
	DefaultMaxTargets = 10000
)

// =============================================================================
// 文件读取器常量 (从FileReader.go迁移)
// =============================================================================

const (
	// DefaultMaxCacheSize 默认最大缓存大小
	DefaultMaxCacheSize = 10
	// DefaultEnableCache 默认启用缓存
	DefaultEnableCache = true
	// DefaultFileReaderMaxFileSize 文件读取器默认最大文件大小50MB
	DefaultFileReaderMaxFileSize = 50 * 1024 * 1024
	// DefaultFileReaderTimeout 文件读取器默认超时时间
	DefaultFileReaderTimeout = 30 * time.Second
	// DefaultFileReaderEnableValidation 文件读取器默认启用验证
	DefaultFileReaderEnableValidation = true
	// DefaultTrimSpace 默认去除空格
	DefaultTrimSpace = true
	// DefaultSkipEmpty 默认跳过空行
	DefaultSkipEmpty = true
	// DefaultSkipComments 默认跳过注释
	DefaultSkipComments = true

	// MaxLineLength 单行最大字符数
	MaxLineLength = 1000
	// MaxValidRune 最小有效字符ASCII值
	MaxValidRune = 32
	// TabRune Tab字符
	TabRune = 9
	// NewlineRune 换行符
	NewlineRune = 10
	// CarriageReturnRune 回车符
	CarriageReturnRune = 13
	// CommentPrefix 注释前缀
	CommentPrefix = "#"
)

// =============================================================================
// 凭据解析器常量 (从CredentialParser.go迁移)
// =============================================================================

const (
	// DefaultMaxUsernameLength 凭据验证限制 - 默认最大用户名长度
	DefaultMaxUsernameLength = 64
	// DefaultMaxPasswordLength 默认最大密码长度
	DefaultMaxPasswordLength = 128
	// DefaultAllowEmptyPasswords 默认允许空密码
	DefaultAllowEmptyPasswords = true
	// DefaultValidateHashes 默认验证哈希
	DefaultValidateHashes = true
	// DefaultDeduplicateUsers 默认去重用户
	DefaultDeduplicateUsers = true
	// DefaultDeduplicatePasswords 默认去重密码
	DefaultDeduplicatePasswords = true

	// HashRegexPattern MD5哈希正则表达式
	HashRegexPattern = `^[a-fA-F0-9]{32}$`
	// HashValidationLength 有效哈希长度
	HashValidationLength = 32
	// InvalidUsernameChars 无效用户名字符
	InvalidUsernameChars = "\r\n\t"
)

// =============================================================================
// 网络解析器常量 (从NetworkParser.go迁移)
// =============================================================================

const (
	// DefaultValidateProxies 网络配置默认值 - 默认验证代理
	DefaultValidateProxies = true
	// DefaultAllowInsecure 默认不允许不安全连接
	DefaultAllowInsecure = false
	// DefaultNetworkTimeout 默认网络超时时间
	DefaultNetworkTimeout = 30 * time.Second
	// DefaultWebTimeout 默认Web超时时间
	DefaultWebTimeout = 10 * time.Second
	// DefaultUserAgent 默认用户代理字符串
	DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"

	// MaxTimeoutSeconds 超时限制 - 最大超时5分钟
	MaxTimeoutSeconds = 300
	// MaxWebTimeoutSeconds 最大Web超时2分钟
	MaxWebTimeoutSeconds = 120

	// MaxUserAgentLength 字符串长度限制 - 最大用户代理长度
	MaxUserAgentLength = 512
	// MaxCookieLength 最大Cookie长度
	MaxCookieLength = 4096

	// ProxyShortcut1 代理快捷配置 - 快捷方式1
	ProxyShortcut1 = "1"
	// ProxyShortcut2 快捷方式2
	ProxyShortcut2 = "2"
	// ProxyShortcutHTTP 快捷方式HTTP代理地址
	ProxyShortcutHTTP = "http://127.0.0.1:8080"
	// ProxyShortcutSOCKS5 快捷方式SOCKS5代理地址
	ProxyShortcutSOCKS5 = "socks5://127.0.0.1:1080"

	// ProtocolHTTP 协议支持 - HTTP协议
	ProtocolHTTP = "http"
	// ProtocolHTTPS HTTPS协议
	ProtocolHTTPS = "https"
	// ProtocolSOCKS5 SOCKS5协议
	ProtocolSOCKS5 = "socks5"
	// ProtocolPrefix 协议前缀分隔符
	ProtocolPrefix = "://"
	// SOCKS5Prefix SOCKS5协议前缀
	SOCKS5Prefix = "socks5://"
	// HTTPPrefix HTTP协议前缀
	HTTPPrefix = "http://"

	// MinPort 端口范围 - 最小端口号
	MinPort = 1
	// MaxPort 最大端口号
	MaxPort = 65535

	// InvalidUserAgentChars 无效字符集 - 用户代理中的非法字符
	InvalidUserAgentChars = "\r\n\t"
)

// GetCommonBrowsers 获取常见浏览器标识列表
func GetCommonBrowsers() []string {
	return []string{
		"Mozilla", "Chrome", "Safari", "Firefox", "Edge", "Opera",
		"AppleWebKit", "Gecko", "Trident", "Presto",
	}
}

// =============================================================================
// 目标解析器常量 (从TargetParser.go迁移)
// =============================================================================

const (
	// DefaultTargetMaxTargets 目标解析器默认配置 - 默认最大目标数量
	DefaultTargetMaxTargets = 10000
	// DefaultMaxPortRange 默认最大端口范围（支持全端口扫描）
	DefaultMaxPortRange = 65535
	// DefaultAllowPrivateIPs 默认允许私有IP
	DefaultAllowPrivateIPs = true
	// DefaultAllowLoopback 默认允许回环地址
	DefaultAllowLoopback = true
	// DefaultValidateURLs 默认验证URL
	DefaultValidateURLs = true
	// DefaultResolveDomains 默认解析域名
	DefaultResolveDomains = false

	// IPv4RegexPattern 正则表达式模式 - IPv4地址正则
	IPv4RegexPattern = `^(\d{1,3}\.){3}\d{1,3}$`
	// PortRangeRegexPattern 端口范围正则
	PortRangeRegexPattern = `^(\d+)(-(\d+))?$`
	// URLValidationRegexPattern URL验证正则
	URLValidationRegexPattern = `^https?://[^\s]+$`
	// DomainRegexPattern 域名正则
	DomainRegexPattern = `^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`
	// CookieRegexPattern Cookie正则
	CookieRegexPattern = `^[^=;\s]+(=[^;\s]*)?(\s*;\s*[^=;\s]+(=[^;\s]*)?)*$`

	// MaxIPv4OctetValue IP地址限制 - IPv4八位组最大值
	MaxIPv4OctetValue = 255
	// IPv4OctetCount IPv4八位组数量
	IPv4OctetCount = 4
	// MaxDomainLength 域名最大长度
	MaxDomainLength = 253

	// PrivateNetwork192 CIDR网段简写 - 192私有网络前缀
	PrivateNetwork192 = "192"
	// PrivateNetwork172 172私有网络前缀
	PrivateNetwork172 = "172"
	// PrivateNetwork10 10私有网络前缀
	PrivateNetwork10 = "10"
	// PrivateNetwork192CIDR 192私有网络CIDR
	PrivateNetwork192CIDR = "192.168.0.0/16"
	// PrivateNetwork172CIDR 172私有网络CIDR
	PrivateNetwork172CIDR = "172.16.0.0/12"
	// PrivateNetwork10CIDR 10私有网络CIDR
	PrivateNetwork10CIDR = "10.0.0.0/8"

	// Private172StartSecondOctet 私有网络范围 - 172网段起始第二段
	Private172StartSecondOctet = 16
	// Private172EndSecondOctet 172网段结束第二段
	Private172EndSecondOctet = 31
	// Private192SecondOctet 192网段第二段
	Private192SecondOctet = 168

	// Subnet8SamplingStep /8网段采样配置 - 采样步长
	Subnet8SamplingStep = 32
	// Subnet8ThirdOctetStep 第三段步长
	Subnet8ThirdOctetStep = 10

	// IPFirstOctetShift IP地址计算位移 - 第一段位移
	IPFirstOctetShift = 24
	// IPSecondOctetShift 第二段位移
	IPSecondOctetShift = 16
	// IPThirdOctetShift 第三段位移
	IPThirdOctetShift = 8
	// IPOctetMask 八位组掩码
	IPOctetMask = 0xFF
)

// GetCommonSecondOctets 获取常用第二段IP
func GetCommonSecondOctets() []int {
	return []int{0, 1, 2, 10, 100, 200, 254}
}

// =============================================================================
// 简化解析器常量 (从Simple.go迁移)
// =============================================================================

const (
	// SimpleMaxHosts 端口和主机限制 - 最大主机数量
	SimpleMaxHosts = 10000

	// DefaultGatewayLastOctet 网段简写展开 - 默认网关最后一段
	DefaultGatewayLastOctet = 1
	// RouterSwitchLastOctet 路由器/交换机最后一段
	RouterSwitchLastOctet = 254
	// SamplingMinHost 采样最小主机号
	SamplingMinHost = 2
	// SamplingMaxHost 采样最大主机号
	SamplingMaxHost = 253
)

// 端口组定义已迁移到 common/config/constants.go
// 此处保留引用函数以保持向后兼容

// =============================================================================
// 验证解析器常量 (从ValidationParser.go迁移)
// =============================================================================

const (
	// DefaultMaxErrorCount 验证解析器默认配置 - 默认最大错误数
	DefaultMaxErrorCount = 100
	// DefaultStrictMode 默认严格模式
	DefaultStrictMode = false
	// DefaultAllowEmpty 默认允许空值
	DefaultAllowEmpty = true
	// DefaultCheckConflicts 默认检查冲突
	DefaultCheckConflicts = true
	// DefaultValidateTargets 默认验证目标
	DefaultValidateTargets = true
	// DefaultValidateNetwork 默认验证网络配置
	DefaultValidateNetwork = true

	// MaxTargetsThreshold 性能警告阈值 - 最大目标数量阈值
	MaxTargetsThreshold = 100000
	// PortCountWarningThreshold 端口数量警告阈值（超过此值时警告）
	PortCountWarningThreshold = 5000
	// MinTimeoutThreshold 最小超时阈值
	MinTimeoutThreshold = 1 * time.Second
	// MaxTimeoutThreshold 最大超时阈值
	MaxTimeoutThreshold = 60 * time.Second
)

// =============================================================================
// 错误类型常量
// =============================================================================

const (
	// ErrorTypeInputError 解析错误类型 - 输入错误
	ErrorTypeInputError = "INPUT_ERROR"
	// ErrorTypeFileError 文件错误
	ErrorTypeFileError = "FILE_ERROR"
	// ErrorTypeTimeout 超时错误
	ErrorTypeTimeout = "TIMEOUT"
	// ErrorTypeReadError 读取错误
	ErrorTypeReadError = "READ_ERROR"
	// ErrorTypeUsernameError 用户名错误
	ErrorTypeUsernameError = "USERNAME_ERROR"
	// ErrorTypePasswordError 密码错误
	ErrorTypePasswordError = "PASSWORD_ERROR"
	// ErrorTypeHashError 哈希错误
	ErrorTypeHashError = "HASH_ERROR"
	// ErrorTypeProxyError 代理错误
	ErrorTypeProxyError = "PROXY_ERROR"
	// ErrorTypeUserAgentError 用户代理错误
	ErrorTypeUserAgentError = "USERAGENT_ERROR"
	// ErrorTypeCookieError Cookie错误
	ErrorTypeCookieError = "COOKIE_ERROR"
	// ErrorTypeHostError 主机错误
	ErrorTypeHostError = "HOST_ERROR"
	// ErrorTypePortError 端口错误
	ErrorTypePortError = "PORT_ERROR"
	// ErrorTypeExcludePortError 排除端口错误
	ErrorTypeExcludePortError = "EXCLUDE_PORT_ERROR"
)

// =============================================================================
// 编译时正则表达式
// =============================================================================

var (
	// CompiledHashRegex 预编译的正则表达式，提高性能 - MD5哈希正则
	CompiledHashRegex *regexp.Regexp
	// CompiledIPv4Regex IPv4地址正则
	CompiledIPv4Regex *regexp.Regexp
	// CompiledPortRegex 端口范围正则
	CompiledPortRegex *regexp.Regexp
	// CompiledURLRegex URL验证正则
	CompiledURLRegex *regexp.Regexp
	// CompiledDomainRegex 域名正则
	CompiledDomainRegex *regexp.Regexp
	// CompiledCookieRegex Cookie正则
	CompiledCookieRegex *regexp.Regexp
)

// 在包初始化时编译正则表达式
func init() {
	CompiledHashRegex = regexp.MustCompile(HashRegexPattern)
	CompiledIPv4Regex = regexp.MustCompile(IPv4RegexPattern)
	CompiledPortRegex = regexp.MustCompile(PortRangeRegexPattern)
	CompiledURLRegex = regexp.MustCompile(URLValidationRegexPattern)
	CompiledDomainRegex = regexp.MustCompile(DomainRegexPattern)
	CompiledCookieRegex = regexp.MustCompile(CookieRegexPattern)
}
