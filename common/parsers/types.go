package parsers

import (
	"errors"
	"fmt"
	"time"

	"github.com/shadow1ng/fscan/common/config"
	"github.com/shadow1ng/fscan/common/i18n"
)

// ParsedConfig 解析后的完整配置
type ParsedConfig struct {
	Targets     *TargetConfig     `json:"targets"`
	Credentials *CredentialConfig `json:"credentials"`
	Network     *NetworkConfig    `json:"network"`
	Validation  *ValidationConfig `json:"validation"`
}

// TargetConfig 目标配置
type TargetConfig struct {
	Hosts        []string `json:"hosts"`
	URLs         []string `json:"urls"`
	Ports        []int    `json:"ports"`
	ExcludePorts []int    `json:"exclude_ports"`
	HostPorts    []string `json:"host_ports"`
	LocalMode    bool     `json:"local_mode"`
}

// CredentialConfig 认证配置
type CredentialConfig struct {
	Usernames     []string                `json:"usernames"`
	Passwords     []string                `json:"passwords"`
	UserPassPairs []config.CredentialPair `json:"user_pass_pairs,omitempty"` // 精确的用户密码对
	HashValues    []string                `json:"hash_values"`
	HashBytes     [][]byte                `json:"hash_bytes,omitempty"`
	SSHKeyPath    string                  `json:"ssh_key_path"`
	Domain        string                  `json:"domain"`
}

// NetworkConfig 网络配置
type NetworkConfig struct {
	HTTPProxy    string        `json:"http_proxy"`
	Socks5Proxy  string        `json:"socks5_proxy"`
	Timeout      time.Duration `json:"timeout"`
	WebTimeout   time.Duration `json:"web_timeout"`
	DisablePing  bool          `json:"disable_ping"`
	EnableDNSLog bool          `json:"enable_dns_log"`
	UserAgent    string        `json:"user_agent"`
	Cookie       string        `json:"cookie"`
}

// ValidationConfig 验证配置
type ValidationConfig struct {
	ScanMode        string   `json:"scan_mode"`
	ConflictChecked bool     `json:"conflict_checked"`
	Errors          []error  `json:"errors,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
}

// ParseResult 解析结果
type ParseResult struct {
	Config    *ParsedConfig `json:"config"`
	Success   bool          `json:"success"`
	Errors    []error       `json:"errors,omitempty"`
	Warnings  []string      `json:"warnings,omitempty"`
	ParseTime time.Duration `json:"parse_time"`
}

// 预定义错误类型
var (
	ErrEmptyInput = errors.New(i18n.GetText("parser_empty_input"))
)

// ParserOptions 解析器选项
type ParserOptions struct {
	EnableConcurrency bool          // 启用并发解析
	MaxWorkers        int           // 最大工作协程数
	Timeout           time.Duration // 解析超时时间
	EnableValidation  bool          // 启用详细验证
	IgnoreErrors      bool          // 忽略非致命错误
	FileMaxSize       int64         // 文件最大大小限制
	MaxTargets        int           // 最大目标数量限制
}

// DefaultParserOptions 返回默认解析器选项
func DefaultParserOptions() *ParserOptions {
	return &ParserOptions{
		EnableConcurrency: DefaultEnableConcurrency,
		MaxWorkers:        DefaultMaxWorkers,
		Timeout:           DefaultTimeout,
		EnableValidation:  DefaultEnableValidation,
		IgnoreErrors:      DefaultIgnoreErrors,
		FileMaxSize:       DefaultFileMaxSize,
		MaxTargets:        DefaultMaxTargets,
	}
}

// Parser 解析器接口
type Parser interface {
	Parse(options *ParserOptions) (*ParseResult, error)
	Validate() error
}

// FileSource 文件源
type FileSource struct {
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	ModTime    time.Time `json:"mod_time"`
	LineCount  int       `json:"line_count"`
	ValidLines int       `json:"valid_lines"`
}

// ParseError 解析错误，包含详细上下文
type ParseError struct {
	Type     string `json:"type"`
	Message  string `json:"message"`
	Source   string `json:"source"`
	Line     int    `json:"line,omitempty"`
	Context  string `json:"context,omitempty"`
	Original error  `json:"original,omitempty"`
}

func (e *ParseError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%s:%d - %s: %s", e.Source, e.Line, e.Type, e.Message)
	}
	return fmt.Sprintf("%s - %s: %s", e.Source, e.Type, e.Message)
}

// NewParseError 创建解析错误
func NewParseError(errType, message, source string, line int, original error) *ParseError {
	return &ParseError{
		Type:     errType,
		Message:  message,
		Source:   source,
		Line:     line,
		Original: original,
	}
}
