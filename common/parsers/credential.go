package parsers

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common/config"
	"github.com/shadow1ng/fscan/common/i18n"
)

// CredentialParser 凭据解析器
type CredentialParser struct {
	fileReader *FileReader
	mu         sync.RWMutex //nolint:unused // reserved for future thread safety
	hashRegex  *regexp.Regexp
	options    *CredentialParserOptions
}

// CredentialParserOptions 凭据解析器选项
type CredentialParserOptions struct {
	MaxUsernameLength    int  `json:"max_username_length"`
	MaxPasswordLength    int  `json:"max_password_length"`
	AllowEmptyPasswords  bool `json:"allow_empty_passwords"`
	ValidateHashes       bool `json:"validate_hashes"`
	DeduplicateUsers     bool `json:"deduplicate_users"`
	DeduplicatePasswords bool `json:"deduplicate_passwords"`
}

// DefaultCredentialParserOptions 默认凭据解析器选项
func DefaultCredentialParserOptions() *CredentialParserOptions {
	return &CredentialParserOptions{
		MaxUsernameLength:    DefaultMaxUsernameLength,
		MaxPasswordLength:    DefaultMaxPasswordLength,
		AllowEmptyPasswords:  DefaultAllowEmptyPasswords,
		ValidateHashes:       DefaultValidateHashes,
		DeduplicateUsers:     DefaultDeduplicateUsers,
		DeduplicatePasswords: DefaultDeduplicatePasswords,
	}
}

// NewCredentialParser 创建凭据解析器
func NewCredentialParser(fileReader *FileReader, options *CredentialParserOptions) *CredentialParser {
	if options == nil {
		options = DefaultCredentialParserOptions()
	}

	// 编译哈希验证正则表达式 (MD5: 32位十六进制)
	hashRegex := CompiledHashRegex

	return &CredentialParser{
		fileReader: fileReader,
		hashRegex:  hashRegex,
		options:    options,
	}
}

// CredentialInput 凭据输入参数
type CredentialInput struct {
	// 直接输入
	Username     string `json:"username"`
	Password     string `json:"password"`
	AddUsers     string `json:"add_users"`
	AddPasswords string `json:"add_passwords"`
	HashValue    string `json:"hash_value"`
	SSHKeyPath   string `json:"ssh_key_path"`
	Domain       string `json:"domain"`

	// 文件输入
	UsersFile     string `json:"users_file"`
	PasswordsFile string `json:"passwords_file"`
	UserPassFile  string `json:"user_pass_file"` // 用户名:密码对文件
	HashFile      string `json:"hash_file"`
}

// Parse 解析凭据配置
func (cp *CredentialParser) Parse(input *CredentialInput, options *ParserOptions) (*ParseResult, error) {
	if input == nil {
		return nil, NewParseError(ErrorTypeInputError, "凭据输入为空", "", 0, ErrEmptyInput)
	}

	startTime := time.Now()
	result := &ParseResult{
		Config: &ParsedConfig{
			Credentials: &CredentialConfig{
				SSHKeyPath: input.SSHKeyPath,
				Domain:     input.Domain,
			},
		},
		Success: true,
	}

	var errors []error
	var warnings []string

	// 解析用户名
	usernames, userErrors, userWarnings := cp.parseUsernames(input)
	errors = append(errors, userErrors...)
	warnings = append(warnings, userWarnings...)

	// 解析密码
	passwords, passErrors, passWarnings := cp.parsePasswords(input)
	errors = append(errors, passErrors...)
	warnings = append(warnings, passWarnings...)

	// 解析哈希值
	hashValues, hashBytes, hashErrors, hashWarnings := cp.parseHashes(input)
	errors = append(errors, hashErrors...)
	warnings = append(warnings, hashWarnings...)

	// 解析用户密码对
	userPassPairs, pairErrors, pairWarnings := cp.parseUserPassPairs(input)
	errors = append(errors, pairErrors...)
	warnings = append(warnings, pairWarnings...)

	// 更新配置
	result.Config.Credentials.Usernames = usernames
	result.Config.Credentials.Passwords = passwords
	result.Config.Credentials.UserPassPairs = userPassPairs
	result.Config.Credentials.HashValues = hashValues
	result.Config.Credentials.HashBytes = hashBytes

	// 设置结果状态
	result.Errors = errors
	result.Warnings = warnings
	result.ParseTime = time.Since(startTime)
	result.Success = len(errors) == 0

	return result, nil
}

// parseUsernames 解析用户名
func (cp *CredentialParser) parseUsernames(input *CredentialInput) ([]string, []error, []string) {
	var usernames []string
	var errors []error
	var warnings []string

	// 解析命令行用户名
	if input.Username != "" {
		users := strings.Split(input.Username, ",")
		for _, user := range users {
			if processedUser, valid, err := cp.validateUsername(strings.TrimSpace(user)); valid {
				usernames = append(usernames, processedUser)
			} else if err != nil {
				errors = append(errors, NewParseError(ErrorTypeUsernameError, err.Error(), "command line", 0, err))
			}
		}
	}

	// 从文件读取用户名
	if input.UsersFile != "" {
		fileResult, err := cp.fileReader.ReadFile(input.UsersFile)
		if err != nil {
			errors = append(errors, NewParseError(ErrorTypeFileError, "读取用户名文件失败", input.UsersFile, 0, err))
		} else {
			for i, line := range fileResult.Lines {
				if processedUser, valid, err := cp.validateUsername(line); valid {
					usernames = append(usernames, processedUser)
				} else if err != nil {
					warnings = append(warnings, fmt.Sprintf("用户名文件第%d行无效: %s", i+1, err.Error()))
				}
			}
		}
	}

	// 处理额外用户名
	if input.AddUsers != "" {
		extraUsers := strings.Split(input.AddUsers, ",")
		for _, user := range extraUsers {
			if processedUser, valid, err := cp.validateUsername(strings.TrimSpace(user)); valid {
				usernames = append(usernames, processedUser)
			} else if err != nil {
				warnings = append(warnings, fmt.Sprintf("额外用户名无效: %s", err.Error()))
			}
		}
	}

	// 去重
	if cp.options.DeduplicateUsers {
		usernames = cp.removeDuplicateStrings(usernames)
	}

	return usernames, errors, warnings
}

// parsePasswords 解析密码
func (cp *CredentialParser) parsePasswords(input *CredentialInput) ([]string, []error, []string) {
	var passwords []string
	var errors []error
	var warnings []string

	// 解析命令行密码
	if input.Password != "" {
		passes := strings.Split(input.Password, ",")
		for _, pass := range passes {
			if processedPass, valid, err := cp.validatePassword(pass); valid {
				passwords = append(passwords, processedPass)
			} else if err != nil {
				errors = append(errors, NewParseError(ErrorTypePasswordError, err.Error(), "command line", 0, err))
			}
		}
	}

	// 从文件读取密码
	if input.PasswordsFile != "" {
		fileResult, err := cp.fileReader.ReadFile(input.PasswordsFile)
		if err != nil {
			errors = append(errors, NewParseError(ErrorTypeFileError, "读取密码文件失败", input.PasswordsFile, 0, err))
		} else {
			for i, line := range fileResult.Lines {
				if processedPass, valid, err := cp.validatePassword(line); valid {
					passwords = append(passwords, processedPass)
				} else if err != nil {
					warnings = append(warnings, fmt.Sprintf("密码文件第%d行无效: %s", i+1, err.Error()))
				}
			}
		}
	}

	// 处理额外密码
	if input.AddPasswords != "" {
		extraPasses := strings.Split(input.AddPasswords, ",")
		for _, pass := range extraPasses {
			if processedPass, valid, err := cp.validatePassword(pass); valid {
				passwords = append(passwords, processedPass)
			} else if err != nil {
				warnings = append(warnings, fmt.Sprintf("额外密码无效: %s", err.Error()))
			}
		}
	}

	// 去重
	if cp.options.DeduplicatePasswords {
		passwords = cp.removeDuplicateStrings(passwords)
	}

	return passwords, errors, warnings
}

// parseHashes 解析哈希值
func (cp *CredentialParser) parseHashes(input *CredentialInput) ([]string, [][]byte, []error, []string) {
	var hashValues []string
	var hashBytes [][]byte
	var errors []error
	var warnings []string

	// 解析单个哈希值
	if input.HashValue != "" {
		if valid, err := cp.validateHash(input.HashValue); valid {
			hashValues = append(hashValues, input.HashValue)
		} else {
			errors = append(errors, NewParseError(ErrorTypeHashError, err.Error(), "command line", 0, err))
		}
	}

	// 从文件读取哈希值
	if input.HashFile != "" {
		fileResult, err := cp.fileReader.ReadFile(input.HashFile)
		if err != nil {
			errors = append(errors, NewParseError(ErrorTypeFileError, "读取哈希文件失败", input.HashFile, 0, err))
		} else {
			for i, line := range fileResult.Lines {
				if valid, err := cp.validateHash(line); valid {
					hashValues = append(hashValues, line)
				} else {
					warnings = append(warnings, fmt.Sprintf("哈希文件第%d行无效: %s", i+1, err.Error()))
				}
			}
		}
	}

	// 转换哈希值为字节数组
	for _, hash := range hashValues {
		if hashByte, err := hex.DecodeString(hash); err == nil {
			hashBytes = append(hashBytes, hashByte)
		} else {
			warnings = append(warnings, fmt.Sprintf("哈希值解码失败: %s", hash))
		}
	}

	return hashValues, hashBytes, errors, warnings
}

// validateUsername 验证用户名
func (cp *CredentialParser) validateUsername(username string) (string, bool, error) {
	if len(username) == 0 {
		return "", false, nil // 允许空用户名，但不添加到列表
	}

	if len(username) > cp.options.MaxUsernameLength {
		return "", false, fmt.Errorf("username length %d exceeds maximum %d", len(username), cp.options.MaxUsernameLength)
	}

	// 检查特殊字符
	if strings.ContainsAny(username, InvalidUsernameChars) {
		return "", false, fmt.Errorf("%s", i18n.GetText("parser_username_invalid_chars"))
	}

	return username, true, nil
}

// validatePassword 验证密码
func (cp *CredentialParser) validatePassword(password string) (string, bool, error) {
	if len(password) == 0 && !cp.options.AllowEmptyPasswords {
		return "", false, fmt.Errorf("%s", i18n.GetText("parser_password_empty"))
	}

	if len(password) > cp.options.MaxPasswordLength {
		return "", false, fmt.Errorf("password length %d exceeds maximum %d", len(password), cp.options.MaxPasswordLength)
	}

	return password, true, nil
}

// validateHash 验证哈希值
func (cp *CredentialParser) validateHash(hash string) (bool, error) {
	if !cp.options.ValidateHashes {
		return true, nil
	}

	hash = strings.TrimSpace(hash)
	if len(hash) == 0 {
		return false, fmt.Errorf("%s", i18n.GetText("parser_hash_empty"))
	}

	if !cp.hashRegex.MatchString(hash) {
		return false, fmt.Errorf("%s", i18n.GetText("parser_hash_invalid_format"))
	}

	return true, nil
}

// removeDuplicateStrings 去重字符串切片
func (cp *CredentialParser) removeDuplicateStrings(slice []string) []string {
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

// parseUserPassPairs 解析用户名密码对
func (cp *CredentialParser) parseUserPassPairs(input *CredentialInput) ([]config.CredentialPair, []error, []string) {
	var pairs []config.CredentialPair
	var errors []error
	var warnings []string

	// 如果命令行同时指定了单个用户名和单个密码（不是逗号分隔的多个），
	// 将其视为精确的用户密码对，而不是做笛卡尔积
	if input.Username != "" && input.Password != "" &&
		!strings.Contains(input.Username, ",") && !strings.Contains(input.Password, ",") &&
		input.UsersFile == "" && input.PasswordsFile == "" && input.UserPassFile == "" {
		pairs = append(pairs, config.CredentialPair{
			Username: strings.TrimSpace(input.Username),
			Password: input.Password, // 密码不trim，可能包含空格
		})
		return pairs, errors, warnings
	}

	if input.UserPassFile == "" {
		return pairs, errors, warnings
	}

	fileResult, err := cp.fileReader.ReadFile(input.UserPassFile)
	if err != nil {
		errors = append(errors, NewParseError(ErrorTypeFileError, "读取用户密码对文件失败", input.UserPassFile, 0, err))
		return pairs, errors, warnings
	}

	for i, line := range fileResult.Lines {
		// 只在第一个 : 处分割，后面的都是密码部分
		idx := strings.Index(line, ":")
		if idx == -1 {
			warnings = append(warnings, fmt.Sprintf("用户密码对文件第%d行格式错误，缺少冒号分隔符: %s", i+1, line))
			continue
		}

		user := strings.TrimSpace(line[:idx])
		pass := line[idx+1:] // 密码不 trim，可能包含空格

		if user == "" {
			warnings = append(warnings, fmt.Sprintf("用户密码对文件第%d行用户名为空", i+1))
			continue
		}

		// 验证用户名
		if _, valid, err := cp.validateUsername(user); !valid {
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("用户密码对文件第%d行用户名无效: %s", i+1, err.Error()))
			}
			continue
		}

		// 验证密码
		if _, valid, err := cp.validatePassword(pass); !valid {
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("用户密码对文件第%d行密码无效: %s", i+1, err.Error()))
			}
			continue
		}

		pairs = append(pairs, config.CredentialPair{
			Username: user,
			Password: pass,
		})
	}

	return pairs, errors, warnings
}

// =============================================================================================
// 已删除的死代码（未使用）：Validate 和 GetStatistics 方法
// =============================================================================================
