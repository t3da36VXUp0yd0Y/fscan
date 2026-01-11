package parsers

import (
	"strings"
	"testing"
)

// =============================================================================
// CredentialParser 构造函数测试
// =============================================================================

func TestNewCredentialParser(t *testing.T) {
	fileReader := NewFileReader(nil)

	tests := []struct {
		name    string
		options *CredentialParserOptions
		wantNil bool
	}{
		{
			name:    "使用默认选项",
			options: nil,
			wantNil: false,
		},
		{
			name: "使用自定义选项",
			options: &CredentialParserOptions{
				MaxUsernameLength:   32,
				MaxPasswordLength:   64,
				AllowEmptyPasswords: false,
			},
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewCredentialParser(fileReader, tt.options)

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
				if parser.hashRegex == nil {
					t.Error("parser.hashRegex为nil")
				}
			}
		})
	}
}

// =============================================================================
// Parse 主函数测试
// =============================================================================

func TestCredentialParser_Parse(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewCredentialParser(fileReader, nil)

	tests := []struct {
		name          string
		input         *CredentialInput
		wantSuccess   bool
		wantUsernames int
		wantPasswords int
		wantHashes    int
		wantError     bool
	}{
		{
			name:        "空输入",
			input:       nil,
			wantSuccess: false,
			wantError:   true,
		},
		{
			name: "单个用户名",
			input: &CredentialInput{
				Username: "admin",
			},
			wantSuccess:   true,
			wantUsernames: 1,
		},
		{
			name: "多个用户名（逗号分隔）",
			input: &CredentialInput{
				Username: "admin,root,user",
			},
			wantSuccess:   true,
			wantUsernames: 3,
		},
		{
			name: "单个密码",
			input: &CredentialInput{
				Password: "password123",
			},
			wantSuccess:   true,
			wantPasswords: 1,
		},
		{
			name: "多个密码",
			input: &CredentialInput{
				Password: "pass1,pass2,pass3",
			},
			wantSuccess:   true,
			wantPasswords: 3,
		},
		{
			name: "用户名和密码组合",
			input: &CredentialInput{
				Username: "admin,root",
				Password: "123456,password",
			},
			wantSuccess:   true,
			wantUsernames: 2,
			wantPasswords: 2,
		},
		{
			name: "有效MD5哈希",
			input: &CredentialInput{
				HashValue: "5f4dcc3b5aa765d61d8327deb882cf99",
			},
			wantSuccess: true,
			wantHashes:  1,
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

			if tt.wantUsernames > 0 && len(result.Config.Credentials.Usernames) != tt.wantUsernames {
				t.Errorf("用户名数量 = %d, want %d", len(result.Config.Credentials.Usernames), tt.wantUsernames)
			}

			if tt.wantPasswords > 0 && len(result.Config.Credentials.Passwords) != tt.wantPasswords {
				t.Errorf("密码数量 = %d, want %d", len(result.Config.Credentials.Passwords), tt.wantPasswords)
			}

			if tt.wantHashes > 0 && len(result.Config.Credentials.HashValues) != tt.wantHashes {
				t.Errorf("哈希数量 = %d, want %d", len(result.Config.Credentials.HashValues), tt.wantHashes)
			}
		})
	}
}

// =============================================================================
// validateUsername 测试
// =============================================================================

func TestCredentialParser_ValidateUsername(t *testing.T) {
	fileReader := NewFileReader(nil)

	tests := []struct {
		name      string
		username  string
		options   *CredentialParserOptions
		wantValid bool
	}{
		{
			name:      "有效用户名",
			username:  "admin",
			options:   nil,
			wantValid: true,
		},
		{
			name:      "带数字的用户名",
			username:  "user123",
			options:   nil,
			wantValid: true,
		},
		{
			name:      "空用户名",
			username:  "",
			options:   nil,
			wantValid: false,
		},
		{
			name:     "过长的用户名",
			username: strings.Repeat("a", 100),
			options: &CredentialParserOptions{
				MaxUsernameLength: 64,
			},
			wantValid: false,
		},
		{
			name:      "包含换行符的用户名（无效）",
			username:  "admin\ntest",
			options:   nil,
			wantValid: false,
		},
		{
			name:      "包含制表符的用户名（无效）",
			username:  "admin\ttest",
			options:   nil,
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewCredentialParser(fileReader, tt.options)

			_, valid, err := parser.validateUsername(tt.username)

			if valid != tt.wantValid {
				t.Errorf("validateUsername() = %v (err: %v), want %v", valid, err, tt.wantValid)
			}
		})
	}
}

// =============================================================================
// validatePassword 测试
// =============================================================================

func TestCredentialParser_ValidatePassword(t *testing.T) {
	fileReader := NewFileReader(nil)

	tests := []struct {
		name      string
		password  string
		options   *CredentialParserOptions
		wantValid bool
	}{
		{
			name:      "有效密码",
			password:  "password123",
			options:   nil,
			wantValid: true,
		},
		{
			name:      "复杂密码",
			password:  "P@ssw0rd!#$",
			options:   nil,
			wantValid: true,
		},
		{
			name:     "空密码（允许）",
			password: "",
			options: &CredentialParserOptions{
				AllowEmptyPasswords: true,
			},
			wantValid: true,
		},
		{
			name:     "空密码（不允许）",
			password: "",
			options: &CredentialParserOptions{
				AllowEmptyPasswords: false,
			},
			wantValid: false,
		},
		{
			name:     "过长的密码",
			password: strings.Repeat("a", 200),
			options: &CredentialParserOptions{
				MaxPasswordLength: 128,
			},
			wantValid: false,
		},
		{
			name:      "带空格的密码",
			password:  "my password",
			options:   nil,
			wantValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewCredentialParser(fileReader, tt.options)

			_, valid, err := parser.validatePassword(tt.password)

			if valid != tt.wantValid {
				t.Errorf("validatePassword() = %v (err: %v), want %v", valid, err, tt.wantValid)
			}
		})
	}
}

// =============================================================================
// validateHash 测试
// =============================================================================

func TestCredentialParser_ValidateHash(t *testing.T) {
	fileReader := NewFileReader(nil)

	tests := []struct {
		name      string
		hash      string
		options   *CredentialParserOptions
		wantValid bool
	}{
		{
			name:      "有效MD5哈希（小写）",
			hash:      "5f4dcc3b5aa765d61d8327deb882cf99",
			options:   nil,
			wantValid: true,
		},
		{
			name:      "有效MD5哈希（大写）",
			hash:      "5F4DCC3B5AA765D61D8327DEB882CF99",
			options:   nil,
			wantValid: true,
		},
		{
			name:      "有效MD5哈希（混合大小写）",
			hash:      "5f4DcC3b5Aa765d61D8327dEb882Cf99",
			options:   nil,
			wantValid: true,
		},
		{
			name:      "空哈希",
			hash:      "",
			options:   nil,
			wantValid: false,
		},
		{
			name:      "过短的哈希",
			hash:      "5f4dcc3b5aa765d61d8327deb882cf",
			options:   nil,
			wantValid: false,
		},
		{
			name:      "过长的哈希",
			hash:      "5f4dcc3b5aa765d61d8327deb882cf9900",
			options:   nil,
			wantValid: false,
		},
		{
			name:      "包含非法字符的哈希",
			hash:      "5f4dcc3b5aa765d61d8327deb882cfgg",
			options:   nil,
			wantValid: false,
		},
		{
			name: "禁用哈希验证",
			hash: "invalid-hash",
			options: &CredentialParserOptions{
				ValidateHashes: false,
			},
			wantValid: true, // 禁用验证时，任何哈希都有效
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewCredentialParser(fileReader, tt.options)

			valid, err := parser.validateHash(tt.hash)

			if valid != tt.wantValid {
				t.Errorf("validateHash() = %v (err: %v), want %v", valid, err, tt.wantValid)
			}
		})
	}
}

// =============================================================================
// 文件解析测试
// =============================================================================

func TestCredentialParser_ParseFromFile(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewCredentialParser(fileReader, nil)

	t.Run("用户名文件", func(t *testing.T) {
		usersFile := createTestFile(t, `admin
root
user
# 这是注释
test`)

		input := &CredentialInput{
			UsersFile: usersFile,
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Errorf("意外错误: %v", err)
			return
		}

		// 应该有4个用户名（注释被跳过）
		if len(result.Config.Credentials.Usernames) != 4 {
			t.Errorf("用户名数量 = %d, want 4", len(result.Config.Credentials.Usernames))
		}
	})

	t.Run("密码文件", func(t *testing.T) {
		passFile := createTestFile(t, `password1
password2
# 注释
password3
`)

		input := &CredentialInput{
			PasswordsFile: passFile,
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Errorf("意外错误: %v", err)
			return
		}

		if len(result.Config.Credentials.Passwords) != 3 {
			t.Errorf("密码数量 = %d, want 3", len(result.Config.Credentials.Passwords))
		}
	})

	t.Run("用户密码对文件", func(t *testing.T) {
		pairsFile := createTestFile(t, `admin:admin123
root:toor
user:password
# test:test123 (注释)
guest:guest`)

		input := &CredentialInput{
			UserPassFile: pairsFile,
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Errorf("意外错误: %v", err)
			return
		}

		// 应该有4对用户名密码
		if len(result.Config.Credentials.UserPassPairs) != 4 {
			t.Errorf("用户密码对数量 = %d, want 4", len(result.Config.Credentials.UserPassPairs))
		}

		// 验证第一对
		if result.Config.Credentials.UserPassPairs[0].Username != "admin" {
			t.Errorf("第一对用户名 = %s, want admin", result.Config.Credentials.UserPassPairs[0].Username)
		}
		if result.Config.Credentials.UserPassPairs[0].Password != "admin123" {
			t.Errorf("第一对密码 = %s, want admin123", result.Config.Credentials.UserPassPairs[0].Password)
		}
	})

	t.Run("哈希文件", func(t *testing.T) {
		hashFile := createTestFile(t, `5f4dcc3b5aa765d61d8327deb882cf99
e99a18c428cb38d5f260853678922e03
# 注释
098f6bcd4621d373cade4e832627b4f6`)

		input := &CredentialInput{
			HashFile: hashFile,
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Errorf("意外错误: %v", err)
			return
		}

		if len(result.Config.Credentials.HashValues) != 3 {
			t.Errorf("哈希数量 = %d, want 3", len(result.Config.Credentials.HashValues))
		}

		// 验证哈希字节数组也被生成
		if len(result.Config.Credentials.HashBytes) != 3 {
			t.Errorf("哈希字节数组数量 = %d, want 3", len(result.Config.Credentials.HashBytes))
		}
	})
}

// =============================================================================
// 去重功能测试
// =============================================================================

func TestCredentialParser_Deduplication(t *testing.T) {
	fileReader := NewFileReader(nil)

	t.Run("用户名去重（启用）", func(t *testing.T) {
		opts := DefaultCredentialParserOptions()
		opts.DeduplicateUsers = true
		parser := NewCredentialParser(fileReader, opts)

		input := &CredentialInput{
			Username: "admin,root,admin,user,root",
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Errorf("意外错误: %v", err)
			return
		}

		// 应该去重为3个用户名
		if len(result.Config.Credentials.Usernames) != 3 {
			t.Errorf("用户名数量 = %d, want 3", len(result.Config.Credentials.Usernames))
		}
	})

	t.Run("用户名去重（禁用）", func(t *testing.T) {
		opts := DefaultCredentialParserOptions()
		opts.DeduplicateUsers = false
		parser := NewCredentialParser(fileReader, opts)

		input := &CredentialInput{
			Username: "admin,root,admin",
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Errorf("意外错误: %v", err)
			return
		}

		// 不去重，应该有3个用户名
		if len(result.Config.Credentials.Usernames) != 3 {
			t.Errorf("用户名数量 = %d, want 3", len(result.Config.Credentials.Usernames))
		}
	})

	t.Run("密码去重（启用）", func(t *testing.T) {
		opts := DefaultCredentialParserOptions()
		opts.DeduplicatePasswords = true
		parser := NewCredentialParser(fileReader, opts)

		input := &CredentialInput{
			Password: "123456,password,123456,admin,password",
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Errorf("意外错误: %v", err)
			return
		}

		// 应该去重为3个密码
		if len(result.Config.Credentials.Passwords) != 3 {
			t.Errorf("密码数量 = %d, want 3", len(result.Config.Credentials.Passwords))
		}
	})
}

// =============================================================================
// 混合输入测试
// =============================================================================

func TestCredentialParser_MixedInput(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewCredentialParser(fileReader, nil)

	t.Run("命令行+文件混合", func(t *testing.T) {
		usersFile := createTestFile(t, "user1\nuser2")
		passFile := createTestFile(t, "pass1\npass2")

		input := &CredentialInput{
			Username:      "admin,root",
			UsersFile:     usersFile,
			Password:      "123456",
			PasswordsFile: passFile,
			AddUsers:      "guest",
			AddPasswords:  "guest123",
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Errorf("意外错误: %v", err)
			return
		}

		// 用户名: 2(命令行) + 2(文件) + 1(AddUsers) = 5
		if len(result.Config.Credentials.Usernames) != 5 {
			t.Errorf("用户名数量 = %d, want 5", len(result.Config.Credentials.Usernames))
		}

		// 密码: 1(命令行) + 2(文件) + 1(AddPasswords) = 4
		if len(result.Config.Credentials.Passwords) != 4 {
			t.Errorf("密码数量 = %d, want 4", len(result.Config.Credentials.Passwords))
		}
	})
}

// =============================================================================
// 错误处理测试
// =============================================================================

func TestCredentialParser_ErrorHandling(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewCredentialParser(fileReader, nil)

	t.Run("用户密码对格式错误", func(t *testing.T) {
		pairsFile := createTestFile(t, `admin:admin123
invalidformat
root:toor`)

		input := &CredentialInput{
			UserPassFile: pairsFile,
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Errorf("意外错误: %v", err)
			return
		}

		// 应该有警告
		if len(result.Warnings) == 0 {
			t.Error("期望有警告，但没有")
		}

		// 应该只解析出2对有效的
		if len(result.Config.Credentials.UserPassPairs) != 2 {
			t.Errorf("用户密码对数量 = %d, want 2", len(result.Config.Credentials.UserPassPairs))
		}
	})

	t.Run("用户密码对-空用户名", func(t *testing.T) {
		pairsFile := createTestFile(t, `admin:admin123
:emptyuser
root:toor`)

		input := &CredentialInput{
			UserPassFile: pairsFile,
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Errorf("意外错误: %v", err)
			return
		}

		// 空用户名的行应该被跳过
		if len(result.Config.Credentials.UserPassPairs) != 2 {
			t.Errorf("用户密码对数量 = %d, want 2", len(result.Config.Credentials.UserPassPairs))
		}
	})

	t.Run("密码中包含冒号", func(t *testing.T) {
		pairsFile := createTestFile(t, `admin:pass:word:123
root:simple`)

		input := &CredentialInput{
			UserPassFile: pairsFile,
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Errorf("意外错误: %v", err)
			return
		}

		if len(result.Config.Credentials.UserPassPairs) != 2 {
			t.Errorf("用户密码对数量 = %d, want 2", len(result.Config.Credentials.UserPassPairs))
		}

		// 验证密码中的冒号被正确保留
		if result.Config.Credentials.UserPassPairs[0].Password != "pass:word:123" {
			t.Errorf("密码 = %s, want pass:word:123", result.Config.Credentials.UserPassPairs[0].Password)
		}
	})

	t.Run("不存在的文件", func(t *testing.T) {
		input := &CredentialInput{
			UsersFile: "/nonexistent/users.txt",
		}

		result, err := parser.Parse(input, nil)
		if err != nil {
			t.Errorf("Parse不应返回错误: %v", err)
			return
		}

		// 应该有文件错误
		if result.Success {
			t.Error("解析不应成功（文件不存在）")
		}

		if len(result.Errors) == 0 {
			t.Error("应该有错误记录")
		}
	})
}

// =============================================================================
// removeDuplicateStrings 测试
// =============================================================================

func TestCredentialParser_RemoveDuplicateStrings(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewCredentialParser(fileReader, nil)

	input := []string{"a", "b", "a", "c", "b", "d"}
	result := parser.removeDuplicateStrings(input)

	expected := []string{"a", "b", "c", "d"}

	if len(result) != len(expected) {
		t.Errorf("结果数量 = %d, want %d", len(result), len(expected))
	}

	// 检查所有元素都存在（顺序可能不同）
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
// SSH和Domain字段测试
// =============================================================================

func TestCredentialParser_SSHAndDomain(t *testing.T) {
	fileReader := NewFileReader(nil)
	parser := NewCredentialParser(fileReader, nil)

	input := &CredentialInput{
		SSHKeyPath: "/path/to/ssh/key",
		Domain:     "example.com",
		Username:   "admin",
	}

	result, err := parser.Parse(input, nil)
	if err != nil {
		t.Errorf("意外错误: %v", err)
		return
	}

	if result.Config.Credentials.SSHKeyPath != "/path/to/ssh/key" {
		t.Errorf("SSHKeyPath = %s, want /path/to/ssh/key", result.Config.Credentials.SSHKeyPath)
	}

	if result.Config.Credentials.Domain != "example.com" {
		t.Errorf("Domain = %s, want example.com", result.Config.Credentials.Domain)
	}
}
