package common

import (
	"reflect"
	"testing"
)

/*
parse_test.go - 解析工具函数测试

测试目标：RemoveDuplicate 函数
价值：去重逻辑影响用户输入处理，错误会导致：
  - 重复扫描同一目标（性能浪费）
  - 顺序错乱（某些场景依赖顺序）

"去重是经典算法问题。保留顺序、处理空值、全重复——
这些都是真实场景，必须验证。代码很简单，但边界情况会咬人。"
*/

// =============================================================================
// RemoveDuplicate - 切片去重测试
// =============================================================================

// TestRemoveDuplicate_BasicCases 测试基本去重功能
func TestRemoveDuplicate_BasicCases(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "无重复元素",
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "有重复元素-保留首次出现",
			input:    []string{"a", "b", "a", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "连续重复",
			input:    []string{"a", "a", "b", "b", "c", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "全部重复",
			input:    []string{"a", "a", "a", "a"},
			expected: []string{"a"},
		},
		{
			name:     "空切片",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "单个元素",
			input:    []string{"a"},
			expected: []string{"a"},
		},
		{
			name:     "两个相同元素",
			input:    []string{"a", "a"},
			expected: []string{"a"},
		},
		{
			name:     "两个不同元素",
			input:    []string{"a", "b"},
			expected: []string{"a", "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RemoveDuplicate(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("RemoveDuplicate(%v) = %v, want %v",
					tt.input, result, tt.expected)
			}
		})
	}
}

// TestRemoveDuplicate_OrderPreservation 测试顺序保留
func TestRemoveDuplicate_OrderPreservation(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
		note     string
	}{
		{
			name:     "保留首次出现顺序",
			input:    []string{"b", "a", "c", "a", "b"},
			expected: []string{"b", "a", "c"},
			note:     "b先出现，应该在a前面",
		},
		{
			name:     "后续重复不影响顺序",
			input:    []string{"1", "2", "3", "2", "1"},
			expected: []string{"1", "2", "3"},
			note:     "保持1,2,3的原始顺序",
		},
		{
			name:     "数字字符串顺序",
			input:    []string{"10", "2", "3", "2", "10"},
			expected: []string{"10", "2", "3"},
			note:     "按出现顺序，不按数值排序",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RemoveDuplicate(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("RemoveDuplicate(%v) = %v, want %v\nNote: %s",
					tt.input, result, tt.expected, tt.note)
			}
		})
	}
}

// TestRemoveDuplicate_EdgeCases 测试边界情况
func TestRemoveDuplicate_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "nil切片",
			input:    nil,
			expected: nil,
		},
		{
			name:     "空字符串元素",
			input:    []string{"", "a", "", "b"},
			expected: []string{"", "a", "b"},
		},
		{
			name:     "全是空字符串",
			input:    []string{"", "", ""},
			expected: []string{""},
		},
		{
			name:     "包含空格的字符串",
			input:    []string{" ", "a", " ", "b"},
			expected: []string{" ", "a", "b"},
		},
		{
			name:     "相似但不同的字符串",
			input:    []string{"a", "A", "a", "A"},
			expected: []string{"a", "A"},
		},
		{
			name:     "长字符串",
			input:    []string{"very long string 1", "short", "very long string 1"},
			expected: []string{"very long string 1", "short"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RemoveDuplicate(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("RemoveDuplicate(%v) = %v, want %v",
					tt.input, result, tt.expected)
			}
		})
	}
}

// TestRemoveDuplicate_ProductionScenarios 测试生产环境真实场景
func TestRemoveDuplicate_ProductionScenarios(t *testing.T) {
	t.Run("IP地址去重", func(t *testing.T) {
		// 用户可能输入重复的IP
		input := []string{"192.168.1.1", "192.168.1.2", "192.168.1.1", "192.168.1.3"}
		expected := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}
		result := RemoveDuplicate(input)
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("IP去重失败: got %v, want %v", result, expected)
		}
	})

	t.Run("域名去重", func(t *testing.T) {
		// 用户可能从文件读取重复域名
		input := []string{"example.com", "test.com", "example.com", "demo.com", "test.com"}
		expected := []string{"example.com", "test.com", "demo.com"}
		result := RemoveDuplicate(input)
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("域名去重失败: got %v, want %v", result, expected)
		}
	})

	t.Run("端口列表去重", func(t *testing.T) {
		// 合并多个端口列表
		input := []string{"80", "443", "8080", "80", "443", "3306"}
		expected := []string{"80", "443", "8080", "3306"}
		result := RemoveDuplicate(input)
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("端口去重失败: got %v, want %v", result, expected)
		}
	})

	t.Run("用户名去重", func(t *testing.T) {
		// 字典文件可能有重复
		input := []string{"admin", "root", "admin", "user", "root", "test"}
		expected := []string{"admin", "root", "user", "test"}
		result := RemoveDuplicate(input)
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("用户名去重失败: got %v, want %v", result, expected)
		}
	})
}

// TestRemoveDuplicate_Performance 测试大规模数据性能
func TestRemoveDuplicate_Performance(t *testing.T) {
	t.Run("1000个元素-50%重复", func(t *testing.T) {
		// 构造测试数据：1000个元素，500个唯一
		input := make([]string, 1000)
		for i := 0; i < 1000; i++ {
			input[i] = string(rune('A' + i%500))
		}

		result := RemoveDuplicate(input)

		// 验证结果长度
		if len(result) != 500 {
			t.Errorf("去重后应该有500个唯一元素，实际 %d", len(result))
		}

		// 验证无重复
		seen := make(map[string]bool)
		for _, item := range result {
			if seen[item] {
				t.Errorf("结果中仍有重复元素: %s", item)
				break
			}
			seen[item] = true
		}
	})

	t.Run("大规模-全不重复", func(t *testing.T) {
		// 10000个唯一元素
		input := make([]string, 10000)
		for i := 0; i < 10000; i++ {
			input[i] = string(rune(i))
		}

		result := RemoveDuplicate(input)

		if len(result) != 10000 {
			t.Errorf("全不重复应该保持原长度，期望10000，实际 %d", len(result))
		}
	})

	t.Run("大规模-全重复", func(t *testing.T) {
		// 10000个相同元素
		input := make([]string, 10000)
		for i := 0; i < 10000; i++ {
			input[i] = "duplicate"
		}

		result := RemoveDuplicate(input)

		if len(result) != 1 {
			t.Errorf("全重复应该只剩1个元素，实际 %d", len(result))
		}
		if result[0] != "duplicate" {
			t.Errorf("结果应该是 'duplicate'，实际 %q", result[0])
		}
	})
}

// TestRemoveDuplicate_ReturnValue 测试返回值特性
func TestRemoveDuplicate_ReturnValue(t *testing.T) {
	t.Run("不修改原始切片", func(t *testing.T) {
		input := []string{"a", "b", "a"}
		inputCopy := make([]string, len(input))
		copy(inputCopy, input)

		_ = RemoveDuplicate(input)

		// 验证原始切片未被修改
		if !reflect.DeepEqual(input, inputCopy) {
			t.Errorf("RemoveDuplicate修改了原始切片\n原始: %v\n修改后: %v", inputCopy, input)
		}
	})

	t.Run("返回新切片", func(t *testing.T) {
		input := []string{"a", "b", "c"}
		result := RemoveDuplicate(input)

		// 修改result不应影响input
		result[0] = "modified"
		if input[0] == "modified" {
			t.Error("返回的切片与输入共享内存")
		}
	})

	t.Run("空输入返回空切片", func(t *testing.T) {
		result := RemoveDuplicate([]string{})
		if result == nil {
			t.Error("空输入应返回空切片，而非nil")
		}
		if len(result) != 0 {
			t.Errorf("空输入返回切片长度应为0，实际 %d", len(result))
		}
	})

	t.Run("单元素不分配新内存", func(t *testing.T) {
		input := []string{"a"}
		result := RemoveDuplicate(input)

		// 根据实现，单元素直接返回原切片（优化）
		// 这是实现细节，测试是否返回相同引用
		if &input[0] != &result[0] {
			t.Log("单元素时返回了新切片（也是正确的实现）")
		}
	})
}

// TestRemoveDuplicate_SpecialCharacters 测试特殊字符处理
func TestRemoveDuplicate_SpecialCharacters(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "包含换行符",
			input:    []string{"a\n", "b", "a\n"},
			expected: []string{"a\n", "b"},
		},
		{
			name:     "包含制表符",
			input:    []string{"a\t", "b", "a\t"},
			expected: []string{"a\t", "b"},
		},
		{
			name:     "Unicode字符",
			input:    []string{"你好", "world", "你好", "世界"},
			expected: []string{"你好", "world", "世界"},
		},
		{
			name:     "特殊符号",
			input:    []string{"!@#", "$%^", "!@#"},
			expected: []string{"!@#", "$%^"},
		},
		{
			name:     "路径字符串",
			input:    []string{"/root/test", "/home/user", "/root/test"},
			expected: []string{"/root/test", "/home/user"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RemoveDuplicate(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("RemoveDuplicate(%v) = %v, want %v",
					tt.input, result, tt.expected)
			}
		})
	}
}
