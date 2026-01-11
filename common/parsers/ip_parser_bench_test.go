package parsers

import (
	"testing"
)

// BenchmarkParseIPCIDR24 测试 /24 网段解析性能
func BenchmarkParseIPCIDR24(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseIP("192.168.1.0/24", "")
	}
}

// BenchmarkParseIPCIDR16 测试 /16 网段解析性能
func BenchmarkParseIPCIDR16(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseIP("192.168.0.0/16", "")
	}
}

// BenchmarkParseIPRange 测试 IP 范围解析性能
func BenchmarkParseIPRange(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseIP("192.168.1.1-192.168.1.254", "")
	}
}

// BenchmarkParseIPSingle 测试单个 IP 解析性能
func BenchmarkParseIPSingle(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseIP("192.168.1.1", "")
	}
}

// BenchmarkParsePortRange 测试端口范围解析性能
func BenchmarkParsePortRange(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParsePort("1-65535")
	}
}

// BenchmarkParsePortList 测试端口列表解析性能
func BenchmarkParsePortList(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParsePort("22,80,443,3389,8080,8443,9000,9001,9002")
	}
}

// BenchmarkParsePortCommon 测试常用端口解析性能
func BenchmarkParsePortCommon(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParsePort("21,22,23,25,80,110,139,143,443,445,3306,3389,5432,6379,8080")
	}
}
