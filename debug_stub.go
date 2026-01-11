//go:build !debug
// +build !debug

package main

// 生产版本：pprof 完全不编译进来
func startPprof() {
	// 空函数，什么都不做
}

func stopPprof() {
	// 空函数，什么都不做
}
