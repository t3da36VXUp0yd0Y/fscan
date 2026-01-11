package proxy

import (
	"sync/atomic"
)

var (
	// proxyEnabled 标记是否启用了代理（全局状态）
	proxyEnabled atomic.Bool

	// socks5Standard 标记是否为标准的SOCKS5代理
	socks5Standard atomic.Bool

	// proxyInitialized 标记代理是否已初始化
	proxyInitialized atomic.Bool
)

// SetProxyEnabled 设置代理启用状态
func SetProxyEnabled(enabled bool) {
	proxyEnabled.Store(enabled)
}

// SetSOCKS5Standard 设置SOCKS5是否标准
func SetSOCKS5Standard(standard bool) {
	socks5Standard.Store(standard)
}

// SetProxyInitialized 设置代理初始化状态
func SetProxyInitialized(initialized bool) {
	proxyInitialized.Store(initialized)
}

// IsProxyEnabled 检查是否启用了代理
func IsProxyEnabled() bool {
	return proxyEnabled.Load()
}

// IsSOCKS5Standard 检查SOCKS5代理是否为标准代理
func IsSOCKS5Standard() bool {
	return socks5Standard.Load()
}

// IsProxyInitialized 检查代理是否已初始化
func IsProxyInitialized() bool {
	return proxyInitialized.Load()
}

// AutoConfigureProxy 自动配置代理相关行为
// 根据代理类型和状态自动调整扫描策略
func AutoConfigureProxy(config *ProxyConfig) {
	if config == nil || config.Type == ProxyTypeNone {
		SetProxyEnabled(false)
		SetSOCKS5Standard(false)
		SetProxyInitialized(false)
		return
	}

	// 启用代理标记
	SetProxyEnabled(true)

	// SOCKS5代理默认假设非标准（后续可以动态探测）
	if config.Type == ProxyTypeSOCKS5 {
		SetSOCKS5Standard(false)
	}

	// HTTP/HTTPS代理视为标准
	if config.Type == ProxyTypeHTTP || config.Type == ProxyTypeHTTPS {
		SetSOCKS5Standard(true)
	}
}
