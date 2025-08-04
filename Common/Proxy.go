package Common

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// WrapperTcpWithTimeout 创建一个带超时的TCP连接
func WrapperTcpWithTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return WrapperTCP(network, address, d)
}

// WrapperTcpWithContext 创建一个带上下文的TCP连接
func WrapperTcpWithContext(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{}
	return WrapperTCPWithContext(ctx, network, address, d)
}

// WrapperTCP 根据配置创建TCP连接
func WrapperTCP(network, address string, forward *net.Dialer) (net.Conn, error) {
	// 直连模式
	if Socks5Proxy == "" {
		conn, err := forward.Dial(network, address)
		if err != nil {
			return nil, fmt.Errorf(GetText("tcp_conn_failed"), err)
		}
		return conn, nil
	}

	// Socks5代理模式
	dialer, err := Socks5Dialer(forward)
	if err != nil {
		return nil, fmt.Errorf(GetText("socks5_create_failed"), err)
	}

	conn, err := dialer.Dial(network, address)
	if err != nil {
		return nil, fmt.Errorf(GetText("socks5_conn_failed"), err)
	}

	return conn, nil
}

// WrapperTCPWithContext 根据配置创建支持上下文的TCP连接
func WrapperTCPWithContext(ctx context.Context, network, address string, forward *net.Dialer) (net.Conn, error) {
	// 直连模式
	if Socks5Proxy == "" {
		conn, err := forward.DialContext(ctx, network, address)
		if err != nil {
			return nil, fmt.Errorf(GetText("tcp_conn_failed"), err)
		}
		return conn, nil
	}

	// Socks5代理模式
	dialer, err := Socks5Dialer(forward)
	if err != nil {
		return nil, fmt.Errorf(GetText("socks5_create_failed"), err)
	}

	// 创建一个结果通道来处理连接和取消
	connChan := make(chan struct {
		conn net.Conn
		err  error
	}, 1)

	go func() {
		conn, err := dialer.Dial(network, address)
		select {
		case <-ctx.Done():
			if conn != nil {
				conn.Close()
			}
		case connChan <- struct {
			conn net.Conn
			err  error
		}{conn, err}:
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-connChan:
		if result.err != nil {
			return nil, fmt.Errorf(GetText("socks5_conn_failed"), result.err)
		}
		return result.conn, nil
	}
}

// Socks5Dialer 创建Socks5代理拨号器
func Socks5Dialer(forward *net.Dialer) (proxy.Dialer, error) {
	// 解析代理URL
	u, err := url.Parse(Socks5Proxy)
	if err != nil {
		return nil, fmt.Errorf(GetText("socks5_parse_failed"), err)
	}

	// 验证代理类型
	if strings.ToLower(u.Scheme) != "socks5" {
		return nil, errors.New(GetText("socks5_only"))
	}

	address := u.Host
	var dialer proxy.Dialer

	// 根据认证信息创建代理
	if u.User.String() != "" {
		// 使用用户名密码认证
		auth := proxy.Auth{
			User: u.User.Username(),
		}
		auth.Password, _ = u.User.Password()
		dialer, err = proxy.SOCKS5("tcp", address, &auth, forward)
	} else {
		// 无认证模式
		dialer, err = proxy.SOCKS5("tcp", address, nil, forward)
	}

	if err != nil {
		return nil, fmt.Errorf(GetText("socks5_create_failed"), err)
	}

	return dialer, nil
}

// WrapperTlsWithContext 创建一个通过代理的TLS连接
func WrapperTlsWithContext(ctx context.Context, network, address string, tlsConfig *tls.Config) (net.Conn, error) {
	// 直连模式
	if Socks5Proxy == "" {
		dialer := &net.Dialer{}

		tcpConn, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, fmt.Errorf("直连TCP连接失败: %v", err)
		}

		// 在TCP连接上进行TLS握手
		tlsConn := tls.Client(tcpConn, tlsConfig)

		// 使用ctx的deadline设置TLS握手超时
		if deadline, ok := ctx.Deadline(); ok {
			tlsConn.SetDeadline(deadline)
		}

		if err := tlsConn.Handshake(); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("TLS握手失败: %v", err)
		}

		// 清除deadline，让上层代码自己管理超时
		tlsConn.SetDeadline(time.Time{})

		return tlsConn, nil
	}

	// Socks5代理模式
	// 首先通过代理建立到目标的TCP连接
	tcpConn, err := WrapperTcpWithContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("通过代理建立TCP连接失败: %v", err)
	}

	// 在TCP连接上进行TLS握手
	tlsConn := tls.Client(tcpConn, tlsConfig)

	// 使用ctx的deadline设置TLS握手超时
	if deadline, ok := ctx.Deadline(); ok {
		tlsConn.SetDeadline(deadline)
	}

	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("TLS握手失败: %v", err)
	}

	// 清除deadline，让上层代码自己管理超时
	tlsConn.SetDeadline(time.Time{})

	return tlsConn, nil
}
