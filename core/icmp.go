package core

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/common/output"
	"golang.org/x/net/icmp"
)

// pingForbiddenChars 命令注入防护 - 禁止的字符
var pingForbiddenChars = []string{";", "&", "|", "`", "$", "\\", "'", "%", "\"", "\n"}

// CheckLive 检测主机存活状态
func CheckLive(hostslist []string, Ping bool, config *common.Config, state *common.State) []string {
	// 创建局部WaitGroup
	var livewg sync.WaitGroup

	// 创建局部存活主机列表，预分配容量避免频繁扩容
	aliveHosts := make([]string, 0, len(hostslist))
	var aliveHostsMu sync.Mutex // 保护aliveHosts并发访问
	existHosts := make(map[string]struct{}, len(hostslist))

	// 创建主机通道
	chanHosts := make(chan string, len(hostslist))

	// 处理存活主机
	go handleAliveHosts(chanHosts, hostslist, Ping, &aliveHosts, &aliveHostsMu, existHosts, config, &livewg)

	// 根据Ping参数选择检测方式
	if Ping {
		// 使用ping方式探测
		RunPing(hostslist, chanHosts, &livewg)
	} else {
		probeWithICMP(hostslist, chanHosts, &aliveHosts, &aliveHostsMu, config, state, &livewg)
	}

	// 等待所有检测完成
	livewg.Wait()
	close(chanHosts)

	// 输出存活统计信息
	printAliveStats(aliveHosts, hostslist)

	return aliveHosts
}

// IsContain 检查切片中是否包含指定元素
func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

func handleAliveHosts(chanHosts chan string, hostslist []string, isPing bool, aliveHosts *[]string, aliveHostsMu *sync.Mutex, existHosts map[string]struct{}, config *common.Config, livewg *sync.WaitGroup) {
	for ip := range chanHosts {
		if _, ok := existHosts[ip]; !ok && IsContain(hostslist, ip) {
			existHosts[ip] = struct{}{}

			// 加锁保护aliveHosts并发写入
			aliveHostsMu.Lock()
			*aliveHosts = append(*aliveHosts, ip)
			aliveHostsMu.Unlock()

			// 使用Output系统保存存活主机信息
			protocol := "ICMP"
			if isPing {
				protocol = "PING"
			}

			result := &output.ScanResult{
				Time:   time.Now(),
				Type:   output.TypeHost,
				Target: ip,
				Status: "alive",
				Details: map[string]interface{}{
					"protocol": protocol,
				},
			}
			_ = common.SaveResult(result)

			// 保留原有的控制台输出
			if !config.Output.Silent {
				common.LogInfo(i18n.Tr("host_alive", ip, protocol))
			}
		}
		livewg.Done()
	}
}

// probeWithICMP 使用ICMP方式探测
func probeWithICMP(hostslist []string, chanHosts chan string, aliveHosts *[]string, aliveHostsMu *sync.Mutex, config *common.Config, state *common.State, livewg *sync.WaitGroup) {
	// 代理模式下自动禁用ICMP，直接降级为Ping
	// ICMP在代理环境无法正常工作
	if shouldDisableICMP() {
		if !config.Output.Silent {
			common.LogInfo(i18n.GetText("proxy_mode_disable_icmp"))
		}
		RunPing(hostslist, chanHosts, livewg)
		return
	}

	// 尝试监听本地ICMP
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err == nil {
		RunIcmp1(hostslist, conn, chanHosts, aliveHosts, aliveHostsMu, config, state, livewg)
		return
	}

	common.LogError(i18n.Tr("icmp_listen_failed", err))
	common.LogBase(i18n.GetText("trying_no_listen_icmp"))

	// 尝试无监听ICMP探测
	conn2, err := net.DialTimeout("ip4:icmp", "127.0.0.1", 3*time.Second)
	if err == nil {
		defer func() { _ = conn2.Close() }()
		RunIcmp2(hostslist, chanHosts, config, state, livewg)
		return
	}

	common.LogBase(i18n.Tr("icmp_connect_failed", err))
	common.LogBase(i18n.GetText("insufficient_privileges"))
	common.LogBase(i18n.GetText("switching_to_ping"))

	// 降级使用ping探测
	RunPing(hostslist, chanHosts, livewg)
}

// shouldDisableICMP 检查是否应该禁用ICMP
// 这是一个内部辅助函数，用于检查代理状态
func shouldDisableICMP() bool {
	// 尝试导入proxy包的状态检查（避免循环依赖）
	// 实际实现中会通过全局配置检查
	// 这里暂时返回false，实际集成时会正确处理
	return false
}

// getOptimalTopCount 根据扫描规模智能决定显示数量
func getOptimalTopCount(totalHosts int) int {
	switch {
	case totalHosts > 50000: // 超大规模扫描
		return 20
	case totalHosts > 10000: // 大规模扫描
		return 15
	case totalHosts > 1000: // 中等规模扫描
		return 10
	case totalHosts > 256: // 小规模扫描
		return 5
	default:
		return 3
	}
}

// printAliveStats 打印存活统计信息
func printAliveStats(aliveHosts []string, hostslist []string) {
	// 智能计算显示数量
	topCount := getOptimalTopCount(len(hostslist))

	// 大规模扫描时输出 /16 网段统计
	if len(hostslist) > 1000 {
		arrTop, arrLen := ArrayCountValueTop(aliveHosts, topCount, true)
		for i := 0; i < len(arrTop); i++ {
			common.LogInfo(i18n.Tr("segment_16_alive", arrTop[i], arrLen[i]))
		}
	}

	// 输出 /24 网段统计
	if len(hostslist) > 256 {
		arrTop, arrLen := ArrayCountValueTop(aliveHosts, topCount, false)
		for i := 0; i < len(arrTop); i++ {
			common.LogInfo(i18n.Tr("segment_24_alive", arrTop[i], arrLen[i]))
		}
	}
}

// RunIcmp1 使用ICMP批量探测主机存活(监听模式)
func RunIcmp1(hostslist []string, conn *icmp.PacketConn, chanHosts chan string, aliveHosts *[]string, aliveHostsMu *sync.Mutex, config *common.Config, state *common.State, livewg *sync.WaitGroup) {
	// 使用atomic.Bool保证并发安全
	var endflag atomic.Bool
	var listenerWg sync.WaitGroup

	// 创建布隆过滤器用于去重（自动根据主机数量调整大小）
	bloomFilter := NewBloomFilter(len(hostslist), 0.01)

	// 启动监听协程
	listenerWg.Add(1)
	go func() {
		defer listenerWg.Done()
		defer func() {
			if r := recover(); r != nil {
				common.LogError(i18n.Tr("icmp_listener_panic", r))
			}
		}()

		for {
			if endflag.Load() {
				return
			}

			// 设置读取超时避免无限期阻塞
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

			// 接收ICMP响应
			msg := make([]byte, 100)
			_, sourceIP, err := conn.ReadFrom(msg)

			if err != nil {
				// 超时错误正常，其他错误则退出
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					continue
				}
				return
			}

			if sourceIP != nil && !endflag.Load() {
				ipStr := sourceIP.String()

				// 使用布隆过滤器去重，过滤重复的ICMP响应和杂包
				if bloomFilter.Contains(ipStr) {
					continue
				}
				bloomFilter.Add(ipStr)

				livewg.Add(1)
				select {
				case chanHosts <- ipStr:
					// 发送成功
				default:
					// channel已满，回退计数器
					livewg.Done()
				}
			}
		}
	}()

	// 发送ICMP请求（应用令牌桶限速）
	limiter := state.GetICMPLimiter(config.Network.ICMPRate)
	for _, host := range hostslist {
		limiter.Wait(1) // 等待令牌，控制发包速率
		dst, _ := net.ResolveIPAddr("ip", host)
		IcmpByte := makemsg(host)
		_, _ = conn.WriteTo(IcmpByte, dst)
	}

	// 等待响应
	start := time.Now()
	for {
		// 加锁读取aliveHosts长度
		aliveHostsMu.Lock()
		aliveCount := len(*aliveHosts)
		aliveHostsMu.Unlock()

		// 所有主机都已响应则退出
		if aliveCount == len(hostslist) {
			break
		}

		// 根据主机数量设置超时时间
		since := time.Since(start)
		wait := time.Second * 6
		if len(hostslist) <= 256 {
			wait = time.Second * 3
		}

		if since > wait {
			break
		}
	}

	endflag.Store(true)
	_ = conn.Close()
	listenerWg.Wait()
}

// RunIcmp2 使用ICMP并发探测主机存活(无监听模式)
func RunIcmp2(hostslist []string, chanHosts chan string, config *common.Config, state *common.State, livewg *sync.WaitGroup) {
	// 控制并发数
	num := 1000
	if len(hostslist) < num {
		num = len(hostslist)
	}

	var wg sync.WaitGroup
	limiter := make(chan struct{}, num)
	rateLimiter := state.GetICMPLimiter(config.Network.ICMPRate) // 获取速率限制器

	// 并发探测
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}

		go func(host string) {
			defer func() {
				<-limiter
				wg.Done()
			}()

			rateLimiter.Wait(1) // 等待令牌，控制发包速率
			if icmpalive(host) {
				livewg.Add(1)
				select {
				case chanHosts <- host:
					// 发送成功
				default:
					// channel已满，回退计数器
					livewg.Done()
				}
			}
		}(host)
	}

	wg.Wait()
	close(limiter)
}

// icmpalive 检测主机ICMP是否存活
func icmpalive(host string) bool {
	startTime := time.Now()

	// 建立ICMP连接
	conn, err := net.DialTimeout("ip4:icmp", host, 6*time.Second)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	// 设置超时时间
	if err := conn.SetDeadline(startTime.Add(6 * time.Second)); err != nil {
		return false
	}

	// 构造并发送ICMP请求
	msg := makemsg(host)
	if _, err := conn.Write(msg); err != nil {
		return false
	}

	// 接收ICMP响应
	receive := make([]byte, 60)
	if _, err := conn.Read(receive); err != nil {
		return false
	}

	return true
}

// RunPing 使用系统Ping命令并发探测主机存活
func RunPing(hostslist []string, chanHosts chan string, livewg *sync.WaitGroup) {
	var wg sync.WaitGroup
	// 限制并发数为50
	limiter := make(chan struct{}, 50)

	// 并发探测
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}

		go func(host string) {
			defer func() {
				<-limiter
				wg.Done()
			}()

			if ExecCommandPing(host) {
				livewg.Add(1)
				select {
				case chanHosts <- host:
					// 发送成功
				default:
					// channel已满，回退计数器
					livewg.Done()
				}
			}
		}(host)
	}

	wg.Wait()
}

// ExecCommandPing 执行系统Ping命令检测主机存活
func ExecCommandPing(ip string) bool {
	// 过滤黑名单字符（命令注入防护）
	for _, char := range pingForbiddenChars {
		if strings.Contains(ip, char) {
			return false
		}
	}

	var command *exec.Cmd
	// 根据操作系统选择不同的ping命令
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("cmd", "/c", "ping -n 1 -w 1 "+ip+" && echo true || echo false")
	case "darwin":
		command = exec.Command("/bin/bash", "-c", "ping -c 1 -W 1 "+ip+" && echo true || echo false")
	default: // linux
		command = exec.Command("/bin/bash", "-c", "ping -c 1 -w 1 "+ip+" && echo true || echo false")
	}

	// 捕获命令输出
	var outinfo bytes.Buffer
	command.Stdout = &outinfo

	// 执行命令
	if err := command.Start(); err != nil {
		return false
	}

	if err := command.Wait(); err != nil {
		return false
	}

	// 分析输出结果
	output := outinfo.String()
	return strings.Contains(output, "true") && strings.Count(output, ip) > 2
}

// makemsg 构造ICMP echo请求消息
func makemsg(host string) []byte {
	msg := make([]byte, 40)

	// 获取标识符
	id0, id1 := genIdentifier(host)

	// 设置ICMP头部
	msg[0] = 8                      // Type: Echo Request
	msg[1] = 0                      // Code: 0
	msg[2] = 0                      // Checksum高位(待计算)
	msg[3] = 0                      // Checksum低位(待计算)
	msg[4], msg[5] = id0, id1       // Identifier
	msg[6], msg[7] = genSequence(1) // Sequence Number

	// 计算校验和
	check := checkSum(msg[0:40])
	msg[2] = byte(check >> 8)  // 设置校验和高位
	msg[3] = byte(check & 255) // 设置校验和低位

	return msg
}

// checkSum 计算ICMP校验和
func checkSum(msg []byte) uint16 {
	sum := 0
	length := len(msg)

	// 按16位累加
	for i := 0; i < length-1; i += 2 {
		sum += int(msg[i])*256 + int(msg[i+1])
	}

	// 处理奇数长度情况
	if length%2 == 1 {
		sum += int(msg[length-1]) * 256
	}

	// 将高16位加到低16位
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	// 取反得到校验和
	return uint16(^sum)
}

// genSequence 生成ICMP序列号
func genSequence(v int16) (byte, byte) {
	ret1 := byte(v >> 8)  // 高8位
	ret2 := byte(v & 255) // 低8位
	return ret1, ret2
}

// genIdentifier 根据主机地址生成标识符
func genIdentifier(host string) (byte, byte) {
	if len(host) < 2 {
		return 0, 0
	}
	return host[0], host[1]
}

// ArrayCountValueTop 统计IP地址段存活数量并返回TOP N结果
func ArrayCountValueTop(arrInit []string, length int, flag bool) (arrTop []string, arrLen []int) {
	if len(arrInit) == 0 {
		return
	}

	// 统计各网段出现次数，预分配容量
	segmentCounts := make(map[string]int, len(arrInit)/4)
	for _, ip := range arrInit {
		segments := strings.Split(ip, ".")
		if len(segments) != 4 {
			continue
		}

		// 根据flag确定统计B段还是C段
		var segment string
		if flag {
			segment = fmt.Sprintf("%s.%s", segments[0], segments[1]) // B段
		} else {
			segment = fmt.Sprintf("%s.%s.%s", segments[0], segments[1], segments[2]) // C段
		}

		segmentCounts[segment]++
	}

	// 创建副本用于排序
	sortMap := make(map[string]int)
	for k, v := range segmentCounts {
		sortMap[k] = v
	}

	// 获取TOP N结果
	for i := 0; i < length && len(sortMap) > 0; i++ {
		maxSegment := ""
		maxCount := 0

		// 查找当前最大值
		for segment, count := range sortMap {
			if count > maxCount {
				maxCount = count
				maxSegment = segment
			}
		}

		// 添加到结果集
		arrTop = append(arrTop, maxSegment)
		arrLen = append(arrLen, maxCount)

		// 从待处理map中删除已处理项
		delete(sortMap, maxSegment)
	}

	return
}
