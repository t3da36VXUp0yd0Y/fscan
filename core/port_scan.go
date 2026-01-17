package core

import (
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/common/output"
	"github.com/shadow1ng/fscan/common/parsers"
)

// proxyFailurePatterns 代理连接失败的错误模式（小写）
var proxyFailurePatterns = []string{
	"connection reset by peer",
	"connection refused",
	"no route to host",
	"network is unreachable",
	"host is unreachable",
	"general socks server failure",
	"connection not allowed",
	"host unreachable",
	"network unreachable",
	"connection refused by destination host",
}

// resourceExhaustedPatterns 资源耗尽类错误模式
var resourceExhaustedPatterns = []string{
	"too many open files",
	"no buffer space available",
	"cannot assign requested address",
	"connection reset by peer",
	"发包受限",
}

// resultCollector 结果收集器，用于并发安全地收集扫描结果
// 使用 map 实现：O(1) 的添加和删除，无顺序依赖问题
type resultCollector struct {
	mu    sync.Mutex
	addrs map[string]struct{}
}

// newResultCollector 创建结果收集器
func newResultCollector() *resultCollector {
	return &resultCollector{
		addrs: make(map[string]struct{}),
	}
}

// Add 添加一个扫描结果
func (c *resultCollector) Add(addr string) {
	c.mu.Lock()
	c.addrs[addr] = struct{}{}
	c.mu.Unlock()
}

// GetAll 获取所有结果
func (c *resultCollector) GetAll() []string {
	c.mu.Lock()
	result := make([]string, 0, len(c.addrs))
	for addr := range c.addrs {
		result = append(result, addr)
	}
	c.mu.Unlock()
	return result
}

// portScanTask 端口扫描任务（轻量级，用于滑动窗口调度）
type portScanTask struct {
	host      string
	port      int
	semaphore chan struct{} // 完成时释放窗口槽位
}

// failedPortInfo 失败端口信息
type failedPortInfo struct {
	Host string
	Port int
	Addr string
}

// failedPortCollector 失败端口收集器，用于记录需要重扫的端口
type failedPortCollector struct {
	mu    sync.Mutex
	ports []failedPortInfo
}

// Add 添加失败的端口
func (f *failedPortCollector) Add(host string, port int, addr string) {
	f.mu.Lock()
	f.ports = append(f.ports, failedPortInfo{
		Host: host,
		Port: port,
		Addr: addr,
	})
	f.mu.Unlock()
}

// Count 获取失败端口数量
func (f *failedPortCollector) Count() int {
	f.mu.Lock()
	count := len(f.ports)
	f.mu.Unlock()
	return count
}

// estimateScanTime 估算扫描时间
// 参数: totalTasks - 总任务数, threads - 线程数, timeout - 超时时间(秒)
// 返回: 估算的扫描时间(秒)
func estimateScanTime(totalTasks int, threads int, timeout int64) int64 {
	if totalTasks == 0 || threads == 0 {
		return 0
	}

	// 假设约50%的端口会快速返回关闭状态（平均耗时 timeout/4）
	// 约50%的端口需要完整超时（耗时 timeout）
	// 因此平均每个任务耗时 = timeout * 0.5 * (0.25 + 1.0) = timeout * 0.625
	avgTaskTime := float64(timeout) * 0.625

	// 计算需要多少批次（向上取整）
	parallelBatches := math.Ceil(float64(totalTasks) / float64(threads))

	// 总时间 = 批次数 × 平均任务时间
	estimatedSeconds := int64(parallelBatches * avgTaskTime)

	return estimatedSeconds
}

// EnhancedPortScan 高性能端口扫描函数
// 使用滑动窗口调度 + 自适应线程池 + 流式迭代器
func EnhancedPortScan(hosts []string, ports string, timeout int64, config *common.Config, state *common.State) []string {
	// 解析端口和排除端口
	portList := parsers.ParsePort(ports)
	if len(portList) == 0 {
		common.LogError(i18n.Tr("invalid_port", ports))
		return nil
	}

	// 使用config中的排除端口配置
	excludePorts := parsers.ParsePort(config.Target.ExcludePorts)
	exclude := make(map[int]struct{}, len(excludePorts))
	for _, p := range excludePorts {
		exclude[p] = struct{}{}
	}

	// 检查代理可靠性，如果存在全回显问题则警告
	if common.IsProxyEnabled() && !common.IsProxyReliable() {
		common.LogBase("[!] 检测到代理存在全回显问题，端口扫描结果可能不准确")
	}

	// 创建流式迭代器（O(1) 内存，端口喷洒策略）
	iter := NewSocketIterator(hosts, portList, exclude)
	totalTasks := iter.Total()

	// 使用传入的配置
	threadNum := config.ThreadNum


	// 初始化端口扫描进度条
	if totalTasks > 0 && config.Output.ShowProgress {
		description := fmt.Sprintf("端口扫描中（%d线程）", threadNum)
		common.InitProgressBar(int64(totalTasks), description)
	}

	// 初始化并发控制
	to := time.Duration(timeout) * time.Second
	var count int64
	collector := newResultCollector()
	failedCollector := &failedPortCollector{}
	var wg sync.WaitGroup

	// 创建自适应线程池（支持动态调整）
	pool, err := NewAdaptivePool(threadNum, func(task interface{}) {
		taskInfo, ok := task.(portScanTask)
		if !ok {
			return
		}
		defer func() {
			<-taskInfo.semaphore // 释放窗口槽位
			wg.Done()
		}()

		addr := fmt.Sprintf("%s:%d", taskInfo.host, taskInfo.port)
		scanSinglePort(taskInfo.host, taskInfo.port, addr, to, &count, collector, failedCollector, config, state)
		common.UpdateProgressBar(1)
	}, state)
	if err != nil {
		common.LogError(i18n.Tr("thread_pool_create_failed", err))
		return nil
	}
	defer pool.Release()

	// 滑动窗口调度：维护固定数量的"飞行中"任务
	slidingWindowSchedule(iter, pool, &wg, threadNum)

	// 收集结果
	aliveAddrs := collector.GetAll()

	// 完成端口扫描进度条
	if common.IsProgressActive() {
		common.FinishProgressBar()
	}

	common.LogBase(i18n.Tr("port_scan_complete", count))

	// 检查扫描失败率，如果过高则警告用户
	resourceErrors := state.GetResourceExhaustedCount()
	failedCount := failedCollector.Count()

	if failedCount > 0 {
		failureRate := float64(failedCount) / float64(totalTasks) * 100

		if failureRate > 20 {
			// 失败率超过20%，严重警告
			common.LogError(i18n.Tr("scan_failure_rate_high", fmt.Sprintf("%.1f%%", failureRate), failedCount, totalTasks))
			common.LogError(i18n.GetText("scan_failure_reason"))
			common.LogError(i18n.Tr("scan_reduce_threads_suggestion", threadNum))
		} else if failureRate > 5 {
			// 失败率5-20%，一般警告
			common.LogInfo(i18n.Tr("scan_partial_failure", fmt.Sprintf("%.1f%%", failureRate), failedCount, totalTasks))
			common.LogInfo(i18n.Tr("scan_reduce_threads_accuracy", threadNum))
		}
	}

	if resourceErrors > 0 {
		common.LogError(i18n.Tr("resource_exhausted_warning", resourceErrors))
	}

	return aliveAddrs
}

// slidingWindowSchedule 滑动窗口调度器
// 核心思想：维护固定数量的"飞行中"任务，一个完成立即补充新的
// 优势：避免任务队列堆积，内存使用恒定
func slidingWindowSchedule(iter *SocketIterator, pool *AdaptivePool, wg *sync.WaitGroup, windowSize int) {
	// 使用信号量控制窗口大小
	semaphore := make(chan struct{}, windowSize)

	for {
		host, port, ok := iter.Next()
		if !ok {
			break
		}

		// 获取窗口槽位（阻塞直到有空位）
		semaphore <- struct{}{}

		wg.Add(1)
		task := portScanTask{
			host:      host,
			port:      port,
			semaphore: semaphore,
		}
		_ = pool.Invoke(task)
	}

	// 等待所有任务完成
	wg.Wait()
}

// connectWithRetry 带重试的TCP连接 - 只对资源耗尽错误重试
func connectWithRetry(addr string, timeout time.Duration, maxRetries int, state *common.State) (net.Conn, error) {
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		conn, err := common.WrapperTcpWithTimeout("tcp", addr, timeout)

		if err == nil {
			return conn, nil
		}

		lastErr = err

		// 只对资源耗尽类错误重试，端口关闭直接返回
		if !isResourceExhaustedError(err) {
			return nil, err
		}

		// 记录资源耗尽错误
		state.IncrementResourceExhaustedCount()

		// 指数退避：第1次等50ms，第2次等150ms
		if attempt < maxRetries-1 {
			waitTime := time.Duration(50*(attempt+1)) * time.Millisecond
			time.Sleep(waitTime)
		}
	}

	return nil, lastErr
}

// isResourceExhaustedError 判断是否为资源耗尽类错误
func isResourceExhaustedError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	for _, pattern := range resourceExhaustedPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// buildServiceLogMessage 构建服务识别的日志信息
// 格式: addr service banner (简洁单行，方便复制)
func buildServiceLogMessage(addr string, serviceInfo *ServiceInfo, isWeb bool) string {
	var parts []string
	parts = append(parts, addr)

	if serviceInfo.Name != "unknown" {
		parts = append(parts, serviceInfo.Name)
	}

	// Banner 优先，其次是版本信息
	if len(serviceInfo.Banner) > 0 && len(serviceInfo.Banner) < 100 {
		parts = append(parts, strings.TrimSpace(serviceInfo.Banner))
	} else if serviceInfo.Version != "" {
		parts = append(parts, serviceInfo.Version)
	}

	return strings.Join(parts, " ")
}

// scanSinglePort 扫描单个端口并进行服务识别（重构后的简洁版本）
func scanSinglePort(host string, port int, addr string, timeout time.Duration, count *int64, collector *resultCollector, failedCollector *failedPortCollector, config *common.Config, state *common.State) {
	// 步骤1：建立连接
	conn, err := connectWithRetry(addr, timeout, 3, state)
	if err != nil {
		handleConnectionFailure(err, host, port, addr, failedCollector)
		return
	}

	// 步骤1.5：代理连接验证（防止非标准SOCKS5代理的"全回显"问题）
	if !verifyProxyConnection(conn, addr) {
		_ = conn.Close()
		return
	}

	// 步骤2：记录开放端口
	atomic.AddInt64(count, 1)
	collector.Add(addr)
	saveOpenPort(host, port)

	// 步骤3：服务识别（Scanner负责关闭连接，包括探测中可能创建的新连接）
	scanner := NewSmartPortInfoScanner(host, port, conn, timeout, config)
	defer scanner.Close()
	serviceInfo, _ := scanner.SmartIdentify()

	// 步骤4：处理结果
	processServiceResult(host, port, addr, serviceInfo, config)
}

// handleConnectionFailure 处理连接失败
func handleConnectionFailure(err error, host string, port int, addr string, failedCollector *failedPortCollector) {
	if isResourceExhaustedError(err) || isTimeoutError(err) {
		failedCollector.Add(host, port, addr)
	}
}

// isTimeoutError 判断是否为超时错误
func isTimeoutError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "i/o timeout")
}

// verifyProxyConnection 验证代理连接是否真正可用
// 防止非标准SOCKS5代理的"全回显"问题：代理连接成功但目标实际不可达
// 返回 true 表示连接有效，false 表示连接无效（目标不可达）
func verifyProxyConnection(conn net.Conn, addr string) bool {
	// 如果没有使用代理，跳过验证
	if !common.IsProxyEnabled() {
		return true
	}

	// 如果代理不可靠（存在全回显问题），直接返回 false
	if !common.IsProxyReliable() {
		common.LogDebug(fmt.Sprintf("代理不可靠，跳过端口 %s", addr))
		return false
	}

	// 设置短超时进行连接验证（100ms）
	// 如果目标端口真的开放，不会在这么短时间内收到错误
	// 如果目标不可达，非标准代理可能会立即返回错误
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	// 尝试读取（非阻塞检查）
	buf := make([]byte, 1)
	_, err := conn.Read(buf)

	// 重置超时设置
	_ = conn.SetReadDeadline(time.Time{})

	if err != nil {
		errLower := strings.ToLower(err.Error())
		for _, pattern := range proxyFailurePatterns {
			if strings.Contains(errLower, pattern) {
				common.LogDebug(fmt.Sprintf("代理连接验证失败 %s: %v", addr, err))
				return false
			}
		}
		// 超时错误是正常的（目标没有主动发送数据）
		// EOF 也可能是正常的（某些服务的行为）
	}

	return true
}

// saveOpenPort 保存开放端口结果
func saveOpenPort(host string, port int) {
	_ = common.SaveResult(&output.ScanResult{
		Time:    time.Now(),
		Type:    output.TypePort,
		Target:  host,
		Status:  "open",
		Details: map[string]interface{}{"port": port},
	})
}

// processServiceResult 处理服务识别结果
func processServiceResult(host string, port int, addr string, serviceInfo *ServiceInfo, config *common.Config) {
	if serviceInfo == nil {
		// 服务识别失败，尝试 HTTP 回退探测
		if !tryHTTPFallbackDetection(host, port, addr, config) {
			common.LogInfo(i18n.Tr("port_open", addr))
		}
		return
	}

	// 保存并输出服务信息
	details := buildServiceDetails(port, serviceInfo)
	isWeb := IsWebServiceByFingerprint(serviceInfo)

	if isWeb {
		details["is_web"] = true
		MarkAsWebService(host, port, serviceInfo)
	}

	_ = common.SaveResult(&output.ScanResult{
		Time:    time.Now(),
		Type:    output.TypeService,
		Target:  fmt.Sprintf("%s:%d", host, port),
		Status:  "identified",
		Details: details,
	})

	common.LogInfo(buildServiceLogMessage(addr, serviceInfo, isWeb))
}

// buildServiceDetails 构建服务详情 map
func buildServiceDetails(port int, info *ServiceInfo) map[string]interface{} {
	details := map[string]interface{}{
		"port":    port,
		"service": info.Name,
	}

	if info.Version != "" {
		details["version"] = info.Version
	}

	extraKeyMap := map[string]string{
		"vendor_product": "product",
		"os":             "os",
		"info":           "info",
	}

	for k, v := range info.Extras {
		if v == "" {
			continue
		}
		if mappedKey, ok := extraKeyMap[k]; ok {
			details[mappedKey] = v
		}
	}

	if len(info.Banner) > 0 {
		details["banner"] = strings.TrimSpace(info.Banner)
	}

	return details
}

// tryHTTPFallbackDetection 尝试HTTP回退探测，返回是否成功识别为HTTP服务
func tryHTTPFallbackDetection(host string, port int, addr string, config *common.Config) bool {
	// 使用WebDetection进行HTTP协议探测
	webDetector := GetWebPortDetector()
	if !webDetector.DetectHTTPServiceOnly(host, port, config) {
		return false
	}

	// HTTP探测成功，标记为Web服务
	webServiceInfo := &ServiceInfo{
		Name:    "http",
		Version: "",
		Banner:  "",
		Extras:  map[string]string{"detected_by": "http_probe"},
	}
	MarkAsWebService(host, port, webServiceInfo)

	// 保存HTTP服务结果
	details := map[string]interface{}{
		"port":        port,
		"service":     "http",
		"is_web":      true,
		"detected_by": "http_probe",
	}
	_ = common.SaveResult(&output.ScanResult{
		Time:    time.Now(),
		Type:    output.TypeService,
		Target:  fmt.Sprintf("%s:%d", host, port),
		Status:  "identified",
		Details: details,
	})

	common.LogInfo(i18n.Tr("port_open_http", addr))
	return true
}
