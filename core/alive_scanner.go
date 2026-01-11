package core

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/common/parsers"
)

/*
AliveScanner.go - 存活探测扫描器

专门用于主机存活探测，仅执行ICMP/Ping检测，
快速识别网络中的存活主机，不进行端口扫描。
*/

// AliveScanStrategy 存活探测扫描策略
type AliveScanStrategy struct {
	*BaseScanStrategy
	startTime time.Time
	stats     AliveStats
}

// AliveStats 存活探测统计信息
type AliveStats struct {
	TotalHosts    int           // 总主机数
	AliveHosts    int           // 存活主机数
	DeadHosts     int           // 死亡主机数
	ScanDuration  time.Duration // 扫描耗时
	SuccessRate   float64       // 成功率
	AliveHostList []string      // 存活主机列表
}

// NewAliveScanStrategy 创建新的存活探测扫描策略
func NewAliveScanStrategy() *AliveScanStrategy {
	return &AliveScanStrategy{
		BaseScanStrategy: NewBaseScanStrategy("存活探测", FilterNone),
		startTime:        time.Now(),
	}
}

// Name 返回策略名称
func (s *AliveScanStrategy) Name() string {
	return i18n.GetText("scan_strategy_alive_name")
}

// Description 返回策略描述
func (s *AliveScanStrategy) Description() string {
	return i18n.GetText("scan_strategy_alive_desc")
}

// Execute 执行存活探测扫描策略
func (s *AliveScanStrategy) Execute(config *common.Config, state *common.State, info common.HostInfo, ch chan struct{}, wg *sync.WaitGroup) {
	// 验证扫描目标
	if info.Host == "" {
		common.LogError(i18n.GetText("parse_error_target_empty"))
		return
	}

	// 输出存活探测开始信息
	common.LogBase(i18n.GetText("scan_alive_start"))

	// 执行存活探测
	s.performAliveScan(info, config, state)

	// 输出统计信息
	s.outputStats()
}

// performAliveScan 执行存活探测
func (s *AliveScanStrategy) performAliveScan(info common.HostInfo, config *common.Config, state *common.State) {
	// 解析目标主机
	fv := common.GetFlagVars()
	hosts, err := parsers.ParseIP(info.Host, fv.HostsFile, fv.ExcludeHosts)
	if err != nil {
		common.LogError(i18n.Tr("parse_target_failed", err))
		return
	}

	if len(hosts) == 0 {
		common.LogError(i18n.GetText("parse_error_no_hosts"))
		return
	}

	// 初始化统计信息
	s.stats.TotalHosts = len(hosts)
	s.stats.AliveHosts = 0
	s.stats.DeadHosts = 0

	// 显示扫描信息
	if len(hosts) == 1 {
		common.LogBase(i18n.Tr("alive_scan_start_single", hosts[0]))
	} else {
		common.LogBase(i18n.Tr("alive_scan_start_multi", len(hosts), hosts[0]))
	}

	// 执行存活检测
	aliveList := CheckLive(hosts, false, config, state) // 使用ICMP探测

	// 更新统计信息
	s.stats.AliveHosts = len(aliveList)
	s.stats.DeadHosts = s.stats.TotalHosts - s.stats.AliveHosts
	s.stats.ScanDuration = time.Since(s.startTime)
	s.stats.AliveHostList = aliveList // 存储存活主机列表

	if s.stats.TotalHosts > 0 {
		s.stats.SuccessRate = float64(s.stats.AliveHosts) / float64(s.stats.TotalHosts) * 100
	}
}

// outputStats 输出详细统计信息
func (s *AliveScanStrategy) outputStats() {
	// 输出分隔线
	common.LogBase("=" + strings.Repeat("=", 60))

	// 输出扫描结果摘要
	common.LogBase(i18n.GetText("scan_alive_summary_title"))

	// 基础统计
	common.LogBase(i18n.Tr("alive_total_hosts", s.stats.TotalHosts))
	common.LogBase(i18n.Tr("alive_hosts_count", s.stats.AliveHosts))
	common.LogBase(i18n.Tr("alive_dead_hosts", s.stats.DeadHosts))
	common.LogBase(i18n.Tr("alive_success_rate", fmt.Sprintf("%.2f%%", s.stats.SuccessRate)))
	common.LogBase(i18n.Tr("alive_scan_duration", s.stats.ScanDuration.Round(time.Millisecond)))

	// 如果有存活主机，显示详细列表
	if s.stats.AliveHosts > 0 {
		common.LogBase("")
		common.LogBase(i18n.GetText("scan_alive_hosts_list"))

		for i, host := range s.stats.AliveHostList {
			common.LogSuccess(i18n.Tr("alive_host_item", i+1, host))
		}
	}

	// 输出分隔线
	common.LogBase("=" + strings.Repeat("=", 60))
}

// PrepareTargets 存活探测不需要准备扫描目标
func (s *AliveScanStrategy) PrepareTargets(info common.HostInfo) []common.HostInfo {
	// 存活探测不需要返回目标列表，因为它不进行后续扫描
	return nil
}

// GetPlugins 存活探测不使用插件
func (s *AliveScanStrategy) GetPlugins(config *common.Config) ([]string, bool) {
	return []string{}, false
}
