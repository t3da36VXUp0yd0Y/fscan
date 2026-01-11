package parsers

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/shadow1ng/fscan/common/config"
)

/*
Simple.go - 简化版本的解析器函数

这个文件提供了简化但功能完整的解析函数，用于替代复杂的解析器架构。
保持与现有代码的接口兼容性，但大幅简化实现逻辑。
*/

// =============================================================================
// 简化的IP/主机解析函数
// =============================================================================

// ParseIP 解析各种格式的IP地址
// 支持单个IP、IP范围、CIDR和文件输入
func ParseIP(host string, filename string, nohosts ...string) ([]string, error) {
	var hosts []string

	// 如果提供了文件名，从文件读取主机列表
	if filename != "" {
		fileHosts, fileErr := readHostsFromFile(filename)
		if fileErr != nil {
			return nil, fmt.Errorf("读取主机文件失败: %w", fileErr)
		}
		hosts = append(hosts, fileHosts...)
	}

	// 解析主机参数
	if host != "" {
		hostList, hostErr := parseHostString(host)
		if hostErr != nil {
			return nil, fmt.Errorf("解析主机失败: %w", hostErr)
		}
		hosts = append(hosts, hostList...)
	}

	// 处理排除主机
	if len(nohosts) > 0 && nohosts[0] != "" {
		excludeList, excludeErr := parseHostString(nohosts[0])
		if excludeErr != nil {
			return nil, fmt.Errorf("解析排除主机失败: %w", excludeErr)
		}
		hosts = excludeHosts(hosts, excludeList)
	}

	// 去重和排序
	hosts = removeDuplicates(hosts)
	sort.Strings(hosts)

	if len(hosts) == 0 {
		return nil, fmt.Errorf("没有找到有效的主机")
	}

	return hosts, nil
}

// =============================================================================
// 简化的端口解析函数
// =============================================================================

// ParsePort 解析端口配置字符串为端口号列表
// 保持与 ParsePort 的接口兼容性
func ParsePort(ports string) []int {
	if ports == "" {
		return nil
	}

	var result []int

	// 处理预定义端口组
	ports = expandPortGroups(ports)

	// 按逗号分割
	for _, portStr := range strings.Split(ports, ",") {
		portStr = strings.TrimSpace(portStr)
		if portStr == "" {
			continue
		}

		// 处理端口范围 (如 1-100)
		if strings.Contains(portStr, "-") {
			rangePorts := parsePortRange(portStr)
			result = append(result, rangePorts...)
		} else {
			// 单个端口
			if port, err := strconv.Atoi(portStr); err == nil {
				if port >= MinPort && port <= MaxPort {
					result = append(result, port)
				}
			}
		}
	}

	// 去重和排序
	result = removeDuplicatePorts(result)
	sort.Ints(result)

	return result
}

// 已移除未使用的 ParsePortsFromString 方法

// =============================================================================
// 辅助函数
// =============================================================================

// readHostsFromFile 从文件读取主机列表
func readHostsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }() // 只读文件，Close错误可安全忽略

	var hosts []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, CommentPrefix) {
			hosts = append(hosts, line)
		}
	}

	return hosts, scanner.Err()
}

// parseHostString 解析主机字符串
func parseHostString(host string) ([]string, error) {
	var hosts []string

	// 按逗号分割多个主机
	for _, h := range strings.Split(host, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}

		// 检查是否为CIDR格式
		if strings.Contains(h, "/") {
			cidrHosts, err := parseIPCIDR(h, SimpleMaxHosts)
			if err != nil {
				return nil, fmt.Errorf("解析CIDR %s 失败: %w", h, err)
			}
			hosts = append(hosts, cidrHosts...)
		} else if strings.Contains(h, "-") && !strings.Contains(h, ":") {
			// IP范围格式 (如 192.168.1.1-10)
			rangeHosts, err := parseIPRangeString(h, SimpleMaxHosts)
			if err != nil {
				return nil, fmt.Errorf("解析IP范围 %s 失败: %w", h, err)
			}
			hosts = append(hosts, rangeHosts...)
		} else {
			// 单个主机
			hosts = append(hosts, h)
		}
	}

	return hosts, nil
}

// parsePortRange 解析端口范围
func parsePortRange(rangeStr string) []int {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil
	}

	start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))

	if err1 != nil || err2 != nil || start < MinPort || end > MaxPort || start > end {
		return nil
	}

	var ports []int
	for i := start; i <= end; i++ {
		ports = append(ports, i)
	}

	return ports
}

// expandPortGroups 展开端口组
func expandPortGroups(ports string) string {
	// 使用预定义的端口组
	portGroups := config.GetPortGroups()

	result := ports
	for group, portList := range portGroups {
		result = strings.ReplaceAll(result, group, portList)
	}

	return result
}

// excludeHosts 排除指定的主机
func excludeHosts(hosts, excludeList []string) []string {
	if len(excludeList) == 0 {
		return hosts
	}

	excludeMap := make(map[string]struct{})
	for _, exclude := range excludeList {
		excludeMap[exclude] = struct{}{}
	}

	var result []string
	for _, host := range hosts {
		if _, found := excludeMap[host]; !found {
			result = append(result, host)
		}
	}

	return result
}

// removeDuplicates 去除字符串重复项
func removeDuplicates(slice []string) []string {
	keys := make(map[string]struct{})
	var result []string

	for _, item := range slice {
		if _, found := keys[item]; !found {
			keys[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}

// removeDuplicatePorts 去除端口重复项
func removeDuplicatePorts(slice []int) []int {
	if len(slice) == 0 {
		return nil
	}

	keys := make(map[int]struct{}, len(slice))
	result := make([]int, 0, len(slice))

	for _, item := range slice {
		if _, found := keys[item]; !found {
			keys[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}
