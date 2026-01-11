package core

import (
	"sync"
)

// SocketIterator 流式生成 host:port 组合
// 设计原则：O(1) 内存，按需生成
// 使用端口喷洒策略：Port1全IP -> Port2全IP -> ...
// 优势：流量分散，避免单IP限速
type SocketIterator struct {
	hosts   []string
	ports   []int
	hostIdx int
	portIdx int
	total   int
	mu      sync.Mutex
}

// NewSocketIterator 创建流式迭代器
func NewSocketIterator(hosts []string, ports []int, exclude map[int]struct{}) *SocketIterator {
	validPorts := filterExcludedPorts(ports, exclude)
	return &SocketIterator{
		hosts: hosts,
		ports: validPorts,
		total: len(hosts) * len(validPorts),
	}
}

// Next 返回下一个 host:port 组合，ok=false 表示迭代结束
// 端口喷洒顺序：先遍历所有IP的同一端口，再换下一个端口
func (it *SocketIterator) Next() (string, int, bool) {
	it.mu.Lock()
	defer it.mu.Unlock()

	// 空输入或迭代结束
	if len(it.hosts) == 0 || it.portIdx >= len(it.ports) {
		return "", 0, false
	}

	host := it.hosts[it.hostIdx]
	port := it.ports[it.portIdx]

	// 端口喷洒：先遍历所有IP，再换端口
	it.hostIdx++
	if it.hostIdx >= len(it.hosts) {
		it.hostIdx = 0
		it.portIdx++
	}

	return host, port, true
}

// Total 返回总任务数（用于进度条）
func (it *SocketIterator) Total() int {
	return it.total
}

// filterExcludedPorts 过滤排除的端口
func filterExcludedPorts(ports []int, exclude map[int]struct{}) []int {
	if len(exclude) == 0 {
		return ports
	}
	result := make([]int, 0, len(ports))
	for _, p := range ports {
		if _, excluded := exclude[p]; !excluded {
			result = append(result, p)
		}
	}
	return result
}
