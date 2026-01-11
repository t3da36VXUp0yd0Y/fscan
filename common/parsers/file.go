package parsers

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common/i18n"
)

// FileReader 高性能文件读取器
type FileReader struct {
	mu               sync.RWMutex
	cache            map[string]*FileResult // 文件缓存
	maxCacheSize     int                    // 最大缓存大小
	enableCache      bool                   // 是否启用缓存
	maxFileSize      int64                  // 最大文件大小
	timeout          time.Duration          // 读取超时
	enableValidation bool                   // 是否启用内容验证
}

// FileResult 文件读取结果
type FileResult struct {
	Lines      []string      `json:"lines"`
	Source     *FileSource   `json:"source"`
	ReadTime   time.Duration `json:"read_time"`
	ValidLines int           `json:"valid_lines"`
	Errors     []error       `json:"errors,omitempty"`
	Cached     bool          `json:"cached"`
}

// NewFileReader 创建文件读取器
func NewFileReader(options *FileReaderOptions) *FileReader {
	if options == nil {
		options = DefaultFileReaderOptions()
	}

	return &FileReader{
		cache:            make(map[string]*FileResult),
		maxCacheSize:     options.MaxCacheSize,
		enableCache:      options.EnableCache,
		maxFileSize:      options.MaxFileSize,
		timeout:          options.Timeout,
		enableValidation: options.EnableValidation,
	}
}

// FileReaderOptions 文件读取器选项
type FileReaderOptions struct {
	MaxCacheSize     int           // 最大缓存文件数
	EnableCache      bool          // 启用文件缓存
	MaxFileSize      int64         // 最大文件大小(字节)
	Timeout          time.Duration // 读取超时
	EnableValidation bool          // 启用内容验证
	TrimSpace        bool          // 自动清理空白字符
	SkipEmpty        bool          // 跳过空行
	SkipComments     bool          // 跳过注释行(#开头)
}

// DefaultFileReaderOptions 默认文件读取器选项
func DefaultFileReaderOptions() *FileReaderOptions {
	return &FileReaderOptions{
		MaxCacheSize:     DefaultMaxCacheSize,
		EnableCache:      DefaultEnableCache,
		MaxFileSize:      DefaultFileReaderMaxFileSize,
		Timeout:          DefaultFileReaderTimeout,
		EnableValidation: DefaultFileReaderEnableValidation,
		TrimSpace:        DefaultTrimSpace,
		SkipEmpty:        DefaultSkipEmpty,
		SkipComments:     DefaultSkipComments,
	}
}

// ReadFile 读取文件内容
func (fr *FileReader) ReadFile(filename string, options ...*FileReaderOptions) (*FileResult, error) {
	if filename == "" {
		return nil, NewParseError("FILE_ERROR", "文件名为空", filename, 0, ErrEmptyInput)
	}

	// 检查缓存
	if fr.enableCache {
		if result := fr.getFromCache(filename); result != nil {
			result.Cached = true
			return result, nil
		}
	}

	// 合并选项
	opts := fr.mergeOptions(options...)

	// 创建带超时的上下文 - 使用合并后的超时配置
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	// 异步读取文件
	resultChan := make(chan *FileResult, 1)
	errorChan := make(chan error, 1)

	go func() {
		result, err := fr.readFileSync(filename, opts)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()

	// 等待结果或超时
	select {
	case result := <-resultChan:
		// 添加到缓存
		if fr.enableCache {
			fr.addToCache(filename, result)
		}
		return result, nil
	case err := <-errorChan:
		return nil, err
	case <-ctx.Done():
		return nil, NewParseError(ErrorTypeTimeout, "文件读取超时", filename, 0, ctx.Err())
	}
}

// =============================================================================================
// 已删除的死代码（未使用）：ReadFiles 并发读取多个文件的方法
// =============================================================================================

// readFileSync 同步读取文件
func (fr *FileReader) readFileSync(filename string, options *FileReaderOptions) (*FileResult, error) {
	startTime := time.Now()

	// 检查文件
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return nil, NewParseError("FILE_ERROR", "文件不存在或无法访问", filename, 0, err)
	}

	// 检查文件大小 - 使用传入的配置选项
	if fileInfo.Size() > options.MaxFileSize {
		return nil, NewParseError("FILE_ERROR",
			fmt.Sprintf("文件过大: %d bytes, 最大限制: %d bytes", fileInfo.Size(), options.MaxFileSize),
			filename, 0, nil)
	}

	// 打开文件
	file, err := os.Open(filename)
	if err != nil {
		return nil, NewParseError("FILE_ERROR", "无法打开文件", filename, 0, err)
	}
	defer func() { _ = file.Close() }() // 只读文件，Close错误可安全忽略

	// 创建结果
	result := &FileResult{
		Lines: make([]string, 0),
		Source: &FileSource{
			Path:    filename,
			Size:    fileInfo.Size(),
			ModTime: fileInfo.ModTime(),
		},
	}

	// 读取文件内容
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	lineNum := 0
	validLines := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// 处理行内容
		if processedLine, valid := fr.processLine(line, options); valid {
			result.Lines = append(result.Lines, processedLine)
			validLines++
		}
	}

	// 检查扫描错误
	if err := scanner.Err(); err != nil {
		return nil, NewParseError(ErrorTypeReadError, i18n.GetText("parser_file_scan_failed"), filename, lineNum, err)
	}

	// 更新统计信息
	result.Source.LineCount = lineNum
	result.Source.ValidLines = validLines
	result.ValidLines = validLines
	result.ReadTime = time.Since(startTime)

	return result, nil
}

// processLine 处理单行内容
func (fr *FileReader) processLine(line string, options *FileReaderOptions) (string, bool) {
	// 清理空白字符
	if options.TrimSpace {
		line = strings.TrimSpace(line)
	}

	// 跳过空行
	if options.SkipEmpty && line == "" {
		return "", false
	}

	// 跳过注释行
	if options.SkipComments && strings.HasPrefix(line, CommentPrefix) {
		return "", false
	}

	// 内容验证
	if options.EnableValidation && fr.enableValidation {
		if !fr.validateLine(line) {
			return "", false
		}
	}

	return line, true
}

// validateLine 验证行内容
func (fr *FileReader) validateLine(line string) bool {
	// 基本验证：检查是否包含特殊字符或过长
	if len(line) > MaxLineLength { // 单行最大字符数
		return false
	}

	// 检查是否包含控制字符
	for _, r := range line {
		if r < MaxValidRune && r != TabRune && r != NewlineRune && r != CarriageReturnRune { // 排除tab、换行、回车
			return false
		}
	}

	return true
}

// mergeOptions 合并选项
func (fr *FileReader) mergeOptions(options ...*FileReaderOptions) *FileReaderOptions {
	opts := DefaultFileReaderOptions()
	if len(options) > 0 && options[0] != nil {
		opts = options[0]
	}
	return opts
}

// getFromCache 从缓存获取结果
func (fr *FileReader) getFromCache(filename string) *FileResult {
	fr.mu.RLock()
	result, exists := fr.cache[filename]
	if !exists {
		fr.mu.RUnlock()
		return nil
	}

	// 检查文件是否有更新
	fileInfo, err := os.Stat(filename)
	if err != nil {
		fr.mu.RUnlock()
		return result
	}

	if fileInfo.ModTime().After(result.Source.ModTime) {
		// 文件已更新，需要删除缓存 - 使用双重检查锁定模式
		fr.mu.RUnlock() // 释放读锁

		fr.mu.Lock() // 获取写锁
		// 重新检查条件（双重检查，因为在锁切换期间状态可能改变）
		if cachedResult, stillExists := fr.cache[filename]; stillExists {
			if reCheckInfo, reCheckErr := os.Stat(filename); reCheckErr == nil {
				if reCheckInfo.ModTime().After(cachedResult.Source.ModTime) {
					delete(fr.cache, filename)
				}
			}
		}
		fr.mu.Unlock() // 释放写锁
		return nil
	}

	fr.mu.RUnlock()
	return result
}

// addToCache 添加到缓存
func (fr *FileReader) addToCache(filename string, result *FileResult) {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	// 检查缓存大小
	if len(fr.cache) >= fr.maxCacheSize {
		// 移除最旧的条目（简单的LRU策略）
		var oldestFile string
		var oldestTime time.Time
		for file, res := range fr.cache {
			if oldestFile == "" || res.Source.ModTime.Before(oldestTime) {
				oldestFile = file
				oldestTime = res.Source.ModTime
			}
		}
		delete(fr.cache, oldestFile)
	}

	fr.cache[filename] = result
}

// =============================================================================================
// 已删除的死代码（未使用）：ClearCache 和 GetCacheStats 方法
// =============================================================================================
