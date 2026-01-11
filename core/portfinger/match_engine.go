package portfinger

import (
	"fmt"
	"regexp"
	"strings"
)

// parseMatchDirective 解析match/softmatch指令的通用实现
func (p *Probe) parseMatchDirective(data, prefix string, isSoft bool) (Match, error) {
	match := Match{IsSoft: isSoft}

	// 提取指令文本并解析语法
	matchText := data[len(prefix)+1:]
	directive := p.getDirectiveSyntax(matchText)

	// 分割文本获取pattern和版本信息
	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)
	if len(textSplited) == 0 {
		return match, fmt.Errorf("无效的%s指令格式", prefix)
	}

	pattern := textSplited[0]
	versionInfo := strings.Join(textSplited[1:], "")

	// 解码并编译正则表达式
	patternUnescaped, decodeErr := DecodePattern(pattern)
	if decodeErr != nil {
		return match, decodeErr
	}

	patternCompiled, compileErr := regexp.Compile(string(patternUnescaped))
	if compileErr != nil {
		return match, compileErr
	}

	match.Service = directive.DirectiveName
	match.Pattern = pattern
	match.PatternCompiled = patternCompiled
	match.VersionInfo = versionInfo

	return match, nil
}

// getMatch 解析match指令获取匹配规则
func (p *Probe) getMatch(data string) (Match, error) {
	return p.parseMatchDirective(data, "match", false)
}

// getSoftMatch 解析softmatch指令获取软匹配规则
func (p *Probe) getSoftMatch(data string) (Match, error) {
	return p.parseMatchDirective(data, "softmatch", true)
}

// MatchPattern 检查响应是否与匹配规则匹配
func (m *Match) MatchPattern(response []byte) bool {
	if m.PatternCompiled == nil {
		return false
	}

	matched := m.PatternCompiled.Match(response)
	if matched {
		// 提取匹配到的子组
		submatches := m.PatternCompiled.FindStringSubmatch(string(response))
		if len(submatches) > 1 {
			m.FoundItems = submatches[1:] // 排除完整匹配，只保留分组
		}
	}

	return matched
}
