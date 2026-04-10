package proguard

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// Layer 1: Parse (Text → AST)
//
// Input:  R8 mapping.txt
// Output: structured AST (Pre-IR), no IDs, no offsets — pure string-based.
//
// Supports:
//   - Class / Method / Field parsing
//   - Inline frames (same obf line → multiple frames)
//   - Metadata (# JSON with "id" field)
//   - Metadata attachment: method-level first, then class-level
// ---------------------------------------------------------------------------

const (
	maxLineLength = 1024 * 1024 // 1 MB
	arrow         = " -> "
	arrowLen      = len(arrow)
)

// OnClass 是一个回调函数类型，用于在解析过程中输出每个解析到的 ASTClass 对象。
type OnClass func(cls *ASTClass) error

// ---------------------------------------------------------------------------
// AST types — pure strings, no IDs, no offsets
// ---------------------------------------------------------------------------

// ASTClass 类映射信息
// 包含原始类名、混淆类名、方法列表、字段列表和类级别的元数据。
type ASTClass struct {
	OriName  string         // e.g. "com.example.MyClass"
	ObfName  string         // e.g. "a.b.c"
	Methods  []*ASTMethod   // 方法映射列表
	Fields   []*ASTField    // 字段映射列表
	Metadata []*ASTMetadata // class-level metadata (R8)
}

// ASTField 字段映射信息
// 包含字段类型、原始字段名和混淆字段名。
type ASTField struct {
	Type    string // 类型, e.g. "android.widget.TextView"
	OriName string // 原始字段名, e.g. "textView"
	ObfName string // 混淆字段名, e.g. "a"
}

// ASTMethod 方法映射信息
// 包含原始方法名、混淆方法名、返回类型、参数类型列表、行号组和方法级别的元数据。
// 行号组（LineGroups）表示一个混淆行号范围映射到一个或多个原始方法帧（InlineFrames）。
// 如果一个混淆行号范围对应多个原始帧，则表示该方法被内联了。
type ASTMethod struct {
	ObfName    string          // 混淆方法名
	OriName    string          // 原始方法名
	Return     string          // 返回类型
	Args       []string        // 参数列表
	LineGroups []*ASTLineGroup // line number groups (one per obf range)
	Metadata   []*ASTMetadata  // method-level metadata (R8)
}

// ASTLineGroup 混淆行号范围和原始帧的映射
// 包含混淆行号的起始和结束，以及对应的原始方法帧列表（可能有多个，表示内联）。
type ASTLineGroup struct {
	ObfStart int               // 混淆行号起始
	ObfEnd   int               // 混淆行号结束
	Frames   []*ASTInlineFrame // 原始方法帧列表（多个表示内联）
}

// ASTInlineFrame 表示一个原始方法帧，包含原始类名、原始方法名、返回类型、参数类型列表以及原始行号范围。
// 当一个混淆行号范围对应多个ASTInlineFrame时，表示这些方法帧被内联了。
type ASTInlineFrame struct {
	OriClass  string   // original class (may differ from enclosing class)
	OriMethod string   // original method name
	Return    string   // return type
	Args      []string // parameter types
	OriStart  int      // original line start
	OriEnd    int      // original line end
}

// ASTMetadata represents an R8 metadata comment line.
// Format: # {"id":"...", "conditions":[...], "actions":[...]}
type ASTMetadata struct {
	ID         string   // e.g. "com.android.tools.r8.synthesized"
	Conditions []string // condition expressions
	Actions    []string // action expressions
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

// ParseReaderStream 从给定的 io.Reader 逐行解析 ProGuard/R8 mapping 数据，并通过 onClass 回调输出每个解析到的 ASTClass 对象。
func ParseReaderStream(r io.Reader, onClass OnClass) error {
	if onClass == nil {
		return fmt.Errorf("onClass callback is required")
	}

	scanner := bufio.NewScanner(r)
	// 默认的Scanner缓冲区为64KB，如果行超过这个长度，Scanner会返回错误。为了支持更长的行，我们需要增加缓冲区大小。
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineLength)

	var (
		curCls    *ASTClass
		curMethod *ASTMethod
		lineNo    int // 当前行号，用于错误报告和调试
	)

	emitCls := func() error {
		if curCls == nil {
			return nil
		}
		if err := onClass(curCls); err != nil {
			return err
		}
		return nil
	}

	// 逐行扫描输入
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++

		// Skip 空行
		if len(line) == 0 {
			continue
		}

		// 检查元数据行：以#开头，并且包含带有"id"字段的JSON
		if line[0] == '#' || (len(line) > 4 && line[0] == ' ' && strings.TrimSpace(line)[0] == '#') {
			trimmed := strings.TrimSpace(line)
			if meta := tryParseMetadata(trimmed); meta != nil {
				if curMethod != nil {
					curMethod.Metadata = append(curMethod.Metadata, meta)
				} else if curCls != nil {
					curCls.Metadata = append(curCls.Metadata, meta)
				}
				continue
			}
			// 普通注释行，忽略
			continue
		}

		// 类：没有前导空格，且以冒号结尾
		if line[0] != ' ' && line[0] != '\t' {
			c, err := parseClassLine(line, lineNo)
			if err != nil {
				// 解析失败，可能是格式不正确，跳过并继续解析后续行
				continue
			}
			// 遇到新类时，先将之前的类（如果有）通过回调输出，然后开始解析新类
			if err := emitCls(); err != nil {
				return err
			}
			curCls = c
			curMethod = nil
			continue
		}

		// 此时应该是方法或字段，但如果 curClass 为空，说明没有有效的类上下文，skip.
		if curCls == nil {
			continue
		}
		// 方法或字段：有前导空格，且包含 " -> "
		parseMemberLine(curCls, &curMethod, line, lineNo)
	}

	// 检查扫描过程中是否发生错误
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanning mapping file: %w", err)
	}

	// 最后一个类也需要通过回调输出
	if err := emitCls(); err != nil {
		return err
	}

	return nil
}

// tryParseMetadata 尝试解析元数据(R8)，返回 ASTMetadata 对象
// Metadata format: # {"id":"...", ...}
// Rule: 必须以#开头，后面跟一个JSON对象，且JSON对象必须包含"id"字段。
func tryParseMetadata(line string) *ASTMetadata {
	if len(line) < 2 || line[0] != '#' {
		return nil
	}
	content := strings.TrimSpace(line[1:])
	if len(content) == 0 || content[0] != '{' {
		return nil
	}

	// 解析JSON
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		return nil
	}

	// "id"字段是必须的，且必须是字符串
	idVal, ok := raw["id"]
	if !ok {
		return nil
	}
	idStr, ok := idVal.(string)
	if !ok {
		return nil
	}

	meta := &ASTMetadata{ID: idStr}

	// conditions解析
	if conds, ok := raw["conditions"]; ok {
		if condList, ok := conds.([]interface{}); ok {
			for _, c := range condList {
				if s, ok := c.(string); ok {
					meta.Conditions = append(meta.Conditions, s)
				}
			}
		}
	}

	// actions解析
	if actions, ok := raw["actions"]; ok {
		if actionList, ok := actions.([]interface{}); ok {
			for _, a := range actionList {
				if s, ok := a.(string); ok {
					meta.Actions = append(meta.Actions, s)
				}
			}
		}
	}

	return meta
}

// 解析类，格式为 "com.example.MyClass -> a.b.c:"
// Format: "com.example.MyClass -> a.b.c:"
func parseClassLine(line string, lineNo int) (*ASTClass, error) {
	if !strings.HasSuffix(line, ":") {
		return nil, fmt.Errorf("line %d: expected class line ending with ':', got: %s", lineNo, line)
	}
	line = line[:len(line)-1] // trim trailing ':'
	idx := strings.Index(line, arrow)
	if idx < 0 {
		return nil, fmt.Errorf("line %d: missing ' -> ' in class line: %s", lineNo, line)
	}
	return &ASTClass{
		OriName: strings.TrimSpace(line[:idx]),
		ObfName: strings.TrimSpace(line[idx+arrowLen:]),
	}, nil
}

// parseMemberLine 解析方法/字段，并将其附加到当前类中。
// 同时将具有相同混淆行号范围的内联帧分组在一起，附加到当前方法的行号组中。
//
// Method formats:
//
//	1:3:void onCreate(android.os.Bundle):15:17 -> onCreate
//	void method() -> a
//
// Field format:
//
//	android.widget.TextView textView -> a
func parseMemberLine(cls *ASTClass, curMethod **ASTMethod, line string, lineNo int) {
	trimmed := strings.TrimSpace(line)
	arrowIdx := strings.LastIndex(trimmed, arrow)
	if arrowIdx < 0 {
		return
	}
	left := trimmed[:arrowIdx]
	obfName := strings.TrimSpace(trimmed[arrowIdx+arrowLen:])

	// 区分方法和字段：如果没有括号，认为是字段，否则是方法
	if !strings.Contains(left, "(") {
		// 如果是字段，需要把curMethod置空，因为字段属于类，而不是方法
		*curMethod = nil
		parts := strings.SplitN(left, " ", 2)
		if len(parts) != 2 {
			return
		}
		cls.Fields = append(cls.Fields, &ASTField{
			Type:    strings.TrimSpace(parts[0]),
			OriName: strings.TrimSpace(parts[1]),
			ObfName: obfName,
		})
		return
	}

	// 解析方法
	// Format: [obfStart:obfEnd:]returnType oriName(args)[:oriStart[:oriEnd]]
	// <混淆后行号范围>:<返回类型> <方法签名>:<原始行号> -> <混淆后方法名>
	// 1:3:void onCreate(android.os.Bundle):15:17 -> onCreate

	// obfStart = 1, obfEnd = 3, rest = "void onCreate(android.os.Bundle):15:17", hasRange = true
	obfStart, obfEnd, rest, hasRange := extractObfLineRange(left)
	retType, oriMethod, args, oriStart, oriEnd, oriClass := parseMethodSignature(rest, cls.OriName)

	frame := &ASTInlineFrame{
		OriClass:  oriClass,
		OriMethod: oriMethod,
		Return:    retType,
		Args:      args,
		OriStart:  oriStart,
		OriEnd:    oriEnd,
	}

	// 如果有行号范围，尝试将其附加到当前方法的行号组中；如果没有行号范围，则创建一个新的方法条目。
	if hasRange {
		var tMethod *ASTMethod
		if *curMethod != nil && (*curMethod).ObfName == obfName {
			tMethod = *curMethod
		}
		if tMethod == nil {
			// Find or create method
			tMethod = findOrCreateMethod(cls, obfName, retType, oriMethod, args)
			*curMethod = tMethod
		}

		// 尝试找到具有相同混淆行号范围的行号组，如果找不到则创建一个新行号组
		var tGroup *ASTLineGroup
		for _, lg := range tMethod.LineGroups {
			if lg.ObfStart == obfStart && lg.ObfEnd == obfEnd {
				tGroup = lg
				break
			}
		}
		if tGroup == nil {
			tGroup = &ASTLineGroup{
				ObfStart: obfStart,
				ObfEnd:   obfEnd,
			}
			tMethod.LineGroups = append(tMethod.LineGroups, tGroup)
		}
		tGroup.Frames = append(tGroup.Frames, frame)
	} else {
		// 没有行号范围，创建一个新的方法条目
		m := &ASTMethod{
			ObfName: obfName,
			OriName: oriMethod,
			Return:  retType,
			Args:    args,
		}
		cls.Methods = append(cls.Methods, m)
		*curMethod = m
	}
}

// findOrCreateMethod 在类中查找具有指定混淆方法名的方法，如果不存在则创建一个新的方法条目。
func findOrCreateMethod(cls *ASTClass, obfName, retType, oriName string, args []string) *ASTMethod {
	for _, m := range cls.Methods {
		if m.ObfName == obfName {
			return m
		}
	}
	m := &ASTMethod{
		ObfName: obfName,
		OriName: oriName,
		Return:  retType,
		Args:    args,
	}
	cls.Methods = append(cls.Methods, m)
	return m
}

// extractObfLineRange 从方法行的开头提取混淆行号范围（如果存在）。
// Format: "start:end:rest" → (start, end, rest, true/false)
// Examples:
// "1:3:void onCreate(android.os.Bundle):15:17" → (1, 3, "void onCreate(android.os.Bundle):15:17", true)
// "void method() -> a" → (0, 0, "void method()", false)
// returns: (obfStart, obfEnd, restOfLine, hasRange)
func extractObfLineRange(s string) (int, int, string, bool) {
	firstColon := strings.Index(s, ":")
	if firstColon < 0 {
		return 0, 0, s, false
	}
	startStr := s[:firstColon]
	startN, err := strconv.Atoi(startStr)
	if err != nil {
		return 0, 0, s, false
	}
	rest := s[firstColon+1:]
	secondColon := strings.Index(rest, ":")
	if secondColon < 0 {
		return 0, 0, s, false
	}
	endStr := rest[:secondColon]
	endN, err := strconv.Atoi(endStr)
	if err != nil {
		return 0, 0, s, false
	}
	return startN, endN, rest[secondColon+1:], true
}

// parseMethodSignature 解析方法签名，提取返回类型、原始方法名、参数列表和原始行号范围。
// Format: "returnType qualifiedName.methodName(arg1,arg2):oriStart[:oriEnd]"
// Examples:
// "void onCreate(android.os.Bundle):15:17" → (void, onCreate, [android.os.Bundle], 15, 17, defaultClass)
// "int helper() -> a" → (int, helper, [], 0, 0, defaultClass)
func parseMethodSignature(s, defaultClass string) (retType, oriMethod string, args []string, oriStart, oriEnd int, oriClass string) {
	oriClass = defaultClass

	// Extract trailing :oriStart[:oriEnd]
	// Work from right: find the last ')' then look for ':' after it
	parenClose := strings.LastIndex(s, ")")
	if parenClose < 0 {
		return s, "", nil, 0, 0, oriClass
	}
	afterParen := s[parenClose+1:]
	sigPart := s[:parenClose+1]

	// Parse :oriStart[:oriEnd] from afterParen
	if len(afterParen) > 0 && afterParen[0] == ':' {
		lineInfo := afterParen[1:]
		colonIdx := strings.Index(lineInfo, ":")
		if colonIdx >= 0 {
			oriStart, _ = strconv.Atoi(lineInfo[:colonIdx])
			oriEnd, _ = strconv.Atoi(lineInfo[colonIdx+1:])
		} else {
			oriStart, _ = strconv.Atoi(lineInfo)
			oriEnd = oriStart
		}
	}

	// Parse "returnType qualifiedOrSimpleName(args)"
	parenOpen := strings.Index(sigPart, "(")
	if parenOpen < 0 {
		return s, "", nil, oriStart, oriEnd, oriClass
	}

	beforeParen := sigPart[:parenOpen]
	argsStr := sigPart[parenOpen+1 : len(sigPart)-1] // between ( and )

	// Parse args
	if len(argsStr) > 0 {
		args = strings.Split(argsStr, ",")
	}

	// beforeParen = "returnType fullMethodName"
	spaceIdx := strings.Index(beforeParen, " ")
	if spaceIdx < 0 {
		return "", beforeParen, args, oriStart, oriEnd, oriClass
	}
	retType = beforeParen[:spaceIdx]
	fullName := beforeParen[spaceIdx+1:]

	// fullName may be "com.example.Class.method" or just "method"
	dotIdx := strings.LastIndex(fullName, ".")
	if dotIdx >= 0 {
		oriClass = fullName[:dotIdx]
		oriMethod = fullName[dotIdx+1:]
	} else {
		oriMethod = fullName
	}

	return retType, oriMethod, args, oriStart, oriEnd, oriClass
}
