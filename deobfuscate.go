package symx

import (
	"fmt"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// 统一反混淆接口
//
// 定义了跨文件类型（ProGuard / SourceMap / DWARF）的统一查询模型：
//   - Location（输入）：表示一个待反混淆的位置，由各类型提供具体实现
//   - Symbol（输出）：表示还原后的一个源码位置
//   - SymbolResult：一次查找的完整结果（含 1:N 帧展开）
//   - Deobfuscator：统一查询接口，各子包的 Decoder 实现此接口
//
// 调用方通过 DeobfuscatorManager（见 manager.go）按 buildId 自动路由，
// 无需关心底层文件类型。
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 统一输入 — Location 接口
//
// sealed 接口：通过未导出的 marker 方法限制，仅允许本包定义的实现。
// 各文件类型的查询输入差异较大，通过接口多态统一。
// ---------------------------------------------------------------------------

// Location 表示一个待反混淆的位置。
// 这是一个 sealed 接口，仅允许包内定义的实现类型。
type Location interface {
	// locationType 返回文件类型标识，同时作为 sealed marker 防止外部实现。
	locationType() uint8
}

// JavaLocation 表示 ProGuard/R8 混淆后的 Java/Kotlin 栈帧位置。
type JavaLocation struct {
	Class  string // 混淆后的类名（全限定，点分隔）
	Method string // 混淆后的方法名
	Line   int    // 混淆后的行号（0 表示不按行号匹配）
}

func (JavaLocation) locationType() uint8 { return ProGuard }

// JSLocation 表示 SourceMap 中生成代码的位置。
type JSLocation struct {
	Line   int // 生成代码的行号（0-based）
	Column int // 生成代码的列号（0-based）
}

func (JSLocation) locationType() uint8 { return SourceMap }

// NativeLocation 表示 DWARF 原生二进制中的地址位置。
type NativeLocation struct {
	Address uint64 // 程序计数器 / 内存地址
}

func (NativeLocation) locationType() uint8 { return Dwarf }

// ---------------------------------------------------------------------------
// 栈帧文本解析 — 从标准栈帧格式构造 Location
//
// 各类型提供独立的 Parse 函数，支持常见的栈帧文本格式。
// ---------------------------------------------------------------------------

// ParseJavaLocation 从 Java/Android 栈帧文本解析出 JavaLocation。
//
// 支持的格式：
//
//	"at com.example.Foo.bar(Foo.java:42)"     — 标准 Java stacktrace
//	"at com.example.Foo.bar(Foo.java)"        — 无行号
//	"at com.example.Foo.bar(Unknown Source)"   — 未知来源
//	"com.example.Foo.bar:42"                  — 简化格式（class.method:line）
//	"com.example.Foo.bar"                     — 仅 class.method
//
// 返回错误当文本无法解析为有效的 Java 栈帧时。
func ParseJavaLocation(text string) (JavaLocation, error) {
	text = strings.TrimSpace(text)

	// 去掉 "at " 前缀
	text = strings.TrimPrefix(text, "at ")

	// 格式 1：标准 Java stacktrace — "com.example.Foo.bar(Foo.java:42)"
	if parenIdx := strings.Index(text, "("); parenIdx > 0 {
		qualifiedMethod := text[:parenIdx]
		class, method, err := splitClassMethod(qualifiedMethod)
		if err != nil {
			return JavaLocation{}, err
		}

		line := 0
		// 提取括号内的内容
		closeIdx := strings.LastIndex(text, ")")
		if closeIdx > parenIdx+1 {
			inner := text[parenIdx+1 : closeIdx]
			// 尝试提取行号：inner 可能是 "Foo.java:42"、"Foo.java"、"Unknown Source" 等
			if colonIdx := strings.LastIndex(inner, ":"); colonIdx >= 0 {
				if n, err := strconv.Atoi(inner[colonIdx+1:]); err == nil {
					line = n
				}
			}
		}

		return JavaLocation{Class: class, Method: method, Line: line}, nil
	}

	// 格式 2：简化格式 — "com.example.Foo.bar:42" 或 "com.example.Foo.bar"
	line := 0
	methodPart := text
	if colonIdx := strings.LastIndex(text, ":"); colonIdx > 0 {
		if n, err := strconv.Atoi(text[colonIdx+1:]); err == nil {
			line = n
			methodPart = text[:colonIdx]
		}
	}

	class, method, err := splitClassMethod(methodPart)
	if err != nil {
		return JavaLocation{}, err
	}

	return JavaLocation{Class: class, Method: method, Line: line}, nil
}

// splitClassMethod 从 "com.example.Foo.bar" 中分离出类名和方法名。
// 规则：最后一个 '.' 之前是类名，之后是方法名。
func splitClassMethod(qualified string) (string, string, error) {
	dotIdx := strings.LastIndex(qualified, ".")
	if dotIdx <= 0 || dotIdx == len(qualified)-1 {
		return "", "", fmt.Errorf("symx: invalid java frame %q: cannot split class and method", qualified)
	}
	return qualified[:dotIdx], qualified[dotIdx+1:], nil
}

// ParseJSLocation 从 JavaScript 栈帧文本解析出 JSLocation。
//
// 支持的格式：
//
//	"at functionName (file.js:10:23)"   — V8 标准格式
//	"at file.js:10:23"                  — V8 无函数名
//	"functionName@file.js:10:23"        — Firefox/Safari 格式
//	"file.js:10:23"                     — 简化格式
//	"10:23"                             — 纯行列号
//
// 行号和列号都解析为 0-based（输入文本通常是 1-based，会自动减 1）。
// 返回错误当文本无法解析为有效的 JS 栈帧时。
func ParseJSLocation(text string) (JSLocation, error) {
	text = strings.TrimSpace(text)

	// 去掉 "at " 前缀
	text = strings.TrimPrefix(text, "at ")

	// 提取位置部分（括号内或 @ 之后或整个文本）
	posPart := text
	if parenOpen := strings.LastIndex(text, "("); parenOpen >= 0 {
		parenClose := strings.LastIndex(text, ")")
		if parenClose > parenOpen {
			posPart = text[parenOpen+1 : parenClose]
		}
	} else if atIdx := strings.Index(text, "@"); atIdx >= 0 {
		posPart = text[atIdx+1:]
	}

	// 从位置部分尾部提取 :line:col
	// posPart 可能是 "file.js:10:23" 或 "10:23"
	line, col, err := extractLineCol(posPart)
	if err != nil {
		return JSLocation{}, fmt.Errorf("symx: invalid js frame %q: %w", text, err)
	}

	return JSLocation{Line: line, Column: col}, nil
}

// extractLineCol 从 "....:line:col" 或 "line:col" 中提取行号和列号。
// 返回的行号和列号为 0-based（输入的 1-based 值自动减 1）。
func extractLineCol(s string) (int, int, error) {
	// 从末尾向前找最后两个 ':'
	lastColon := strings.LastIndex(s, ":")
	if lastColon < 0 {
		return 0, 0, fmt.Errorf("no line:col found in %q", s)
	}

	col, err := strconv.Atoi(s[lastColon+1:])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid column in %q", s)
	}

	rest := s[:lastColon]
	secondColon := strings.LastIndex(rest, ":")
	if secondColon < 0 {
		// 只有 "line:col" 格式
		line, err := strconv.Atoi(rest)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid line in %q", s)
		}
		return toZeroBased(line), toZeroBased(col), nil
	}

	line, err := strconv.Atoi(rest[secondColon+1:])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid line in %q", s)
	}

	return toZeroBased(line), toZeroBased(col), nil
}

// toZeroBased 将 1-based 值转换为 0-based，最小为 0。
func toZeroBased(v int) int {
	if v > 0 {
		return v - 1
	}
	return 0
}

// ParseNativeLocation 从原生栈帧文本解析出 NativeLocation。
//
// 支持的格式：
//
//	"0x7fff5fbff8c0"                     — 纯十六进制地址
//	"#0 0x00007fff5fbff8c0"              — 编号 + 地址
//	"#0 0x00007fff5fbff8c0 in main"      — 编号 + 地址 + 函数名
//
// 返回错误当文本无法解析为有效地址时。
func ParseNativeLocation(text string) (NativeLocation, error) {
	text = strings.TrimSpace(text)

	// 找到 0x 开头的十六进制地址
	fields := strings.Fields(text)
	for _, field := range fields {
		if strings.HasPrefix(field, "0x") || strings.HasPrefix(field, "0X") {
			addr, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(field, "0x"), "0X"), 16, 64)
			if err != nil {
				continue
			}
			return NativeLocation{Address: addr}, nil
		}
	}

	// 尝试直接作为十六进制数解析
	addr, err := strconv.ParseUint(text, 16, 64)
	if err != nil {
		return NativeLocation{}, fmt.Errorf("symx: invalid native frame %q: no hex address found", text)
	}
	return NativeLocation{Address: addr}, nil
}

// ---------------------------------------------------------------------------
// 统一输出 — Symbol + SymbolResult
//
// Symbol 采用公共字段 + Extra 扩展的设计：
//   - 公共字段覆盖所有类型共有的信息（文件、函数、行号、列号）
//   - Extra map 存放类型特有的扩展字段，不污染公共结构
//
// ProGuard Extra 字段约定（key → value type）：
//
//	"class"        string       — 原始完整类名
//	"returnType"   string       — 返回类型
//	"args"         string       — 参数类型（逗号分隔）
//	"frameKind"    FrameKind    — 帧类别（App / Synthetic / Platform）
//	"syntheticTag" SyntheticTag — 合成帧子类别标签
//	"hostClass"    string       — 合成帧归因宿主类
//	"hostMethod"   string       — 合成帧归因宿主方法
//
// SourceMap Extra 字段约定（key → value type）：
//
//	"srcIdx"       uint32       — 源文件在 sources 数组中的索引
//	"genCol"       uint32       — 匹配到的生成列号
// ---------------------------------------------------------------------------

// Symbol 表示还原后的一个源码位置（帧）。
type Symbol struct {
	File     string         // 原始源文件路径（ProGuard 为完整类名，SourceMap 为源文件路径）
	Function string         // 原始函数/方法名（SourceMap 暂为空）
	Line     int            // 原始行号（起始）
	LineEnd  int            // 原始行号（结束，不适用则为 0）
	Column   int            // 原始列号（不适用则为 0）
	Inlined  bool           // 是否为内联帧
	Extra    map[string]any // 类型特有的扩展字段，具体约定见上方注释
}

// SymbolResult 表示一次反混淆查找的结果。
// 一个混淆位置可能还原为多个 Symbol（如 ProGuard 内联帧展开为 1:N）。
type SymbolResult struct {
	Input   Location // 原始查询输入（回带）
	Symbols []Symbol // 还原后的符号帧列表
	Found   bool     // 是否找到匹配
}

// ---------------------------------------------------------------------------
// 统一反混淆接口 — Deobfuscator
//
// 各子包（proguard、smap、dwarf）的 Decoder 实现此接口。
// 调用方可直接使用，也可通过 DeobfuscatorManager 按 buildId 路由。
// ---------------------------------------------------------------------------

// Deobfuscator 定义了统一的反混淆能力。
type Deobfuscator interface {
	// Lookup 单次查询：给定一个混淆位置，返回还原结果。
	// 如果 Location 类型与 Deobfuscator 不匹配，返回 Found=false。
	Lookup(loc Location) SymbolResult

	// LookupStack 批量查询：给定一组混淆位置（栈帧），返回还原结果列表。
	// 返回的切片与输入切片一一对应，顺序一致。
	LookupStack(locs []Location) []SymbolResult

	// FileType 返回底层符号文件类型（SourceMap / ProGuard / Dwarf）。
	FileType() uint8

	// Close 释放 Deobfuscator 持有的资源。
	// 注意：如果 Deobfuscator 由 DeobfuscatorManager 管理，
	// 应通过 Manager.Close() 统一关闭，而非直接调用此方法。
	Close() error
}
