package proguard

import (
	"bytes"
	"encoding/binary"
	"strings"

	"github.com/devcoze/symx"
)

// 编译期接口满足性检查
var _ symx.Deobfuscator = (*Decoder)(nil)

// ---------------------------------------------------------------------------
// 解码器 — 从 SymX 二进制文件中零拷贝读取 ProGuard/R8 映射数据。
//
// 工作流程：
//   1. 通过 symx.Engine 打开文件（mmap），解析 FixedHead + ExtendedHead
//   2. 从 ExtendedHead TLV 反序列化 Metadata，获取 Payload 各 section 布局
//   3. 构造 Decoder，持有 mmap 字节切片的各 section 视图（零拷贝）
//   4. 查找：二分查找 ClassIndex → 定位 DataBlock 数据区域 → 遍历方法/行号/帧
//
// Payload 布局（与 Builder 写入顺序一致）：
//   [DataBlock:DataBlockLen]  [ClassIndex:ClassCount*16]  [StringPool:StringPoolLen]
// ---------------------------------------------------------------------------

// Decoder 提供对 ProGuard/R8 二进制索引的只读访问。
// 所有字节切片均为 mmap 映射的子切片，零拷贝、零分配。
type Decoder struct {
	meta      Metadata // 从 ExtendedHead TLV 反序列化而来
	dataBlock []byte   // DataBlock 原始字节
	classIdx  []byte   // ClassIndex 原始字节（每条 16B）
	strPool   []byte   // StringPool 原始字节
}

// NewDecoder 从已打开的 symx.Engine 构造 Decoder。
// engine 必须是 ProGuard 类型文件（FileType == symx.ProGuard）。
func NewDecoder(engine *symx.Engine) (*Decoder, error) {
	if engine.FileType() != symx.ProGuard {
		return nil, symx.ErrInvalidFileType
	}

	// 从 ExtendedHead 反序列化 Metadata
	var meta Metadata
	if err := symx.UnmarshalTLVs(engine.ExtData(), &meta); err != nil {
		return nil, err
	}

	payload := engine.PayloadData()

	// 计算各 section 的偏移
	dataBlockEnd := meta.DataBlockLen
	classIdxLen := meta.ClassCount * classIndexEntrySize
	classIdxEnd := dataBlockEnd + classIdxLen
	// StringPool 紧随 ClassIndex 之后
	d := &Decoder{
		meta:      meta,
		dataBlock: payload[:dataBlockEnd],
		classIdx:  payload[dataBlockEnd:classIdxEnd],
		strPool:   payload[classIdxEnd:],
	}
	return d, nil
}

// Meta 返回文件级元数据。
func (d *Decoder) Meta() Metadata {
	return d.meta
}

// ---------------------------------------------------------------------------
// 字符串池读取（零拷贝）
// ---------------------------------------------------------------------------

// readStr 从字符串池中读取指定偏移处的字符串。
// 注意：会产生 []byte → string 的拷贝分配。仅在需要持有字符串结果时使用。
// 查找比较场景请使用 readStrBytes 或 compareStr 避免分配。
func (d *Decoder) readStr(off uint32) string {
	b := d.readStrBytes(off)
	if b == nil {
		return ""
	}
	return string(b)
}

// readStrBytes 从字符串池中读取指定偏移处的原始字节切片（零拷贝）。
// 返回的切片直接引用 mmap 内存，不产生分配。
// 调用者不应修改返回的切片。
func (d *Decoder) readStrBytes(off uint32) []byte {
	if off == 0 {
		return nil
	}
	if int(off)+2 > len(d.strPool) {
		return nil
	}
	length := binary.LittleEndian.Uint16(d.strPool[off : off+2])
	if length == 0 {
		return nil
	}
	start := off + 2
	end := start + uint32(length)
	if int(end) > len(d.strPool) {
		return nil
	}
	return d.strPool[start:end]
}

// compareStr 将字符串池中指定偏移处的字符串与目标字节切片进行比较（零分配）。
// 返回值含义与 bytes.Compare 相同：-1 表示池中字符串更小，0 表示相等，1 表示更大。
func (d *Decoder) compareStr(off uint32, target []byte) int {
	b := d.readStrBytes(off)
	if b == nil {
		if len(target) == 0 {
			return 0
		}
		return -1
	}
	return bytes.Compare(b, target)
}

// ---------------------------------------------------------------------------
// ClassIndex 二分查找
// ---------------------------------------------------------------------------

// classCount 返回类索引条目数量。
func (d *Decoder) classCount() int {
	return len(d.classIdx) / classIndexEntrySize
}

// classEntry 读取第 i 个 ClassIndex 条目。
func (d *Decoder) classEntry(i int) BinClassIndexEntry {
	off := i * classIndexEntrySize
	raw := d.classIdx[off : off+classIndexEntrySize]
	return BinClassIndexEntry{
		ObfName: binary.LittleEndian.Uint32(raw[0:4]),
		OriName: binary.LittleEndian.Uint32(raw[4:8]),
		DataOff: binary.LittleEndian.Uint32(raw[8:12]),
		DataLen: binary.LittleEndian.Uint32(raw[12:16]),
	}
}

// findClass 通过混淆类名二分查找 ClassIndex，返回条目索引和是否找到。
// 查找过程零分配：使用 compareStr 直接在 mmap 字节上比较。
func (d *Decoder) findClass(obfClass string) (int, bool) {
	target := []byte(obfClass) // 仅此一次分配
	lo, hi := 0, d.classCount()
	for lo < hi {
		mid := lo + (hi-lo)/2
		entry := d.classEntry(mid)
		cmp := d.compareStr(entry.ObfName, target)
		if cmp < 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < d.classCount() {
		entry := d.classEntry(lo)
		if d.compareStr(entry.ObfName, target) == 0 {
			return lo, true
		}
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// DataBlock 结构读取
// ---------------------------------------------------------------------------

// readClassDataHeader 从 DataBlock 指定偏移读取 ClassDataHeader。
func (d *Decoder) readClassDataHeader(off uint32) ClassDataHeader {
	raw := d.dataBlock[off : off+classDataHeaderSize]
	return ClassDataHeader{
		MethodCount: binary.LittleEndian.Uint16(raw[0:2]),
		FieldCount:  binary.LittleEndian.Uint16(raw[2:4]),
		MetaCount:   binary.LittleEndian.Uint16(raw[4:6]),
	}
}

// readMethodEntry 从 DataBlock 指定偏移读取 BinMethodEntry。
func (d *Decoder) readMethodEntry(off uint32) BinMethodEntry {
	raw := d.dataBlock[off : off+methodEntrySize]
	return BinMethodEntry{
		ObfName:   binary.LittleEndian.Uint32(raw[0:4]),
		OriName:   binary.LittleEndian.Uint32(raw[4:8]),
		Return:    binary.LittleEndian.Uint32(raw[8:12]),
		Args:      binary.LittleEndian.Uint32(raw[12:16]),
		LineOff:   binary.LittleEndian.Uint32(raw[16:20]),
		LineCount: binary.LittleEndian.Uint16(raw[20:22]),
		MetaOff:   binary.LittleEndian.Uint32(raw[22:26]),
		MetaCount: binary.LittleEndian.Uint16(raw[26:28]),
	}
}

// readLineEntry 从 DataBlock 指定偏移读取 BinLineEntry。
func (d *Decoder) readLineEntry(off uint32) BinLineEntry {
	raw := d.dataBlock[off : off+lineEntrySize]
	return BinLineEntry{
		ObfStart:   binary.LittleEndian.Uint32(raw[0:4]),
		ObfEnd:     binary.LittleEndian.Uint32(raw[4:8]),
		FrameOff:   binary.LittleEndian.Uint32(raw[8:12]),
		FrameCount: binary.LittleEndian.Uint16(raw[12:14]),
	}
}

// readFrameEntry 从 DataBlock 指定偏移读取 BinFrameEntry。
func (d *Decoder) readFrameEntry(off uint32) BinFrameEntry {
	raw := d.dataBlock[off : off+frameEntrySize]
	return BinFrameEntry{
		OriClass:  binary.LittleEndian.Uint32(raw[0:4]),
		OriMethod: binary.LittleEndian.Uint32(raw[4:8]),
		Return:    binary.LittleEndian.Uint32(raw[8:12]),
		Args:      binary.LittleEndian.Uint32(raw[12:16]),
		OriStart:  binary.LittleEndian.Uint32(raw[16:20]),
		OriEnd:    binary.LittleEndian.Uint32(raw[20:24]),
	}
}

// readMetadataEntry 从 DataBlock 指定偏移读取 BinMetadataEntry。
func (d *Decoder) readMetadataEntry(off uint32) BinMetadataEntry {
	raw := d.dataBlock[off : off+metadataEntrySize]
	return BinMetadataEntry{
		ID:      binary.LittleEndian.Uint32(raw[0:4]),
		CondOff: binary.LittleEndian.Uint32(raw[4:8]),
		ActOff:  binary.LittleEndian.Uint32(raw[8:12]),
	}
}

// readStringList 从 DataBlock 指定偏移读取字符串列表。
// 格式：[count:uint16][pad:uint16][strPoolOff:uint32*count]
func (d *Decoder) readStringList(off uint32) []string {
	raw := d.dataBlock[off:]
	count := binary.LittleEndian.Uint16(raw[0:2])
	if count == 0 {
		return nil
	}
	result := make([]string, count)
	for i := uint16(0); i < count; i++ {
		strOff := binary.LittleEndian.Uint32(raw[4+i*4 : 4+i*4+4])
		result[i] = d.readStr(strOff)
	}
	return result
}

// ---------------------------------------------------------------------------
// 帧类型定义 — 栈帧分级
// ---------------------------------------------------------------------------

// FrameKind 表示栈帧的类别，用于展示时的分级和折叠。
type FrameKind int

const (
	// FrameApp 应用帧 — 用户自己的代码，全量展示
	FrameApp FrameKind = iota
	// FrameSynthetic 合成帧 — 编译器生成的桥方法/lambda/匿名类，默认折叠
	FrameSynthetic
	// FramePlatform 平台帧 — android.*、java.*、kotlin.* 等系统类，默认隐藏
	FramePlatform
)

// String 返回帧类别的字符串表示。
func (k FrameKind) String() string {
	switch k {
	case FrameApp:
		return "app"
	case FrameSynthetic:
		return "synthetic"
	case FramePlatform:
		return "platform"
	default:
		return "unknown"
	}
}

// ---------------------------------------------------------------------------
// 合成帧标签 — 描述合成帧的具体类型
// ---------------------------------------------------------------------------

// SyntheticTag 描述合成帧的具体子类别，帮助展示层做更精细的归因和标注。
type SyntheticTag int

const (
	SynNone               SyntheticTag = iota // 非合成
	SynR8Synthesized                          // R8 元数据标记为 synthesized
	SynLambdaClass                            // $$Lambda$ 或 $$ExternalSyntheticLambda
	SynLambdaMethod                           // lambda$methodName$N 方法
	SynAccessBridge                           // access$NNN 桥方法
	SynAnonymousClass                         // Foo$1, Foo$1$2 匿名内部类
	SynEnumValues                             // values() / valueOf() 编译器生成的枚举方法
	SynDefaultConstructor                     // <init> / <clinit>（可选标记）
)

// String 返回合成标签的可读标注。
func (t SyntheticTag) String() string {
	switch t {
	case SynNone:
		return ""
	case SynR8Synthesized:
		return "[r8-synthesized]"
	case SynLambdaClass:
		return "[lambda-class]"
	case SynLambdaMethod:
		return "[lambda]"
	case SynAccessBridge:
		return "[bridge]"
	case SynAnonymousClass:
		return "[anonymous]"
	case SynEnumValues:
		return "[enum]"
	case SynDefaultConstructor:
		return "[init]"
	default:
		return "[synthetic]"
	}
}

// ---------------------------------------------------------------------------
// 反符号化结果类型
// ---------------------------------------------------------------------------

// Frame 表示反符号化后的一个栈帧。
// 一个混淆栈帧可能展开为多个 Frame（内联帧），最外层是实际执行的方法，
// 内层帧是被内联的调用者。
type Frame struct {
	ClassName  string       // 原始类名（全限定，点分隔）
	MethodName string       // 原始方法名
	ReturnType string       // 返回类型
	Args       string       // 参数类型（逗号分隔）
	LineStart  int          // 原始行号起始
	LineEnd    int          // 原始行号结束
	Kind       FrameKind    // 帧类别（App / Synthetic / Platform）
	Synthetic  SyntheticTag // 合成帧子类别标签
	HostClass  string       // 归因宿主类（合成帧被归因到的真实用户类）
	HostMethod string       // 归因宿主方法（合成帧被归因到的真实用户方法，可能为空）
	Inlined    bool         // 是否为内联帧
}

// DisplayName 返回适合展示的帧名称。
// 如果是合成帧且有宿主归因，返回 "HostClass.HostMethod [tag]" 格式。
// 否则返回 "ClassName.MethodName"。
func (f *Frame) DisplayName() string {
	if f.Synthetic != SynNone && f.HostClass != "" {
		base := f.HostClass
		if f.HostMethod != "" {
			base += "." + f.HostMethod
		}
		return base + " " + f.Synthetic.String()
	}
	return f.ClassName + "." + f.MethodName
}

// SymbolResult 表示一个混淆栈帧的完整反符号化结果。
type SymbolResult struct {
	// 输入（混淆信息）
	ObfClass  string // 混淆类名
	ObfMethod string // 混淆方法名
	ObfLine   int    // 混淆行号

	// 输出（反符号化结果）
	Frames []Frame // 展开后的帧列表（可能多个，表示内联栈）
	Found  bool    // 是否找到对应的映射
}

// ---------------------------------------------------------------------------
// 反符号化 — 核心查找逻辑
// ---------------------------------------------------------------------------

// Symbolicate 对单个混淆栈帧进行反符号化。
// 输入：混淆类名、混淆方法名、混淆行号。
// 输出：展开后的帧列表（含合成帧检测和归因），保留内联信息。
//
// 查找流程：
//  1. 二分查找 ClassIndex → 定位类数据区域
//  2. 读取 ClassDataHeader → 获取方法/字段/元数据数量
//  3. 读取类级别元数据 → 检查是否有 R8 synthesized 标记
//  4. 遍历方法条目 → 匹配混淆方法名
//  5. 对匹配的方法，遍历行号条目 → 匹配混淆行号
//  6. 展开帧数据 → 构造 Frame 列表
//  7. 对每个帧执行合成帧检测和归因
func (d *Decoder) Symbolicate(obfClass, obfMethod string, obfLine int) SymbolResult {
	result := SymbolResult{
		ObfClass:  obfClass,
		ObfMethod: obfMethod,
		ObfLine:   obfLine,
	}

	// 步骤 1：二分查找类
	idx, found := d.findClass(obfClass)
	if !found {
		return result
	}

	entry := d.classEntry(idx)
	oriClass := d.readStr(entry.OriName)
	dataOff := entry.DataOff

	// 步骤 2：读取 ClassDataHeader
	hdr := d.readClassDataHeader(dataOff)
	cursor := dataOff + classDataHeaderSize

	// 步骤 3：读取方法条目起始位置，跳过方法条目区域到字段/元数据
	methodsOff := cursor
	cursor += uint32(hdr.MethodCount) * methodEntrySize

	// 跳过字段条目
	cursor += uint32(hdr.FieldCount) * fieldEntrySize

	// 读取类级别元数据 — 检查 R8 synthesized 标记
	classSynthesized := false
	synthesizedID := []byte("com.android.tools.r8.synthesized") // 复用避免重复分配
	for i := uint16(0); i < hdr.MetaCount; i++ {
		// 元数据布局：条件列表 + 动作列表 + MetadataEntry
		// 实际上类级别元数据紧随字段条目之后写入，每条是：
		//   [条件列表][动作列表][MetadataEntry 12B]
		// 我们需要跳过条件列表和动作列表才能读到 MetadataEntry
		condCount := binary.LittleEndian.Uint16(d.dataBlock[cursor : cursor+2])
		cursor += metaListHeaderSize + uint32(condCount)*4

		actCount := binary.LittleEndian.Uint16(d.dataBlock[cursor : cursor+2])
		cursor += metaListHeaderSize + uint32(actCount)*4

		me := d.readMetadataEntry(cursor)
		cursor += metadataEntrySize

		if d.compareStr(me.ID, synthesizedID) == 0 {
			classSynthesized = true
		}
	}

	// 步骤 4：遍历方法条目，匹配混淆方法名
	obfMethodBytes := []byte(obfMethod) // 仅此一次分配
	for i := uint16(0); i < hdr.MethodCount; i++ {
		me := d.readMethodEntry(methodsOff + uint32(i)*methodEntrySize)
		if d.compareStr(me.ObfName, obfMethodBytes) != 0 {
			continue
		}

		oriMethod := d.readStr(me.OriName)
		retType := d.readStr(me.Return)
		args := d.readStr(me.Args)

		// 检查方法级别元数据中的 synthesized 标记
		methodSynthesized := false
		if me.MetaCount > 0 {
			mOff := me.MetaOff
			for j := uint16(0); j < me.MetaCount; j++ {
				condCount := binary.LittleEndian.Uint16(d.dataBlock[mOff : mOff+2])
				mOff += metaListHeaderSize + uint32(condCount)*4

				actCount := binary.LittleEndian.Uint16(d.dataBlock[mOff : mOff+2])
				mOff += metaListHeaderSize + uint32(actCount)*4

				mm := d.readMetadataEntry(mOff)
				mOff += metadataEntrySize

				if d.compareStr(mm.ID, synthesizedID) == 0 {
					methodSynthesized = true
				}
			}
		}

		// 步骤 5：如果方法没有行号映射（纯方法级别映射），直接构造帧
		if me.LineCount == 0 {
			frame := Frame{
				ClassName:  oriClass,
				MethodName: oriMethod,
				ReturnType: retType,
				Args:       args,
			}
			classifyFrame(&frame, classSynthesized, methodSynthesized)
			result.Frames = append(result.Frames, frame)
			result.Found = true
			continue
		}

		// 步骤 5：遍历行号条目，匹配混淆行号
		for li := uint16(0); li < me.LineCount; li++ {
			le := d.readLineEntry(me.LineOff + uint32(li)*lineEntrySize)

			// 如果 obfLine == 0，表示不按行号匹配（返回所有行号组）
			if obfLine != 0 && (uint32(obfLine) < le.ObfStart || uint32(obfLine) > le.ObfEnd) {
				continue
			}

			// 步骤 6：展开帧数据
			for fi := uint16(0); fi < le.FrameCount; fi++ {
				fe := d.readFrameEntry(le.FrameOff + uint32(fi)*frameEntrySize)
				frame := Frame{
					ClassName:  d.readStr(fe.OriClass),
					MethodName: d.readStr(fe.OriMethod),
					ReturnType: d.readStr(fe.Return),
					Args:       d.readStr(fe.Args),
					LineStart:  int(fe.OriStart),
					LineEnd:    int(fe.OriEnd),
					Inlined:    fi < le.FrameCount-1, // 最后一帧是实际执行的方法，前面的是被内联的
				}
				// 步骤 7：合成帧检测和归因
				classifyFrame(&frame, classSynthesized, methodSynthesized)
				result.Frames = append(result.Frames, frame)
			}
			result.Found = true

			// 如果指定了行号，找到第一个匹配的行号组即可
			if obfLine != 0 {
				break
			}
		}

		// 如果没有行号匹配但方法名匹配了，返回方法级别的结果
		if !result.Found {
			frame := Frame{
				ClassName:  oriClass,
				MethodName: oriMethod,
				ReturnType: retType,
				Args:       args,
			}
			classifyFrame(&frame, classSynthesized, methodSynthesized)
			result.Frames = append(result.Frames, frame)
			result.Found = true
		}

		// 找到匹配的方法即停止（可能有多个同名方法，但第一个匹配即可）
		break
	}

	return result
}

// ---------------------------------------------------------------------------
// 合成帧检测 — 基于 R8 metadata + 名字模式匹配
//
// 检测优先级：
//  1. R8 metadata 中的 synthesized 标记（最可靠）
//  2. 类名模式匹配（$$Lambda$, $$ExternalSyntheticLambda, $N 匿名类）
//  3. 方法名模式匹配（lambda$, access$, values/valueOf）
//  4. 平台类前缀匹配（android.*, java.*, kotlin.*, dalvik.*）
// ---------------------------------------------------------------------------

// classifyFrame 对单个帧执行合成帧检测，设置 Kind、Synthetic、HostClass、HostMethod。
func classifyFrame(f *Frame, classSynth, methodSynth bool) {
	// 优先级 1：R8 metadata 标记
	if classSynth || methodSynth {
		f.Kind = FrameSynthetic
		f.Synthetic = SynR8Synthesized
		attributeToHost(f)
		return
	}

	// 优先级 4（先检查平台类，因为平台类不需要进一步归因）
	if isPlatformClass(f.ClassName) {
		f.Kind = FramePlatform
		return
	}

	// 优先级 2：类名模式匹配
	if tag := detectSyntheticClass(f.ClassName); tag != SynNone {
		f.Kind = FrameSynthetic
		f.Synthetic = tag
		attributeToHost(f)
		return
	}

	// 优先级 3：方法名模式匹配
	if tag := detectSyntheticMethod(f.MethodName); tag != SynNone {
		f.Kind = FrameSynthetic
		f.Synthetic = tag
		attributeToHost(f)
		return
	}

	// 默认：应用帧
	f.Kind = FrameApp
}

// ---------------------------------------------------------------------------
// 平台类检测
// ---------------------------------------------------------------------------

// platformPrefixes 定义平台类的包前缀。
var platformPrefixes = []string{
	"android.",
	"androidx.",
	"java.",
	"javax.",
	"kotlin.",
	"kotlinx.",
	"dalvik.",
	"com.android.internal.",
	"sun.",
	"libcore.",
}

// isPlatformClass 检查类名是否属于平台类。
func isPlatformClass(className string) bool {
	for _, prefix := range platformPrefixes {
		if strings.HasPrefix(className, prefix) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// 合成类检测 — 基于类名模式
// ---------------------------------------------------------------------------

// detectSyntheticClass 基于类名模式检测合成类，返回合成标签。
func detectSyntheticClass(className string) SyntheticTag {
	// $$ExternalSyntheticLambda — R8 合成 lambda 类
	// 必须在 $$Lambda$ 之前检查，因为两者都含 "Lambda"
	if strings.Contains(className, "$$ExternalSyntheticLambda") {
		return SynLambdaClass
	}

	// $$Lambda$ — Java 8 lambda desugaring 生成的类
	if strings.Contains(className, "$$Lambda$") {
		return SynLambdaClass
	}

	// -$$Lambda — D8/R8 早期格式的 lambda 类
	if strings.Contains(className, "-$$Lambda") {
		return SynLambdaClass
	}

	// 匿名内部类：Foo$1, Foo$1$2, Foo$Bar$1 等
	// 规则：类名中最后一个 $ 后面是纯数字
	if isAnonymousInnerClass(className) {
		return SynAnonymousClass
	}

	return SynNone
}

// isAnonymousInnerClass 检查类名是否为匿名内部类。
// 匿名内部类的特征：最后一个 $ 后面是纯数字（如 Foo$1, Foo$Bar$2）。
func isAnonymousInnerClass(className string) bool {
	idx := strings.LastIndex(className, "$")
	if idx < 0 || idx == len(className)-1 {
		return false
	}
	suffix := className[idx+1:]
	for _, ch := range suffix {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// 合成方法检测 — 基于方法名模式
// ---------------------------------------------------------------------------

// detectSyntheticMethod 基于方法名模式检测合成方法，返回合成标签。
func detectSyntheticMethod(methodName string) SyntheticTag {
	// lambda$methodName$N — lambda 表达式编译生成的方法
	if strings.HasPrefix(methodName, "lambda$") {
		return SynLambdaMethod
	}

	// access$NNN — 内部类访问桥方法
	if strings.HasPrefix(methodName, "access$") {
		return SynAccessBridge
	}

	// <init> / <clinit> — 构造器和静态初始化块
	if methodName == "<init>" || methodName == "<clinit>" {
		return SynDefaultConstructor
	}

	// values() / valueOf() — 枚举编译器生成的方法
	if methodName == "values" || methodName == "valueOf" {
		return SynEnumValues
	}

	return SynNone
}

// ---------------------------------------------------------------------------
// 合成帧归因 — 将合成帧归因到宿主类/方法
//
// 归因规则：
//   1. $$Lambda$N / $$ExternalSyntheticLambdaN → 宿主是 $$ 之前的类名
//   2. lambda$methodName$N → 宿主方法是 methodName
//   3. access$NNN → 宿主是当前类（桥方法连接内部类与外部类）
//   4. Foo$1, Foo$2 → 宿主是 Foo
//   5. R8 synthesized → 尝试按类名模式归因
// ---------------------------------------------------------------------------

// attributeToHost 将合成帧归因到其宿主类和方法。
func attributeToHost(f *Frame) {
	switch f.Synthetic {
	case SynLambdaClass:
		// $$Lambda$ 或 $$ExternalSyntheticLambda → 宿主是 $$ 之前的部分
		if idx := strings.Index(f.ClassName, "$$"); idx > 0 {
			f.HostClass = f.ClassName[:idx]
		} else {
			f.HostClass = f.ClassName
		}

	case SynLambdaMethod:
		// lambda$methodName$N → 提取 methodName 作为宿主方法
		f.HostClass = f.ClassName
		parts := strings.SplitN(f.MethodName, "$", 3)
		if len(parts) >= 2 {
			f.HostMethod = parts[1] // "lambda" → methodName → N
		}

	case SynAccessBridge:
		// access$NNN → 宿主就是当前类
		f.HostClass = f.ClassName

	case SynAnonymousClass:
		// Foo$1 → 宿主是 Foo
		if idx := strings.LastIndex(f.ClassName, "$"); idx > 0 {
			f.HostClass = f.ClassName[:idx]
		} else {
			f.HostClass = f.ClassName
		}

	case SynR8Synthesized:
		// R8 synthesized：尝试按类名模式归因
		if idx := strings.Index(f.ClassName, "$$"); idx > 0 {
			f.HostClass = f.ClassName[:idx]
		} else if idx := strings.LastIndex(f.ClassName, "$"); idx > 0 {
			f.HostClass = f.ClassName[:idx]
		} else {
			f.HostClass = f.ClassName
		}

	default:
		f.HostClass = f.ClassName
	}
}

// ---------------------------------------------------------------------------
// 批量反符号化 — 处理完整栈帧列表
// ---------------------------------------------------------------------------

// StackInput 表示一个待反符号化的混淆栈帧。
type StackInput struct {
	ClassName  string // 混淆类名
	MethodName string // 混淆方法名
	LineNumber int    // 混淆行号
}

// SymbolicateStack 对一组混淆栈帧批量反符号化。
// 返回的 Frame 列表保持输入顺序，每个输入帧可能展开为多个 Frame（内联帧）。
func (d *Decoder) SymbolicateStack(stack []StackInput) []SymbolResult {
	results := make([]SymbolResult, len(stack))
	for i, input := range stack {
		results[i] = d.Symbolicate(input.ClassName, input.MethodName, input.LineNumber)
	}
	return results
}

// ---------------------------------------------------------------------------
// 折叠逻辑 — 对反符号化后的栈帧列表进行折叠
//
// 业界标准做法：
//   1. 合成帧归因到宿主 — 已在 classifyFrame/attributeToHost 完成
//   2. 栈帧分级 — 已在 classifyFrame 通过 Kind 字段标记
//   3. 折叠策略 — 由本节函数提供
//
// FoldedStack 将展开的帧列表按以下规则折叠：
//   - App 帧：保留，全量展示
//   - Synthetic 帧：折叠到相邻的 App 帧中
//   - Platform 帧：可选保留或隐藏
// ---------------------------------------------------------------------------

// FoldOptions 控制栈帧折叠行为。
type FoldOptions struct {
	HidePlatform  bool // 是否隐藏平台帧（android.*, java.* 等）
	HideSynthetic bool // 是否隐藏合成帧（lambda, bridge 等）
	FoldInlined   bool // 是否折叠内联帧（只显示最外层帧）
}

// DefaultFoldOptions 返回业界标准的默认折叠选项。
func DefaultFoldOptions() FoldOptions {
	return FoldOptions{
		HidePlatform:  false, // 平台帧默认保留但标记
		HideSynthetic: false, // 合成帧默认保留但标记
		FoldInlined:   false, // 内联帧默认展开
	}
}

// FoldedFrame 表示折叠后的栈帧，可能包含被折叠的子帧。
type FoldedFrame struct {
	Frame        Frame   // 主帧
	FoldedFrames []Frame // 被折叠进来的合成帧/内联帧
	Hidden       bool    // 是否应被隐藏（由 FoldOptions 决定）
}

// FoldStack 对反符号化后的完整栈帧列表执行折叠。
//
// 折叠策略：
//  1. 连续的合成帧合并到下一个（或上一个）App 帧的 FoldedFrames 中
//  2. 连续的平台帧保持独立但标记 Hidden
//  3. 内联帧组保持顺序（最外层帧在前）
//
// 输入是 SymbolicateStack 的输出（多个 SymbolResult），平铺为单一帧列表。
func FoldStack(results []SymbolResult, opts FoldOptions) []FoldedFrame {
	// 先平铺所有帧
	var allFrames []Frame
	for _, r := range results {
		allFrames = append(allFrames, r.Frames...)
	}

	if len(allFrames) == 0 {
		return nil
	}

	var folded []FoldedFrame
	var pendingSynthetic []Frame // 暂存的合成帧，等待归入下一个 App 帧

	for _, f := range allFrames {
		switch {
		case f.Kind == FrameSynthetic:
			// 合成帧：暂存，等归入下一个 App 帧（无论是否隐藏）
			pendingSynthetic = append(pendingSynthetic, f)

		case f.Kind == FramePlatform:
			// 平台帧：先刷新暂存的合成帧
			if len(pendingSynthetic) > 0 {
				folded = flushSyntheticFrames(folded, pendingSynthetic, opts)
				pendingSynthetic = nil
			}
			folded = append(folded, FoldedFrame{
				Frame:  f,
				Hidden: opts.HidePlatform,
			})

		default:
			// App 帧：将暂存的合成帧归入此帧
			ff := FoldedFrame{
				Frame:        f,
				FoldedFrames: pendingSynthetic,
				Hidden:       false,
			}
			pendingSynthetic = nil
			folded = append(folded, ff)
		}
	}

	// 处理尾部残留的合成帧
	if len(pendingSynthetic) > 0 {
		folded = flushSyntheticFrames(folded, pendingSynthetic, opts)
	}

	return folded
}

// flushSyntheticFrames 将暂存的合成帧刷新到结果中。
// 如果前面有 App 帧，合并到最后一个 App 帧的 FoldedFrames。
// 否则作为独立的 FoldedFrame 输出。
func flushSyntheticFrames(folded []FoldedFrame, pending []Frame, opts FoldOptions) []FoldedFrame {
	// 尝试归入最近的 App 帧
	for i := len(folded) - 1; i >= 0; i-- {
		if folded[i].Frame.Kind == FrameApp {
			folded[i].FoldedFrames = append(folded[i].FoldedFrames, pending...)
			return folded
		}
	}

	// 没有 App 帧可归入，作为独立帧输出
	for _, f := range pending {
		folded = append(folded, FoldedFrame{
			Frame:  f,
			Hidden: opts.HideSynthetic,
		})
	}
	return folded
}

// ---------------------------------------------------------------------------
// symx.Deobfuscator 接口实现
//
// 以下方法将 ProGuard 特有的 Symbolicate 能力适配到统一的 Deobfuscator 接口。
// 内部复用已有的 Symbolicate 方法，将 proguard.Frame 转换为 symx.Symbol。
// ---------------------------------------------------------------------------

// Lookup 实现 symx.Deobfuscator 接口。
// 接受 symx.JavaLocation 作为输入，内部调用 Symbolicate 并转换结果。
// 如果 Location 类型不匹配（非 JavaLocation），返回 Found=false。
func (d *Decoder) Lookup(loc symx.Location) symx.SymbolResult {
	jl, ok := loc.(symx.JavaLocation)
	if !ok {
		return symx.SymbolResult{Input: loc}
	}

	r := d.Symbolicate(jl.Class, jl.Method, jl.Line)

	symbols := make([]symx.Symbol, len(r.Frames))
	for i, f := range r.Frames {
		symbols[i] = frameToSymbol(f)
	}

	return symx.SymbolResult{
		Input:   loc,
		Symbols: symbols,
		Found:   r.Found,
	}
}

// LookupStack 实现 symx.Deobfuscator 接口。
// 对每个 Location 依次调用 Lookup，返回的切片与输入一一对应。
func (d *Decoder) LookupStack(locs []symx.Location) []symx.SymbolResult {
	results := make([]symx.SymbolResult, len(locs))
	for i, loc := range locs {
		results[i] = d.Lookup(loc)
	}
	return results
}

// FileType 实现 symx.Deobfuscator 接口，返回 ProGuard 文件类型标识。
func (d *Decoder) FileType() uint8 { return symx.ProGuard }

// Close 实现 symx.Deobfuscator 接口。
// ProGuard Decoder 不持有独立资源（依赖 Engine 的 mmap），Close 为空操作。
// Engine 的生命周期由 DeobfuscatorManager 管理。
func (d *Decoder) Close() error { return nil }

// frameToSymbol 将 ProGuard 特有的 Frame 转换为统一的 symx.Symbol。
// ProGuard 独有信息通过 Extra map 暴露。
func frameToSymbol(f Frame) symx.Symbol {
	return symx.Symbol{
		File:     f.ClassName,
		Function: f.MethodName,
		Line:     f.LineStart,
		LineEnd:  f.LineEnd,
		Inlined:  f.Inlined,
		Extra: map[string]any{
			"class":        f.ClassName,
			"returnType":   f.ReturnType,
			"args":         f.Args,
			"frameKind":    f.Kind,
			"syntheticTag": f.Synthetic,
			"hostClass":    f.HostClass,
			"hostMethod":   f.HostMethod,
		},
	}
}
