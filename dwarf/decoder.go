package dwarf

import (
	"encoding/binary"
	"sort"

	"github.com/devcoze/symx"
)

// 编译期接口满足性检查
var _ symx.Deobfuscator = (*Decoder)(nil)

// ---------------------------------------------------------------------------
// DWARF Decoder — 从 SymX 二进制索引中零拷贝查询地址→源码映射
//
// 工作流程：
//  1. 通过 symx.Engine 打开文件（mmap），解析 FixedHead + ExtendedHead
//  2. 从 ExtendedHead TLV 反序列化 Metadata，获取各 section 的长度和数量
//  3. 按顺序布局计算各 section 边界（FuncDetail→StringPool→FuncIndex）
//  4. 查找：二分查找 FuncIndex(24B) → 命中后读取 FuncDetail blob → 内联帧匹配
//     → 行号表精确化 → 构建 Symbol 链
//
// Payload 布局（各 section 位置由 Metadata 中的长度按顺序隐式确定）：
//   [FuncDetail blobs...]           — 变长，每个函数的完整数据
//   [StringPool]                    — 去重字符串池
//   [FuncIndex × FuncCount]         — 24B/条目，按 StartPC 排序
// ---------------------------------------------------------------------------

// Decoder 提供对 DWARF 二进制索引的只读访问。
// 所有字节切片均为 mmap 映射的子切片，零拷贝、零分配。
type Decoder struct {
	meta    Metadata
	index   []byte // FuncIndex 数组区域
	detail  []byte // FuncDetail section 区域
	strPool []byte // StringPool 区域
}

// NewDecoder 从已打开的 symx.Engine 构造 Decoder。
// engine 必须是 DWARF 类型文件（FileType == symx.Dwarf）。
func NewDecoder(engine *symx.Engine) (*Decoder, error) {
	if engine.FileType() != symx.Dwarf {
		return nil, symx.ErrInvalidFileType
	}

	// 从 ExtendedHead 反序列化 Metadata
	var meta Metadata
	if err := symx.UnmarshalTLVs(engine.ExtData(), &meta); err != nil {
		return nil, err
	}

	payload := engine.PayloadData()

	// 通过 Metadata 中的长度和数量，按顺序布局计算各 section 的边界
	// （与 ProGuard 一致：Metadata 只存长度，位置由顺序隐式确定）
	//
	// Payload 布局：[FuncDetail | StringPool | FuncIndex]
	funcDetailEnd := meta.FuncDetailLen
	strPoolEnd := funcDetailEnd + meta.StringPoolLen
	funcIndexStart := strPoolEnd
	funcIndexEnd := funcIndexStart + meta.FuncCount*funcIndexSize

	d := &Decoder{
		meta:    meta,
		index:   payload[funcIndexStart:funcIndexEnd],
		detail:  payload[0:funcDetailEnd],
		strPool: payload[funcDetailEnd:strPoolEnd],
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
func (d *Decoder) readStr(off uint32) string {
	return symx.ReadStringAt(d.strPool, off)
}

// ---------------------------------------------------------------------------
// FuncIndex 读取与二分查找
// ---------------------------------------------------------------------------

// funcCount 返回函数条目数量。
func (d *Decoder) funcCount() int {
	return int(d.meta.FuncCount)
}

// readIndexStartPC 从 FuncIndex 数组中读取第 i 个条目的 StartPC（零拷贝）。
func (d *Decoder) readIndexStartPC(i int) uint64 {
	off := i * funcIndexSize
	return binary.LittleEndian.Uint64(d.index[off : off+8])
}

// readIndexEndPC 从 FuncIndex 数组中读取第 i 个条目的 EndPC（零拷贝）。
func (d *Decoder) readIndexEndPC(i int) uint64 {
	off := i*funcIndexSize + 8
	return binary.LittleEndian.Uint64(d.index[off : off+8])
}

// readIndex 从 FuncIndex 数组中读取第 i 个完整条目。
func (d *Decoder) readIndex(i int) FuncIndex {
	off := i * funcIndexSize
	raw := d.index[off : off+funcIndexSize]
	return FuncIndex{
		StartPC:   binary.LittleEndian.Uint64(raw[0:8]),
		EndPC:     binary.LittleEndian.Uint64(raw[8:16]),
		DetailOff: binary.LittleEndian.Uint32(raw[16:20]),
		DetailLen: binary.LittleEndian.Uint32(raw[20:24]),
	}
}

// findFunc 在按 StartPC 排序的 FuncIndex 数组上二分查找。
// 查找包含给定地址的函数（StartPC <= addr < EndPC）。
// 返回函数索引和是否找到。
func (d *Decoder) findFunc(addr uint64) (int, bool) {
	n := d.funcCount()
	if n == 0 {
		return 0, false
	}

	// 二分查找：找到最大的 i 使得 StartPC[i] <= addr
	idx := sort.Search(n, func(i int) bool {
		return d.readIndexStartPC(i) > addr
	}) - 1

	if idx < 0 {
		return 0, false
	}

	// 验证 addr < EndPC
	if addr >= d.readIndexEndPC(idx) {
		return 0, false
	}

	return idx, true
}

// ---------------------------------------------------------------------------
// FuncDetail blob 解析
// ---------------------------------------------------------------------------

// decodedDetail 保存从 FuncDetail blob 解码的完整信息。
type decodedDetail struct {
	funcName    uint32 // 字符串池偏移
	file        uint32 // 字符串池偏移
	line        uint32
	inlineCount uint16
	lineCount   uint16
	blob        []byte // 整个 blob 的原始字节（用于后续读取 inline/line 条目）
}

// readDetail 从 FuncDetail section 中读取指定偏移和长度的 blob 并解码头部。
func (d *Decoder) readDetail(detailOff, detailLen uint32) decodedDetail {
	blob := d.detail[detailOff : detailOff+detailLen]
	return decodedDetail{
		funcName:    binary.LittleEndian.Uint32(blob[0:4]),
		file:        binary.LittleEndian.Uint32(blob[4:8]),
		line:        binary.LittleEndian.Uint32(blob[8:12]),
		inlineCount: binary.LittleEndian.Uint16(blob[12:14]),
		lineCount:   binary.LittleEndian.Uint16(blob[14:16]),
		blob:        blob,
	}
}

// ---------------------------------------------------------------------------
// InlineEntry 读取（从 FuncDetail blob 内部）
// ---------------------------------------------------------------------------

// decodedInline 保存从二进制数据解码的 InlineEntry 信息。
type decodedInline struct {
	startPC  uint64
	endPC    uint64
	funcName uint32 // 字符串池偏移
	callFile uint32 // 字符串池偏移
	callLine uint32
	depth    uint16
}

// readInline 从 FuncDetail blob 中读取第 i 个 InlineEntry。
// InlineEntry 数组紧随 detail header (16B) 之后。
func (dd *decodedDetail) readInline(i int) decodedInline {
	off := funcDetailHeaderSize + i*inlineEntrySize
	raw := dd.blob[off : off+inlineEntrySize]
	return decodedInline{
		startPC:  binary.LittleEndian.Uint64(raw[0:8]),
		endPC:    binary.LittleEndian.Uint64(raw[8:16]),
		funcName: binary.LittleEndian.Uint32(raw[16:20]),
		callFile: binary.LittleEndian.Uint32(raw[20:24]),
		callLine: binary.LittleEndian.Uint32(raw[24:28]),
		depth:    binary.LittleEndian.Uint16(raw[28:30]),
	}
}

// ---------------------------------------------------------------------------
// LineTableEntry 读取（从 FuncDetail blob 内部）
// ---------------------------------------------------------------------------

// decodedLine 保存从二进制数据解码的 LineTableEntry 信息。
type decodedLine struct {
	pcDelta uint32
	file    uint32 // 字符串池偏移（0 = 与 FuncDetail.File 相同）
	line    uint32
	col     uint16
}

// readLine 从 FuncDetail blob 中读取第 i 个 LineTableEntry。
// LineTableEntry 数组紧随 InlineEntry 数组之后。
func (dd *decodedDetail) readLine(i int) decodedLine {
	off := funcDetailHeaderSize + int(dd.inlineCount)*inlineEntrySize + i*lineTableEntrySize
	raw := dd.blob[off : off+lineTableEntrySize]
	return decodedLine{
		pcDelta: binary.LittleEndian.Uint32(raw[0:4]),
		file:    binary.LittleEndian.Uint32(raw[4:8]),
		line:    binary.LittleEndian.Uint32(raw[8:12]),
		col:     binary.LittleEndian.Uint16(raw[12:14]),
	}
}

// ---------------------------------------------------------------------------
// 行号表精确化 — 在函数的 LineTableEntry 上二分查找
// ---------------------------------------------------------------------------

// resolveLineInfo 在函数的行号表中查找最精确的 PC 位置对应的行号信息。
// 使用二分查找找到 PCDelta <= (addr - startPC) 的最右条目。
// 返回文件路径、行号和列号。
func (d *Decoder) resolveLineInfo(dd *decodedDetail, startPC, addr uint64) (file string, line int, col int) {
	if dd.lineCount == 0 {
		return d.readStr(dd.file), int(dd.line), 0
	}

	targetDelta := uint32(addr - startPC)
	count := int(dd.lineCount)

	// 二分查找：找到最大的 i 使得 PCDelta[i] <= targetDelta
	idx := sort.Search(count, func(i int) bool {
		le := dd.readLine(i)
		return le.pcDelta > targetDelta
	}) - 1

	if idx < 0 {
		// 没有匹配的行号表条目，回退到函数入口信息
		return d.readStr(dd.file), int(dd.line), 0
	}

	le := dd.readLine(idx)
	if le.file != 0 {
		file = d.readStr(le.file)
	} else {
		file = d.readStr(dd.file)
	}
	return file, int(le.line), int(le.col)
}

// ---------------------------------------------------------------------------
// 核心查找逻辑
// ---------------------------------------------------------------------------

// lookupAddr 对单个地址执行完整的符号查找。
// 返回还原后的符号帧列表（含内联帧展开）。
func (d *Decoder) lookupAddr(addr uint64) ([]symx.Symbol, bool) {
	funcIdx, found := d.findFunc(addr)
	if !found {
		return nil, false
	}

	fi := d.readIndex(funcIdx)
	dd := d.readDetail(fi.DetailOff, fi.DetailLen)

	// 收集匹配的内联帧（地址落在内联范围内的）
	var inlineFrames []decodedInline
	for i := 0; i < int(dd.inlineCount); i++ {
		il := dd.readInline(i)
		if addr >= il.startPC && addr < il.endPC {
			inlineFrames = append(inlineFrames, il)
		}
	}

	// 按 depth 降序排序内联帧（最深的先，形成从内到外的调用链）
	if len(inlineFrames) > 1 {
		sort.Slice(inlineFrames, func(i, j int) bool {
			return inlineFrames[i].depth > inlineFrames[j].depth
		})
	}

	// 解析行号信息
	file, line, col := d.resolveLineInfo(&dd, fi.StartPC, addr)

	// 构建 Symbol 列表
	// 顺序：内联帧（从最深到最浅） → 外层函数
	symbols := make([]symx.Symbol, 0, len(inlineFrames)+1)

	for _, il := range inlineFrames {
		callFile := d.readStr(il.callFile)
		if callFile == "" {
			callFile = d.readStr(dd.file)
		}
		symbols = append(symbols, symx.Symbol{
			File:     callFile,
			Function: d.readStr(il.funcName),
			Line:     int(il.callLine),
			Inlined:  true,
		})
	}

	// 外层函数帧
	symbols = append(symbols, symx.Symbol{
		File:     file,
		Function: d.readStr(dd.funcName),
		Line:     line,
		Column:   col,
		Inlined:  false,
	})

	return symbols, true
}

// ---------------------------------------------------------------------------
// symx.Deobfuscator 接口实现
// ---------------------------------------------------------------------------

// Lookup 实现 symx.Deobfuscator 接口。
// 接受 symx.NativeLocation 作为输入，执行地址→源码符号查找。
// 如果 Location 类型不匹配（非 NativeLocation），返回 Found=false。
func (d *Decoder) Lookup(loc symx.Location) symx.SymbolResult {
	nl, ok := loc.(symx.NativeLocation)
	if !ok {
		return symx.SymbolResult{Input: loc}
	}

	symbols, found := d.lookupAddr(nl.Address)
	return symx.SymbolResult{
		Input:   loc,
		Symbols: symbols,
		Found:   found,
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

// FileType 实现 symx.Deobfuscator 接口，返回 DWARF 文件类型标识。
func (d *Decoder) FileType() uint8 { return symx.Dwarf }

// Close 实现 symx.Deobfuscator 接口。
// DWARF Decoder 不持有独立资源（依赖 Engine 的 mmap），Close 为空操作。
// Engine 的生命周期由 DeobfuscatorManager 管理。
func (d *Decoder) Close() error { return nil }
