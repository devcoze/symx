package proguard

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/devcoze/symx"
)

// ---------------------------------------------------------------------------
// 二进制索引（高性能存储）
//
// 从解析后的 AST 类流式生成 mmap 友好的二进制 Payload。
// 不包含独立的文件头 —— 文件级别的封装由 SymX FixedHead + ExtendedHead (TLV) 管理，
// 本层仅生成 Payload 部分。
//
// Payload 布局（全部小端序）：
//
//   [DataBlock]     — 每个类的变长数据（头部、方法、字段、行号、帧、元数据）
//   [ClassIndex]    — 按混淆类名排序，支持二分查找（16B 每条）
//   [StringPool]    — 所有去重字符串，长度前缀编码
//
// 各 section 的偏移和长度存储在 ExtendedHead 的 TLV 字段中（Metadata）。
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Metadata — 存储在 ExtendedHead 中的 TLV 条目。
//
// 字符串字段在写入 ExtHead 时一次性写入。
// 带 "Update" 标记的 uint32 字段初始写为 0，在 Payload 写入完成后
// 通过 AfterWrite 回填实际值。
// ---------------------------------------------------------------------------

type Metadata struct {
	// 文件级元数据（来自 mapping 文件头部注释）
	Compiler        string `json:"compiler"          symx:"33"`
	CompilerVersion string `json:"compiler_version"  symx:"34"`
	MinAPI          string `json:"min_api"           symx:"35"`
	Hash            string `json:"hash"              symx:"36"`
	PGHashId        string `json:"pg_hash_id"        symx:"37"`

	// Payload 各 section 的布局信息（WritePayload 完成后回填）
	ClassCount    uint32 `symx:"40,Update"`
	DataBlockLen  uint32 `symx:"41,Update"`
	StringPoolLen uint32 `symx:"42,Update"`
	TotalMethods  uint32 `symx:"43,Update"`
	TotalLines    uint32 `symx:"44,Update"`
	TotalMetadata uint32 `symx:"45,Update"`
}

// ---------------------------------------------------------------------------
// ClassIndex 条目（16 字节）— 按混淆类名排序，支持二分查找
// ---------------------------------------------------------------------------

const classIndexEntrySize = 16

// BinClassIndexEntry 将混淆类名指向 DataBlock 中对应的数据区域。
// 仅包含查找和定位所需的字段；结构数量信息在每个类数据区域开头的
// ClassDataHeader 中。
type BinClassIndexEntry struct {
	ObfName uint32 // 字符串池字节偏移（混淆类名）
	OriName uint32 // 字符串池字节偏移（原始类名）
	DataOff uint32 // 该类数据在 DataBlock 中的起始偏移
	DataLen uint32 // 该类数据在 DataBlock 中的字节长度
}

// ---------------------------------------------------------------------------
// DataBlock 子条目（每个类的变长布局）
//
// 每个类在 DataOff 处的布局：
//   [ClassDataHeader]                (6B)
//   [MethodEntry * MethodCount]      (28B 每条，先预留空间后回填)
//   [FieldEntry  * FieldCount]       (12B 每条)
//   每条类级别元数据：
//     [条件列表]                      (变长 — [count:u16][pad:u16][字符串池偏移:u32*count])
//     [动作列表]                      (变长 — 同上格式)
//     [MetadataEntry]                (12B — ID + 指向上述列表的偏移)
//   每个方法：
//     [LineEntry * LineCount]        (14B 每条，先预留空间后回填)
//     每个行号组：
//       [FrameEntry * FrameCount]    (24B 每条)
//     每条方法级别元数据：
//       [条件列表]                    (变长)
//       [动作列表]                    (变长)
//       [MetadataEntry]              (12B)
// ---------------------------------------------------------------------------

const classDataHeaderSize = 6

// ClassDataHeader 写在每个类的 DataBlock 数据区域开头。
type ClassDataHeader struct {
	MethodCount uint16 // 方法数量
	FieldCount  uint16 // 字段数量
	MetaCount   uint16 // 类级别元数据数量
}

const methodEntrySize = 28

// BinMethodEntry （28 字节）
type BinMethodEntry struct {
	ObfName   uint32 // 字符串池字节偏移（混淆方法名）
	OriName   uint32 // 字符串池字节偏移（原始方法名）
	Return    uint32 // 字符串池字节偏移（返回类型）
	Args      uint32 // 字符串池字节偏移（参数类型，逗号分隔）
	LineOff   uint32 // DataBlock 偏移，指向 LineEntry 数组
	LineCount uint16 // 行号条目数量
	MetaOff   uint32 // DataBlock 偏移，指向方法级别元数据区域
	MetaCount uint16 // 方法级别元数据条目数量
}

const fieldEntrySize = 12

// BinFieldEntry （12 字节）
type BinFieldEntry struct {
	ObfName uint32 // 字符串池字节偏移（混淆字段名）
	OriName uint32 // 字符串池字节偏移（原始字段名）
	Type    uint32 // 字符串池字节偏移（字段类型）
}

const lineEntrySize = 14

// BinLineEntry （14 字节）— 一个混淆行号范围
type BinLineEntry struct {
	ObfStart   uint32 // 混淆行号起始
	ObfEnd     uint32 // 混淆行号结束
	FrameOff   uint32 // DataBlock 偏移，指向 FrameEntry 数组
	FrameCount uint16 // 帧数量（>1 表示内联）
}

const frameEntrySize = 24

// BinFrameEntry （24 字节）— 一个原始帧
type BinFrameEntry struct {
	OriClass  uint32 // 字符串池字节偏移（原始类名）
	OriMethod uint32 // 字符串池字节偏移（原始方法名）
	Return    uint32 // 字符串池字节偏移（返回类型）
	Args      uint32 // 字符串池字节偏移（参数类型）
	OriStart  uint32 // 原始行号起始
	OriEnd    uint32 // 原始行号结束
}

const metadataEntrySize = 12

// BinMetadataEntry （12 字节）— 一条元数据记录。
// CondOff 和 ActOff 指向紧邻该条目之前写入的条件/动作列表。
type BinMetadataEntry struct {
	ID      uint32 // 字符串池字节偏移（元数据 ID）
	CondOff uint32 // DataBlock 偏移，指向条件列表
	ActOff  uint32 // DataBlock 偏移，指向动作列表
}

// 条件/动作列表布局：
//
//	[count:uint16][padding:uint16][字符串池偏移:uint32 * count]
//
// 每个偏移值是字符串池中的字节偏移。
const metaListHeaderSize = 4 // uint16 count + uint16 padding

// ---------------------------------------------------------------------------
// Builder — 流式 AST -> 二进制构建器
//
// 用法：
//
//	builder := NewBuilder()
//	builder.SetWriter(w)                    // 设置输出 writer
//	ParseReaderStream(r, builder.OnClass)   // 流式解析（逐类写入 DataBlock）
//	builder.Finalize()                      // 排序类索引
//	builder.WriteIndex(w)                   // 写入 ClassIndex + StringPool
// ---------------------------------------------------------------------------

// Builder 从 ASTClass 对象流构建 Payload 二进制数据。
//
// 每次 OnClass 调用将一个类的数据序列化到临时缓冲区中，
// 在本地完成所有回填后立即刷写到底层 writer。
// 内存中仅保留 classIdx 和 strings。
type Builder struct {
	pool        *symx.StringPool
	classIdx    []BinClassIndexEntry
	w           io.Writer // DataBlock 流式写入的底层 writer
	dataWritten uint32    // 已写入 w 的总字节数（即 DataBlock 大小）

	// 统计信息
	totalMethods  int
	totalLines    int
	totalMetadata int
}

// NewBuilder 创建新的构建器。在流式调用 OnClass 之前需先调用 SetWriter。
func NewBuilder() *Builder {
	return &Builder{
		pool: symx.NewStringPool(),
	}
}

// SetWriter 设置 DataBlock 流式写入的底层 writer。
// 必须在第一次 OnClass 调用之前设置。
func (b *Builder) SetWriter(w io.Writer) {
	b.w = w
}

// OnClass 处理一个 ASTClass，将其二进制数据序列化到临时缓冲区，
// 然后刷写到底层 writer。
// 此方法用作 ParseReaderStream 的 OnClass 回调。
func (b *Builder) OnClass(cls *ASTClass) error {
	cw := &classWriter{baseOff: b.dataWritten}

	classEntry := BinClassIndexEntry{
		ObfName: b.str(cls.ObfName),
		OriName: b.str(cls.OriName),
		DataOff: b.dataWritten,
	}

	// 写入 ClassDataHeader（类数据区域开头）
	hdr := ClassDataHeader{
		MethodCount: uint16(len(cls.Methods)),
		FieldCount:  uint16(len(cls.Fields)),
		MetaCount:   uint16(len(cls.Metadata)),
	}
	_ = binary.Write(&cw.buf, binary.LittleEndian, &hdr)

	// 预留方法条目空间（稍后回填）
	methodLocalOff := cw.buf.Len()
	methodEntries := make([]BinMethodEntry, len(cls.Methods))
	for range cls.Methods {
		cw.writeZeros(methodEntrySize)
	}

	// 写入字段条目
	for _, f := range cls.Fields {
		fe := BinFieldEntry{
			ObfName: b.str(f.ObfName),
			OriName: b.str(f.OriName),
			Type:    b.str(f.Type),
		}
		_ = binary.Write(&cw.buf, binary.LittleEndian, &fe)
	}

	// 写入类级别元数据
	for _, m := range cls.Metadata {
		b.writeASTMetadata(cw, m)
		b.totalMetadata++
	}

	// 写入每个方法的数据（行号、帧、方法元数据）
	for i, am := range cls.Methods {
		argsStr := joinArgs(am.Args)
		me := BinMethodEntry{
			ObfName:   b.str(am.ObfName),
			OriName:   b.str(am.OriName),
			Return:    b.str(am.Return),
			Args:      b.str(argsStr),
			LineCount: uint16(len(am.LineGroups)),
			MetaCount: uint16(len(am.Metadata)),
		}
		b.totalMethods++

		// 写入行号条目
		me.LineOff = cw.globalOff()
		lineLocalOff := cw.buf.Len()
		lineEntries := make([]BinLineEntry, len(am.LineGroups))

		// 预留行号条目空间（稍后回填）
		for range am.LineGroups {
			cw.writeZeros(lineEntrySize)
		}

		// 写入每个行号组的帧数据
		for li, lg := range am.LineGroups {
			lineEntries[li] = BinLineEntry{
				ObfStart:   uint32(lg.ObfStart),
				ObfEnd:     uint32(lg.ObfEnd),
				FrameOff:   cw.globalOff(),
				FrameCount: uint16(len(lg.Frames)),
			}
			b.totalLines++

			for _, fr := range lg.Frames {
				fe := BinFrameEntry{
					OriClass:  b.str(fr.OriClass),
					OriMethod: b.str(fr.OriMethod),
					Return:    b.str(fr.Return),
					Args:      b.str(joinArgs(fr.Args)),
					OriStart:  uint32(fr.OriStart),
					OriEnd:    uint32(fr.OriEnd),
				}
				_ = binary.Write(&cw.buf, binary.LittleEndian, &fe)
			}
		}

		// 回填行号条目
		cw.backfillLineEntries(lineLocalOff, lineEntries)

		// 写入方法级别元数据
		me.MetaOff = cw.globalOff()
		for _, m := range am.Metadata {
			b.writeASTMetadata(cw, m)
			b.totalMetadata++
		}

		methodEntries[i] = me
	}

	// 回填方法条目
	cw.backfillMethodEntries(methodLocalOff, methodEntries)

	classEntry.DataLen = uint32(cw.buf.Len())

	// 刷写到底层 writer
	n, err := b.w.Write(cw.buf.Bytes())
	b.dataWritten += uint32(n)
	if err != nil {
		return fmt.Errorf("flushing class data: %w", err)
	}

	b.classIdx = append(b.classIdx, classEntry)
	return nil
}

// str 将字符串放入池中，返回其字节偏移。
func (b *Builder) str(s string) uint32 {
	return b.pool.Put(s)
}

// writeASTMetadata 写入一条 ASTMetadata 及其条件/动作列表。
func (b *Builder) writeASTMetadata(cw *classWriter, m *ASTMetadata) {
	condOff := cw.globalOff()
	b.writeStringList(cw, m.Conditions)

	actOff := cw.globalOff()
	b.writeStringList(cw, m.Actions)

	me := BinMetadataEntry{
		ID:      b.str(m.ID),
		CondOff: condOff,
		ActOff:  actOff,
	}
	_ = binary.Write(&cw.buf, binary.LittleEndian, &me)
}

// writeStringList 写入 [count:uint16][pad:uint16][字符串池偏移:uint32*count] 格式的列表。
func (b *Builder) writeStringList(cw *classWriter, ss []string) {
	count := uint16(len(ss))
	_ = binary.Write(&cw.buf, binary.LittleEndian, count)
	_ = binary.Write(&cw.buf, binary.LittleEndian, uint16(0)) // 填充对齐
	for _, s := range ss {
		off := b.str(s)
		_ = binary.Write(&cw.buf, binary.LittleEndian, off)
	}
}

// readStringAt 从字符串池中读取指定字节偏移处的字符串。
func (b *Builder) readStringAt(off uint32) string {
	return b.pool.ReadAt(off)
}

// Finalize 按混淆类名排序类索引，以支持二分查找。
// 必须在所有 OnClass 调用完成后、WriteIndex 之前调用。
func (b *Builder) Finalize() {
	sort.Slice(b.classIdx, func(i, j int) bool {
		si := b.readStringAt(b.classIdx[i].ObfName)
		sj := b.readStringAt(b.classIdx[j].ObfName)
		return si < sj
	})
}

// WriteIndex 写入 ClassIndex 和 StringPool（DataBlock 已在 OnClass 过程中写入）。
// 返回写入的字节数。
func (b *Builder) WriteIndex(w io.Writer) (int64, error) {
	var total int64

	// 写入 ClassIndex（已排序）
	for i := range b.classIdx {
		if err := binary.Write(w, binary.LittleEndian, &b.classIdx[i]); err != nil {
			return total, fmt.Errorf("writing class index entry %d: %w", i, err)
		}
		total += classIndexEntrySize
	}

	// 写入 StringPool
	n, err := w.Write(b.pool.Bytes())
	total += int64(n)
	if err != nil {
		return total, fmt.Errorf("writing string pool: %w", err)
	}

	return total, nil
}

// FillMetadata 用 Payload 布局信息填充 Metadata 结构体。
func (b *Builder) FillMetadata(meta *Metadata) {
	meta.ClassCount = uint32(len(b.classIdx))
	meta.DataBlockLen = b.dataWritten
	meta.StringPoolLen = uint32(b.pool.Len())
	meta.TotalMethods = uint32(b.totalMethods)
	meta.TotalLines = uint32(b.totalLines)
	meta.TotalMetadata = uint32(b.totalMetadata)
}

// Stats 返回人类可读的统计摘要。
func (b *Builder) Stats() string {
	return fmt.Sprintf("classes=%d methods=%d lines=%d metadata=%d strPoolSize=%d dataBlockSize=%d",
		len(b.classIdx), b.totalMethods, b.totalLines, b.totalMetadata,
		b.pool.Len(), b.dataWritten)
}

// ---------------------------------------------------------------------------
// classWriter — 单个类的临时缓冲区，带全局偏移量追踪。
// ---------------------------------------------------------------------------

type classWriter struct {
	buf     bytes.Buffer
	baseOff uint32 // 该类在 DataBlock 中的全局起始偏移
}

// globalOff 返回当前的 DataBlock 全局偏移。
func (cw *classWriter) globalOff() uint32 {
	return cw.baseOff + uint32(cw.buf.Len())
}

// writeZeros 写入 n 个零字节。
func (cw *classWriter) writeZeros(n int) {
	cw.buf.Write(make([]byte, n))
}

// backfillMethodEntries 回填预留的方法条目槽位。
func (cw *classWriter) backfillMethodEntries(localOff int, entries []BinMethodEntry) {
	raw := cw.buf.Bytes()
	for i, me := range entries {
		off := localOff + i*methodEntrySize
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, &me)
		copy(raw[off:off+methodEntrySize], buf.Bytes())
	}
}

// backfillLineEntries 回填预留的行号条目槽位。
func (cw *classWriter) backfillLineEntries(localOff int, entries []BinLineEntry) {
	raw := cw.buf.Bytes()
	for i, le := range entries {
		off := localOff + i*lineEntrySize
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, &le)
		copy(raw[off:off+lineEntrySize], buf.Bytes())
	}
}

// joinArgs 将参数类型列表用 ',' 连接，用于字符串池去重。
func joinArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return strings.Join(args, ",")
}
