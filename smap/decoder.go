package smap

import (
	"encoding/binary"
	"fmt"

	"github.com/devcoze/symx"
)

// 编译期接口满足性检查
var _ symx.Deobfuscator = (*Decoder)(nil)

// Decoder 提供对 SourceMap 二进制索引的只读访问。
// 所有字节切片均为 mmap 映射的子切片，零拷贝、零分配。
type Decoder struct {
	meta     Metadata // 从 ExtendedHead TLV 反序列化而来
	lines    []byte   // Line 索引原始字节（每条 8B）
	segments []byte   // Segment 索引原始字节（每条 16B）
}

// NewDecoder 创建新的 Decoder 实例，接受 SymX Engine 作为参数。
// 它首先验证文件类型是否正确，然后从 ExtendedHead 中反序列化 Metadata，
// 并将 Payload 分割为行数据区和段数据区。
func NewDecoder(engine *symx.Engine) (*Decoder, error) {
	if engine.FileType() != symx.SourceMap {
		return nil, symx.ErrInvalidFileType
	}

	// 从 ExtendedHead 反序列化 Metadata
	var meta Metadata
	if err := symx.UnmarshalTLVs(engine.ExtData(), &meta); err != nil {
		return nil, err
	}
	// payload 数据区
	payload := engine.PayloadData()
	// 行数据区的总字节数 = 每行字节数 * 行数
	lineEnd := lineSize * meta.LineCnt
	return &Decoder{
		meta:     meta,
		lines:    payload[:lineEnd],
		segments: payload[lineEnd:],
	}, nil
}

// Meta 返回文件级元数据。
func (d *Decoder) Meta() Metadata {
	return d.meta
}

// ---------------------------------------------------------------------------
// 底层数据读取（零拷贝）
// ---------------------------------------------------------------------------

// readLine 读取第 idx 个 Line 条目的原始字节。
func (d *Decoder) readLine(idx uint32) []byte {
	return d.lines[idx*lineSize : (idx+1)*lineSize]
}

// readLineEntry 读取第 idx 个 Line 条目并解析为 Line 结构体。
func (d *Decoder) readLineEntry(idx uint32) Line {
	raw := d.readLine(idx)
	return Line{
		Start: binary.LittleEndian.Uint32(raw[0:4]),
		End:   binary.LittleEndian.Uint32(raw[4:8]),
	}
}

// readSegmentEntry 读取第 idx 个 Segment 条目并解析为 Segment 结构体。
func (d *Decoder) readSegmentEntry(idx uint32) Segment {
	off := idx * segmentSize
	raw := d.segments[off : off+segmentSize]
	return Segment{
		GenCol:  binary.LittleEndian.Uint32(raw[0:4]),
		SrcIdx:  binary.LittleEndian.Uint32(raw[4:8]),
		SrcLine: binary.LittleEndian.Uint32(raw[8:12]),
		SrcCol:  binary.LittleEndian.Uint32(raw[12:16]),
	}
}

// ---------------------------------------------------------------------------
// SourceMap 查询 — 从生成位置反查原始位置
//
// 查找流程：
//  1. 根据 genLine 从 Line 索引读取该行的 Segment 索引范围 [Start, End)
//  2. 在 Segment 范围内二分查找 GenCol <= genCol 的最后一个 Segment
//  3. 从命中的 Segment 读取 SrcIdx、SrcLine、SrcCol
// ---------------------------------------------------------------------------

// LookupPosition 根据生成代码的行号和列号，查找原始源码位置。
// genLine 和 genCol 均为 0-based。
// 返回命中的 Segment 和是否找到。
func (d *Decoder) LookupPosition(genLine, genCol int) (Segment, bool) {
	line := uint32(genLine)
	col := uint32(genCol)

	// 边界检查
	if line >= d.meta.LineCnt {
		return Segment{}, false
	}

	// 读取该行的 Segment 范围
	le := d.readLineEntry(line)
	if le.Start >= le.End {
		return Segment{}, false
	}

	// 在 Segment 范围内二分查找：找到 GenCol <= col 的最右侧条目
	segCount := le.End - le.Start
	bestIdx := int(-1)
	lo, hi := 0, int(segCount)
	for lo < hi {
		mid := lo + (hi-lo)/2
		seg := d.readSegmentEntry(le.Start + uint32(mid))
		if seg.GenCol <= col {
			bestIdx = mid
			lo = mid + 1
		} else {
			hi = mid
		}
	}

	if bestIdx < 0 {
		return Segment{}, false
	}

	seg := d.readSegmentEntry(le.Start + uint32(bestIdx))
	return seg, true
}

// ---------------------------------------------------------------------------
// symx.Deobfuscator 接口实现
//
// 以下方法将 SourceMap 特有的位置查找能力适配到统一的 Deobfuscator 接口。
// ---------------------------------------------------------------------------

// Lookup 实现 symx.Deobfuscator 接口。
// 接受 symx.JSLocation 作为输入，内部调用 LookupPosition 并转换结果。
// 如果 Location 类型不匹配（非 JSLocation），返回 Found=false。
func (d *Decoder) Lookup(loc symx.Location) symx.SymbolResult {
	jsl, ok := loc.(symx.JSLocation)
	if !ok {
		return symx.SymbolResult{Input: loc}
	}

	seg, found := d.LookupPosition(jsl.Line, jsl.Column)
	if !found {
		return symx.SymbolResult{Input: loc}
	}

	// 构造源文件标识
	// 注意：当前 SymX SourceMap 格式未存储 sources 数组，
	// File 使用 "source:<index>" 格式，调用方可通过 Extra["srcIdx"] 获取原始索引。
	srcFile := fmt.Sprintf("source:%d", seg.SrcIdx)

	return symx.SymbolResult{
		Input: loc,
		Symbols: []symx.Symbol{{
			File:   srcFile,
			Line:   int(seg.SrcLine),
			Column: int(seg.SrcCol),
			Extra: map[string]any{
				"srcIdx": seg.SrcIdx,
				"genCol": seg.GenCol,
			},
		}},
		Found: true,
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

// FileType 实现 symx.Deobfuscator 接口，返回 SourceMap 文件类型标识。
func (d *Decoder) FileType() uint8 { return symx.SourceMap }

// Close 实现 symx.Deobfuscator 接口。
// SourceMap Decoder 不持有独立资源（依赖 Engine 的 mmap），Close 为空操作。
func (d *Decoder) Close() error { return nil }
