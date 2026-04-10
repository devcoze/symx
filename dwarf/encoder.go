package dwarf

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"

	"github.com/devcoze/symx"
)

// ---------------------------------------------------------------------------
// DWARF Encoder — 将 DWARF 调试信息编码为 SymX 二进制索引格式
//
// 工作流程：
//  1. NewEncoder：打开输入文件（ELF/MachO/dSYM），预扫描 Producer 并填充 Metadata 字符串。
//  2. ExtHeadSize：返回预计算的 TLV 大小（Metadata 字符串字段已填充）。
//  3. WriteExtHead：将 Metadata 序列化为 TLV（Update 字段写为 0，PatchBindings 被记录）。
//  4. WritePayload：流式两趟写入——
//     第一趟：边提取边序列化 FuncDetail blob（含 InlineEntry + LineTableEntry），
//     收集 funcSkeleton（24B/函数）；追加写 StringPool；
//     第二趟：对骨架排序后追加写 FuncIndex。
//  5. AfterWrite：回填 Update TLV 字段的实际值 + 修正 FixedHead 中的 PayloadLen。
//
// 内存占用：O(函数数 × 24B 骨架 + StringPool)。FuncDetail 边提取边写入文件，不驻留内存。
// ---------------------------------------------------------------------------

// Encoder 实现了 symx.Encoder 和 symx.AfterWriter 接口，用于 DWARF 调试信息。
type Encoder struct {
	opts  *symx.WriteOptions
	dOpts *Options
	meta  Metadata

	// openResult 保持到 WritePayload 完成后才关闭，
	// 因为 DWARF 提取延迟到 WritePayload 阶段。
	result *openResult
}

// NewEncoder 创建新的 DWARF Encoder。打开输入文件并预扫描元数据字符串字段，
// 使得 ExtHeadSize() 能返回准确值。实际的 DWARF 提取延迟到 WritePayload。
func NewEncoder(opts *symx.WriteOptions, dOpts *Options) (*Encoder, error) {
	// 打开输入文件，提取 DWARF 数据
	result, err := openDWARF(opts.Input, dOpts)
	if err != nil {
		return nil, fmt.Errorf("dwarf: encoder open: %w", err)
	}

	e := &Encoder{
		opts:   opts,
		dOpts:  dOpts,
		result: result,
	}

	// 填充元数据字符串字段
	e.meta.Arch = result.arch
	e.meta.BuildId = result.buildId

	// 提取 Producer（从第一个 CU 的 DW_AT_producer）
	reader := result.data.Reader()
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}
		if entry.Tag == 0 {
			continue
		}
		if p, ok := entry.Val(0x25).(string); ok && p != "" { // DW_AT_producer = 0x25
			e.meta.Producer = p
			break
		}
	}

	return e, nil
}

// Close 释放 Encoder 持有的资源（关闭输入文件句柄）。
func (e *Encoder) Close() error {
	if e.result != nil {
		err := e.result.closer()
		e.result = nil
		return err
	}
	return nil
}

// FileType 返回 DWARF 文件类型标识。
func (e *Encoder) FileType() uint8 {
	return symx.Dwarf
}

// Identify 返回该 DWARF 文件的唯一标识（Build ID）。
func (e *Encoder) Identify() string {
	return e.meta.BuildId
}

// ExtHeadSize 返回 TLV 扩展头的总字节长度。
func (e *Encoder) ExtHeadSize() uint16 {
	return uint16(symx.MustTLVsSize(&e.meta))
}

// PayloadSize 返回 0，因为 Payload 大小在 WritePayload 完成前是未知的。
// 实际值通过 AfterWrite → CorrectPayloadLen 回填。
func (e *Encoder) PayloadSize() uint64 {
	return 0
}

// WriteExtHead 将 Metadata 序列化为 TLV 条目写入扩展头。
func (e *Encoder) WriteExtHead(cw *symx.CountingWriter) error {
	return symx.WriteTLVsTo(cw, &e.meta)
}

// ---------------------------------------------------------------------------
// funcSkeleton — 函数骨架（24B），用于第二趟排序写入 FuncIndex
//
// 在流式写入过程中，每个函数的 FuncDetail blob 已经直接写入输出流，
// 骨架只保留 FuncIndex 需要的 4 个字段，用于第二趟排序后写入。
// ---------------------------------------------------------------------------

// funcSkeleton 保存一个函数的索引骨架，用于最终排序和写入 FuncIndex。
type funcSkeleton struct {
	startPC   uint64
	endPC     uint64
	detailOff uint32 // FuncDetail blob 在 FuncDetail section 中的字节偏移
	detailLen uint32 // FuncDetail blob 的字节长度
}

// WritePayload 流式写入 DWARF 二进制索引。
//
// Payload 布局：
//
//	[FuncDetail blobs...]            — Pass 1: 变长 blob，边提取边直接写入 cw
//	[StringPool]                     — 提取完成后追加写入
//	[FuncIndex × FuncCount]          — Pass 2: 骨架排序后追加写入（24B/条目）
//
// 内存占用：O(函数数 × 24B 骨架 + StringPool)。
// FuncDetail blob 在提取后立即写入输出流，不在内存中累积。
func (e *Encoder) WritePayload(cw *symx.CountingWriter) error {
	if e.result == nil {
		return fmt.Errorf("dwarf: encoder already consumed (Close called before WritePayload)")
	}

	sp := symx.NewStringPool()
	var skeletons []funcSkeleton

	// 记录 Payload 起始偏移，用于计算 Payload-relative 偏移。
	// FuncDetail section 从 Payload 偏移 0 开始（与 ProGuard DataBlock 一致）。
	payloadBase := cw.Offset()

	// --- 第一趟：边提取边直接写入 FuncDetail blob ---
	//
	// 每个函数的 detail blob 格式：
	//   FuncName(4) + File(4) + Line(4) + InlineCount(2) + LineCount(2) = 16B header
	//   [InlineEntry × InlineCount]  (32B each)
	//   [LineTableEntry × LineCount] (14B each)
	//
	// blob 直接写入 cw（零缓冲）。骨架只记录 (startPC, endPC, detailOff, detailLen)。

	ex := &extractor{
		dw: e.result.data,
		onFn: func(fn *ParsedFunc) error {
			blobStart := cw.Offset() - payloadBase

			// --- 写入 detail header (16B) ---
			var hdr [funcDetailHeaderSize]byte
			binary.LittleEndian.PutUint32(hdr[0:4], sp.Put(fn.Name))
			binary.LittleEndian.PutUint32(hdr[4:8], sp.Put(fn.File))
			binary.LittleEndian.PutUint32(hdr[8:12], uint32(fn.Line))
			binary.LittleEndian.PutUint16(hdr[12:14], uint16(len(fn.Inlines)))
			binary.LittleEndian.PutUint16(hdr[14:16], uint16(len(fn.Lines)))
			if _, err := cw.Write(hdr[:]); err != nil {
				return err
			}

			// --- 写入 InlineEntry ---
			for _, il := range fn.Inlines {
				var buf [inlineEntrySize]byte
				binary.LittleEndian.PutUint64(buf[0:8], il.StartPC)
				binary.LittleEndian.PutUint64(buf[8:16], il.EndPC)
				binary.LittleEndian.PutUint32(buf[16:20], sp.Put(il.Name))
				binary.LittleEndian.PutUint32(buf[20:24], sp.Put(il.CallFile))
				binary.LittleEndian.PutUint32(buf[24:28], uint32(il.CallLine))
				binary.LittleEndian.PutUint16(buf[28:30], uint16(il.Depth))
				binary.LittleEndian.PutUint16(buf[30:32], 0) // padding
				if _, err := cw.Write(buf[:]); err != nil {
					return err
				}
			}

			// --- 写入 LineTableEntry ---
			for _, ln := range fn.Lines {
				fileOff := uint32(0)
				if ln.File != fn.File {
					fileOff = sp.Put(ln.File)
				}
				var buf [lineTableEntrySize]byte
				binary.LittleEndian.PutUint32(buf[0:4], uint32(ln.PC-fn.StartPC))
				binary.LittleEndian.PutUint32(buf[4:8], fileOff)
				binary.LittleEndian.PutUint32(buf[8:12], uint32(ln.Line))
				binary.LittleEndian.PutUint16(buf[12:14], uint16(ln.Col))
				if _, err := cw.Write(buf[:]); err != nil {
					return err
				}
			}

			blobLen := cw.Offset() - payloadBase - blobStart
			skeletons = append(skeletons, funcSkeleton{
				startPC:   fn.StartPC,
				endPC:     fn.EndPC,
				detailOff: uint32(blobStart),
				detailLen: uint32(blobLen),
			})
			return nil
		},
	}
	if err := ex.Extract(); err != nil {
		return fmt.Errorf("dwarf: encoder extract: %w", err)
	}

	// 关闭输入文件（提取完成，不再需要）
	_ = e.result.closer()
	e.result = nil

	// 记录 FuncDetail section 长度（与 ProGuard 一致，只存长度不存偏移）
	e.meta.FuncDetailLen = uint32(cw.Offset() - payloadBase)

	// --- 写入 StringPool ---
	e.meta.StringPoolLen = uint32(sp.Len())
	if _, err := cw.Write(sp.Bytes()); err != nil {
		return err
	}

	// --- 第二趟：骨架排序后写入 FuncIndex 数组 ---
	sort.Slice(skeletons, func(i, j int) bool {
		return skeletons[i].startPC < skeletons[j].startPC
	})

	e.meta.FuncCount = uint32(len(skeletons))

	var idxBuf [funcIndexSize]byte
	for i := range skeletons {
		sk := &skeletons[i]
		binary.LittleEndian.PutUint64(idxBuf[0:8], sk.startPC)
		binary.LittleEndian.PutUint64(idxBuf[8:16], sk.endPC)
		binary.LittleEndian.PutUint32(idxBuf[16:20], sk.detailOff)
		binary.LittleEndian.PutUint32(idxBuf[20:24], sk.detailLen)

		if _, err := cw.Write(idxBuf[:]); err != nil {
			return err
		}
	}

	return nil
}

// AfterWrite 回填 ExtHead 中 Update TLV 字段的实际值，
// 并修正 FixedHead 中的 PayloadLen 字段。
func (e *Encoder) AfterWrite(f *os.File, r symx.WriteResult) error {
	if err := symx.ApplyPatchBindings(f, &e.meta, r.PatchBindings); err != nil {
		return err
	}
	if _, err := symx.CorrectPayloadLen(f, r.PayloadBytes); err != nil {
		return err
	}
	return nil
}

// NewDWARFEncoderFactory 创建一个 DWARF EncoderFactory 闭包，
// 将 Options 绑定到工厂函数中，适配 symx.EncoderFactory 签名。
func NewDWARFEncoderFactory(dOpts *Options) symx.EncoderFactory {
	return func(opts *symx.WriteOptions) symx.Encoder {
		enc, err := NewEncoder(opts, dOpts)
		if err != nil {
			// EncoderFactory 无法返回 error，panic 表示编程错误
			panic(fmt.Sprintf("dwarf: NewEncoder failed: %v", err))
		}
		return enc
	}
}
