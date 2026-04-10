package proguard

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/devcoze/symx"
)

// 编译期接口满足性检查
var (
	_ symx.Encoder     = (*Encoder)(nil)
	_ symx.AfterWriter = (*Encoder)(nil)
)

// Encoder 实现了 symx.Encoder 接口，用于 ProGuard/R8 mapping 文件。
//
// 工作流程：
//  1. NewEncoder：打开 mapping 文件，预扫描头部注释填充 Metadata 字符串字段。
//  2. ExtHeadSize：返回预计算的 TLV 大小（因为 Metadata 字符串已填充，所以是准确值）。
//  3. WriteExtHead：将 Metadata 序列化为 TLV（Update 字段写为 0，PatchBindings 被记录）。
//  4. WritePayload：流式解析 AST 类并通过 Builder 处理。DataBlock 在解析过程中逐类写入，
//     所有类处理完成后再追加写入 ClassIndex 和 StringPool。
//  5. AfterWrite：回填 Update TLV 字段的实际值 + 修正 FixedHead 中的 PayloadLen。
type Encoder struct {
	opts    *symx.WriteOptions
	r       *os.File
	meta    Metadata
	builder *Builder
}

// NewEncoder 创建新的 Encoder。打开输入文件并预扫描头部注释以填充 Metadata 字符串字段，
// 使得 ExtHeadSize() 能返回准确值。失败时返回 nil 和错误。
func NewEncoder(opts *symx.WriteOptions) (*Encoder, error) {
	f, err := os.Open(opts.Input)
	if err != nil {
		return nil, fmt.Errorf("proguard: open input: %w", err)
	}
	e := &Encoder{
		opts:    opts,
		r:       f,
		builder: NewBuilder(),
	}
	e.scanMetadata()
	return e, nil
}

// Close 释放 Encoder 持有的文件句柄。
func (e *Encoder) Close() error {
	if e.r != nil {
		return e.r.Close()
	}
	return nil
}

// scanMetadata 读取 mapping 文件的头部注释行，填充 Metadata 字符串字段
// （Compiler、CompilerVersion 等）。
//
// mapping 文件头部格式：
//
//	# compiler: R8
//	# compiler_version: 4.0.48
//	# min_api: 19
//	# common_typos_disable
//	# {"id":"com.android.tools.r8.mapping","version":"2.1"}
//	# pg_map_id: 6b55239
//	# pg_map_hash: SHA-256 6b55239c41cba8d771463fec2f668d7140e75699c6da9642010f7f1d59aaab7b
func (e *Encoder) scanMetadata() {
	scanner := bufio.NewScanner(e.r)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "#") {
			break // 遇到第一行非注释行时停止
		}
		content := strings.TrimSpace(trimmed[1:])
		parts := strings.SplitN(content, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		switch key {
		case "compiler":
			e.meta.Compiler = value
		case "compiler_version":
			e.meta.CompilerVersion = value
		case "min_api":
			e.meta.MinAPI = value
		case "pg_map_hash":
			e.meta.Hash = value
		case "pg_map_id":
			e.meta.PGHashId = value
		}
	}
}

func (e *Encoder) FileType() uint8 {
	return symx.ProGuard
}

// reset 将文件指针重置到开头。
func (e *Encoder) reset() error {
	_, err := e.r.Seek(0, io.SeekStart)
	return err
}

// Identify 返回该 mapping 文件的唯一标识。
// 使用第一行注释的内容作为标识。
func (e *Encoder) Identify() string {
	_ = e.reset()
	scanner := bufio.NewScanner(e.r)
	lineNo := 0
	for scanner.Scan() && lineNo < 100 {
		line := scanner.Text()
		lineNo++
		if strings.HasPrefix(line, "#") {
			line = strings.TrimSpace(line[1:])
			return line
		}
	}
	return ""
}

// ExtHeadSize 返回 TLV 扩展头的总字节长度。
// 由于 Metadata 字符串字段已在 NewEncoder 中预填充，返回值是准确的。
func (e *Encoder) ExtHeadSize() uint16 {
	return uint16(symx.MustTLVsSize(&e.meta))
}

// PayloadSize 返回 0，因为 Payload 大小在 WritePayload 完成前是未知的。
// 实际值通过 AfterWrite → CorrectPayloadLen 回填。
func (e *Encoder) PayloadSize() uint64 {
	return 0
}

// WriteExtHead 将 Metadata 序列化为 TLV 条目写入扩展头。
// 带 Update 标记的 uint32 字段（ClassCount、DataBlockLen 等）写为 0，
// 其 PatchBindings 由 CountingWriter 自动记录。
func (e *Encoder) WriteExtHead(cw *symx.CountingWriter) error {
	return symx.WriteTLVsTo(cw, &e.meta)
}

// WritePayload 流式解析 mapping 文件并通过 Builder 处理。
// DataBlock 在解析过程中逐类写入，完成后追加 ClassIndex + StringPool。
func (e *Encoder) WritePayload(cw *symx.CountingWriter) error {
	_ = e.reset()

	// 设置 DataBlock 流式写入的 writer
	e.builder.SetWriter(cw)

	// 流式解析 → Builder.OnClass（每个类完成后立即刷写到 cw）
	if err := ParseReaderStream(e.r, e.builder.OnClass); err != nil {
		return err
	}

	// 排序类索引以支持二分查找
	e.builder.Finalize()

	// 写入 ClassIndex + StringPool
	if _, err := e.builder.WriteIndex(cw); err != nil {
		return err
	}

	// 用实际的 Payload 布局值填充 Metadata（供 AfterWrite 回填使用）
	e.builder.FillMetadata(&e.meta)

	return nil
}

// AfterWrite 回填 ExtHead 中 Update TLV 字段的实际值，
// 并修正 FixedHead 中的 PayloadLen 字段。
func (e *Encoder) AfterWrite(f *os.File, r symx.WriteResult) error {
	// 用 e.meta 中的实际值回填 ExtHead 中的 Update TLV 字段
	if err := symx.ApplyPatchBindings(f, &e.meta, r.PatchBindings); err != nil {
		return err
	}

	// 修正 FixedHead 中的 PayloadLen（写入时为 0）
	if _, err := symx.CorrectPayloadLen(f, r.PayloadBytes); err != nil {
		return err
	}

	return nil
}

// NewEncoderFactory 创建一个 EncoderFactory 闭包，
// 将 Options 绑定到工厂函数中，适配 symx.EncoderFactory 签名。
func NewEncoderFactory() symx.EncoderFactory {
	return func(opts *symx.WriteOptions) symx.Encoder {
		enc, err := NewEncoder(opts)
		if err != nil {
			// EncoderFactory 无法返回 error，panic 表示编程错误
			panic(fmt.Sprintf("proguard: NewEncoder failed: %v", err))
		}
		return enc
	}
}
