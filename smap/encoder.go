package smap

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/bytedance/sonic"
	"github.com/devcoze/symx"
)

const (
	versionKey    = "version"
	sourceRootKey = "sourceRoot"
	fileKey       = "file"
	mappingsKey   = "mappings"
)

// Encoder 负责将 SourceMap 数据编码为 SymX 格式。它实现了 symx.Encoder 接口，包含必要的元数据和索引信息以供写入使用。
type Encoder struct {
	opts *symx.WriteOptions
	data []byte
	meta Metadata
}

// NewEncoder 创建一个新的 Encoder 实例，接受 WriteOptions 作为参数以配置输入输出路径。
func NewEncoder(opts *symx.WriteOptions) (*Encoder, error) {
	data, err := os.ReadFile(opts.Input)
	if err != nil {
		return nil, err
	}
	enc := &Encoder{
		opts: opts,
		data: data,
		meta: Metadata{
			CompileTime: uint64(time.Now().UnixMilli()),
			OriFile:     opts.Output,
		},
	}
	err = enc.scanMetadata()
	if err != nil {
		return nil, err
	}
	return enc, nil
}

// scanMetadata 从 SourceMap JSON 数据中提取版本、SourceRoot 和原始文件路径等元数据信息。
func (e *Encoder) scanMetadata() error {
	// 版本，目前应该都是 3
	version, err := extractKey(e.data, versionKey)
	if err != nil {
		return err
	}
	e.meta.Version = version

	// SourceRoot
	sourceRoot, err := extractKey(e.data, sourceRootKey)
	if err != nil {
		return err
	}
	e.meta.SourceRoot = sourceRoot

	// file
	filename, err := extractKey(e.data, fileKey)
	if err != nil {
		return err
	}
	e.meta.OriFile = filename
	return nil
}

// FileType 返回文件类型标识（SourceMap）。
func (e *Encoder) FileType() uint8 {
	return symx.SourceMap
}

// Identify 返回一个字符串标识，用于调试和日志输出，帮助区分不同类型的 Encoder 实现。这里使用 SourceMap 文件内容的 SHA-1 哈希值作为标识，确保同一内容的 SourceMap 具有相同的标识。
func (e *Encoder) Identify() string {
	hash := sha1.New()
	hash.Write(e.data)
	return hex.EncodeToString(hash.Sum(nil))
}

// ExtHeadSize 返回 TLV 扩展头的字节总长，用于填写固定头中的 ExtLen 字段。
func (e *Encoder) ExtHeadSize() uint16 {
	return uint16(symx.MustTLVsSize(&e.meta))
}

// PayloadSize 返回 Line 与 Segment 索引区的总字节数。
func (e *Encoder) PayloadSize() uint64 {
	// 目前的实现中，行索引和段索引的数据结构是动态生成的，无法在预计算阶段准确计算其字节长度，因此暂时返回 0。
	// 在 WritePayload 中实际写入时，会根据行索引和段索引的数量动态计算并写入正确的字节数。
	return uint64(0)
}

// WriteExtHead 将文件类型特有的元数据以 TLV 格式流式写入 w。写入的字节数必须等于 ExtHeadSize() 的返回值。
func (e *Encoder) WriteExtHead(cw *symx.CountingWriter) error {
	return symx.WriteTLVsTo(cw, &e.meta)
}

// WritePayload 将文件类型特有的索引数据流式写入 w。写入的字节数必须等于 PayloadSize() 的返回值。
func (e *Encoder) WritePayload(cw *symx.CountingWriter) error {
	// mappings
	mappings, err := extractKey(e.data, mappingsKey)
	if err != nil {
		return err
	}
	segments, lines := parseMappings(mappings)

	// 写入行
	e.meta.LineOff = uint32(cw.Offset())
	e.meta.LineCnt = uint32(len(lines))
	var lineBuf [lineSize]byte
	for _, line := range lines {
		binary.LittleEndian.PutUint32(lineBuf[0:4], line.Start)
		binary.LittleEndian.PutUint32(lineBuf[4:8], line.End)
		if _, err := cw.Write(lineBuf[:]); err != nil {
			return err
		}
	}

	// 写入段
	e.meta.SegmentOff = uint32(cw.Offset())
	e.meta.SegmentCnt = uint32(len(segments))
	var segmentBuf [segmentSize]byte
	for _, segment := range segments {
		binary.LittleEndian.PutUint32(segmentBuf[0:4], segment.GenCol)
		binary.LittleEndian.PutUint32(segmentBuf[4:8], segment.SrcIdx)
		binary.LittleEndian.PutUint32(segmentBuf[8:12], segment.SrcLine)
		binary.LittleEndian.PutUint32(segmentBuf[12:16], segment.SrcCol)
		if _, err := cw.Write(segmentBuf[:]); err != nil {
			return err
		}
	}
	return nil
}

// AfterWrite 是一个回调函数，在文件写入完成后被调用。
// 它回填 ExtHead 中 Update TLV 字段的实际值，并修正 FixedHead 中的 PayloadLen 字段。
func (e *Encoder) AfterWrite(w *os.File, wr symx.WriteResult) error {
	if err := symx.ApplyPatchBindings(w, &e.meta, wr.PatchBindings); err != nil {
		return err
	}
	if _, err := symx.CorrectPayloadLen(w, wr.PayloadBytes); err != nil {
		return err
	}
	return nil
}

// extractKey 从 SourceMap JSON 数据中提取指定键的字符串值，使用 sonic 库进行高效的 JSON 解析，避免全量反序列化。
func extractKey(data []byte, key string) (string, error) {
	n, err := sonic.Get(data, key)
	if err != nil {
		return "", err
	}
	return n.String()
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
