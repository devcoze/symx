package smap

import (
	"encoding/binary"
	"os"
	"time"

	"github.com/bytedance/sonic"
	"github.com/devcoze/symx"
)

const (
	VersionKey    = "version"
	SourceRootKey = "sourceRoot"
	FileKey       = "file"
	MappingsKey   = "mappings"
)

// Encoder 负责将 SourceMap 数据编码为 SymX 格式。它实现了 engine.Encoder 接口，包含必要的元数据和索引信息以供写入使用。
type Encoder struct {
	meta     Metadata
	Segments []Segment
	Lines    []Line
}

// NewEncoder 创建一个新的 Encoder 实例，接受 Options 作为参数以配置输入输出路径。
func NewEncoder() *Encoder {
	return &Encoder{
		meta: Metadata{
			CompileTime: uint64(time.Now().UnixMilli()),
		},
	}
}

// Parse 读取输入文件并解析 SourceMap JSON 数据，提取必要的元数据和映射信息，填充 Encoder 的字段以供后续写入使用。
func (e *Encoder) Parse(input string) error {
	data, err := os.ReadFile(input)
	if err != nil {
		return err
	}

	e.meta.OriFile = input

	// 版本，目前应该都是 3
	version, err := extractKey(data, VersionKey)
	if version != "" {
		e.meta.Version = version
	}

	// SourceRoot
	sourceRoot, err := extractKey(data, SourceRootKey)
	if sourceRoot != "" {
		e.meta.SourceRoot = sourceRoot
	}

	// file
	filename, err := extractKey(data, FileKey)
	if filename != "" {
		e.meta.OriFile = filename
	}

	// mappings
	mappings, err := extractKey(data, MappingsKey)
	if err != nil {
		return err
	}

	segments, lines := parseMappings(mappings)
	e.Lines = lines
	e.Segments = segments
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

// FileType 返回文件类型标识（SourceMap）。
func (e *Encoder) FileType() uint8 {
	return symx.SourceMap
}

func (e *Encoder) Identify() string {
	return ""
}

// ExtHeadSize 返回 TLV 扩展头的字节总长，用于填写固定头中的 ExtLen 字段。
func (e *Encoder) ExtHeadSize() uint16 {
	return uint16(symx.MustTLVsSize(&e.meta))
}

// PayloadSize 返回 Line 与 Segment 索引区的总字节数。
func (e *Encoder) PayloadSize() uint64 {
	return uint64(len(e.Lines)*lineSize + len(e.Segments)*segmentSize)
}

// WriteExtHead 将文件类型特有的元数据以 TLV 格式流式写入 w。写入的字节数必须等于 ExtHeadSize() 的返回值。
func (e *Encoder) WriteExtHead(cw *symx.CountingWriter) error {
	return symx.WriteTLVsTo(cw, &e.meta)
}

// WritePayload 将文件类型特有的索引数据流式写入 w。写入的字节数必须等于 PayloadSize() 的返回值。
func (e *Encoder) WritePayload(cw *symx.CountingWriter) error {

	// 写入行
	e.meta.LineOff = uint64(cw.Offset())
	e.meta.LineCnt = uint32(len(e.Lines))
	var lineBuf [lineSize]byte
	for _, line := range e.Lines {
		binary.LittleEndian.PutUint32(lineBuf[0:4], line.Start)
		binary.LittleEndian.PutUint32(lineBuf[4:8], line.End)
		if _, err := cw.Write(lineBuf[:]); err != nil {
			return err
		}
	}

	// 写入段
	e.meta.SegmentOff = uint64(cw.Offset())
	e.meta.SegmentCnt = uint32(len(e.Segments))
	var segmentBuf [segmentSize]byte
	for _, segment := range e.Segments {
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

// AfterWrite 是一个回调函数，在文件写入完成后被调用
func (e *Encoder) AfterWrite(w *os.File, wr symx.WriteResult) error {
	return symx.ApplyPatchBindings(w, &e.meta, wr.PatchBindings)
}
