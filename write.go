package symx

import (
	"encoding/binary"
	"io"
	"os"
	"strings"
)

type EncoderInitFunc func(*WriteOptions) Encoder

// WriteOptions 写入时固定头的公共参数。
type WriteOptions struct {
	Input    string // 输入文件路径，即需要Codec解析的原始文件路径，供 Encoder 解析使用
	Output   string // 输出文件路径
	FileType uint8  // 文件类型标识（SourceMap / ProGuard / Dwarf 等常量），供回调使用
	Version  uint8  // 协议版本，0 时默认填 1
	BuildID  string // 原始 BuildID，由 NormalizeBuildID 规范化为 16 字节
}

func NewWriteOptions(input string, output string, ft uint8) *WriteOptions {
	return &WriteOptions{
		Input:    "",
		Output:   "",
		FileType: 0,
		Version:  0,
		BuildID:  "",
	}
}

// WriteResult 记录一次完整写入的实际字节统计，由 Write 返回并传递给回调。
type WriteResult struct {
	FixedHeadBytes int64          // 固定头实际写入字节数（应等于 FixedSize）
	ExtHeadBytes   int64          // TLV 扩展头实际写入字节数
	PayloadBytes   int64          // 有效负载实际写入字节数
	PatchBindings  []PatchBinding // 记录允许回填字段的绑定信息，供写入完成后的回调使用
}

// PatchBinding 记录一个可回填字段在文件中的位置和其对应的 struct 字段绑定信息。
// 写入完成后，可通过 ApplyPatchBindings 从目标 struct 中按 FieldIndex 取出当前值并回填到文件。
// 注意：仅支持固定宽度字段（uint8/uint16/uint32/uint64）。
type PatchBinding struct {
	Type       uint8  // 对应 TLV 的 Type
	Offset     int64  // TLV Value 在文件中的起始偏移（相对于文件开头）
	Size       int    // TLV Value 的固定字节宽度（1、2、4 或 8）
	FieldIndex []int  // 反射字段路径，供 FieldByIndex 使用
	FieldName  string // 便于调试和错误提示
}

// TotalBytes 返回本次写入的总字节数。
func (r WriteResult) TotalBytes() int64 {
	return r.FixedHeadBytes + r.ExtHeadBytes + r.PayloadBytes
}

// AfterWriter 是可选接口，Encoder 可选择实现，以便在写入完成后更新自身状态。
// 例如：记录实际写入的偏移、更新校验和字段等。
// Write 函数会检测 Encoder 是否实现该接口并调用它。
type AfterWriter interface {
	AfterWrite(w *os.File, r WriteResult) error
}

// CountingWriter 包装 io.Writer，统计已写入字节数。
type CountingWriter struct {
	w       io.Writer      // wrapped writer
	n       int64          // total bytes written
	patches []PatchBinding // 记录写入过程中发现的可回填字段绑定信息，由 WriteExtHead / WritePayload 调用 recordPatchBinding 填充
}

// WriteTLVTo 的 writeValue 回调中调用 recordPatchBinding 记录可回填字段绑定信息。
func (c *CountingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// Offset 返回当前已写入的字节数，供 WriteExtHead / WritePayload 在记录 PatchBinding 时使用。
func (c *CountingWriter) Offset() int64 {
	return c.n
}

// recordPatchBinding 将一个 PatchBinding 追加到 CountingWriter 的 patches 切片中，供 WriteResult 返回和回调使用。
func (c *CountingWriter) recordPatchBinding(binding PatchBinding) {
	c.patches = append(c.patches, binding)
}

// Write 将任意 Encoder 流式编码为完整的 SymX 二进制文件并写入 w。
//
// 写入顺序：
//
//	[固定头 32 bytes] [TLV 扩展头 ExtLen bytes] [有效负载 PayloadLen bytes]
//
// 固定头通过 ExtHeadSize / PayloadSize 预计算填写，
// 后续数据由 WriteExtHead / WritePayload 直接流式输出，无中间缓冲。
// 写入完成后依次触发 opts.OnWritten 回调和 Encoder 的 AfterWrite（若实现）。
func Write(opts *WriteOptions, initEF EncoderInitFunc) (WriteResult, error) {
	output := opts.Output
	// 创建或覆盖输出文件，确保写入前文件为空。
	f, err := os.OpenFile(output, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return WriteResult{}, err
	}
	defer f.Close()

	enc := initEF(opts)

	// 如果 opts.BuildID 为空，则调用 Encoder 的 Identify 方法来获取
	buildID := strings.TrimSpace(opts.BuildID)
	if len(buildID) == 0 {
		buildID = enc.Identify()
	}
	bid, _, _ := NormalizeBuildID(buildID)
	ver := opts.Version
	if ver == 0 {
		ver = 1
	}
	hdr := FixedHead{
		Magic:      Magic,
		FileType:   enc.FileType(),
		Version:    ver,
		ExtLen:     enc.ExtHeadSize(),
		PayloadLen: enc.PayloadSize(),
		BuildID:    bid,
	}

	cw := &CountingWriter{w: f}
	var result WriteResult

	// 序列化固定头（栈上 32 字节，一次性写入）
	var buf [FixedSize]byte
	binary.LittleEndian.PutUint32(buf[MagicOffset:], hdr.Magic)
	buf[FileTypeOffset] = hdr.FileType
	buf[VersionOffset] = hdr.Version
	binary.LittleEndian.PutUint16(buf[ExtLenOffset:], hdr.ExtLen)
	binary.LittleEndian.PutUint64(buf[PayloadLenOffset:], hdr.PayloadLen)
	copy(buf[BuildIDOffset:], hdr.BuildID[:])

	if _, err := cw.Write(buf[:]); err != nil {
		return result, err
	}
	result.FixedHeadBytes = cw.n

	// 流式写入扩展头和有效负载，无需整体缓冲，直接写入 w。
	if hdr.ExtLen > 0 {
		before := cw.n
		if err := enc.WriteExtHead(cw); err != nil {
			return result, err
		}
		result.ExtHeadBytes = cw.n - before
		result.PatchBindings = append(result.PatchBindings, cw.patches...)
	}

	// PayloadSize 可能依赖于 WriteExtHead 的结果，因此在写入前再次确认 PayloadLen 是否正确。
	if hdr.PayloadLen > 0 {
		before := cw.n
		if err := enc.WritePayload(cw); err != nil {
			return result, err
		}
		result.PayloadBytes = cw.n - before
	}

	// 触发 Encoder 自身回调（可选实现）
	if aw, ok := enc.(AfterWriter); ok {
		if err := aw.AfterWrite(f, result); err != nil {
			return result, err
		}
	}

	return result, nil
}

// WriteExtLen 更新固定头中 ExtLen，
// 如果在写入之前就能确定 ExtLen 的值，可以实现 ExtHeadSize 就不需要事后修正了。
func WriteExtLen(wa io.WriterAt, extLen int) (int, error) {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], uint16(extLen))
	n, err := wa.WriteAt(buf[:], ExtLenOffset)
	return n, err
}

// CorrectPayloadLen 更新固定头中 PayloadLen，
// 如果在写入之前就能确定 PayloadLen 的值，可以实现 PayloadSize 就不需要事后修正了。
func CorrectPayloadLen(wa io.WriterAt, payload int64) (int64, error) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(payload))
	n, err := wa.WriteAt(buf[:], PayloadLenOffset)
	return int64(n), err
}

// WriteTLVTo 流式写入一个 TLV 项：先写 3 字节头（T+L），再调用 writeValue 写入内容。
// valueLen 必须与 writeValue 实际写入的字节数一致。
func WriteTLVTo(w io.Writer, typ uint8, valueLen int, writeValue func(io.Writer) error) error {
	var hdr [3]byte
	hdr[0] = typ
	binary.LittleEndian.PutUint16(hdr[1:], uint16(valueLen))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	return writeValue(w)
}

// TLVSize 返回一个 TLV 项序列化后的总字节数（3 字节头 + 内容长度）。
func TLVSize(valueLen int) int {
	return 3 + valueLen
}

// EncodeTLVs 将一组 TLV 序列化为字节切片（适用于尺寸极小的扩展头）。
func EncodeTLVs(tlvs []TLV) []byte {
	total := 0
	for _, t := range tlvs {
		total += 3 + int(t.Len)
	}
	buf := make([]byte, total)
	off := 0
	for i := range tlvs {
		off += WriteTLV(buf[off:], &tlvs[i])
	}
	return buf
}

// NewTLV 构造一个 TLV 结构体，自动填充 Len 字段。
func NewTLV(typ uint8, value []byte) TLV {
	return TLV{Typ: typ, Len: uint16(len(value)), Value: value}
}
