package header

import (
	"crypto/rand"
	"errors"
)

// HeaderFixedSize
// 固定前缀长度:
//
//	Magic (4 bytes) + FileType (1 byte) + Version (1 byte) + HeadLen (2 bytes) = 8 bytes
const HeaderFixedSize = 32

var (
	ErrInvalidMagic      = errors.New("symx: invalid magic number")
	ErrUnknownMagic      = errors.New("symx: unknown magic number, no codec registered")
	ErrHeaderTooSmall    = errors.New("symx: header size less than minimum (8)")
	ErrPayloadTooLarge   = errors.New("symx: payload exceeds max header size")
	ErrVersionMismatch   = errors.New("symx: version mismatch")
	ErrShortRead         = errors.New("symx: short read")
	ErrDuplicateRegister = errors.New("symx: duplicate codec registration for magic")
)

// Magic SYMX 表示协议魔数，固定为 "SYMX"，用于标识 SymX 协议的文件头。
const Magic uint32 = 0x53594D58 //  = "SYMX" (SymX)

const (
	SourceMap = 1 // Js Source Map文件
	ProGuard  = 2 // Java ProGuard 映射文件，或者 Android R8 映射文件
	Dwarf     = 3 // DWARF 调试信息索引文件
)

const (
	BIDUnset    = 0 // BIDUnset    表示未设置或未知的 BID 类型
	BIDFull16   = 1 // BIDFull16   = 16 bytes eg: uuid
	BIDTrunc16  = 2 // BIDTrunc16  > 16 bytes 被截断 16 , eg: sha1 或 sha256
	BIDRandFill = 3 // BIDRandFill < 16 bytes 随机填充到 16
	BIDGenerate = 4 // BIDGenerate 没有BID 由 symx 生成一个随机的 16 字节 BID
)

// SymxHeader 是 SymX 协议的头部结构体，包含固定前缀和可选字段。
// Magic    (4 bytes) - 协议魔数，固定为 "SYMX"
// FileType (1 byte)  - 文件类型，1=SourceMap, 2=ProGuard, 3=Dwarf
// Version  (1 byte)  - 协议版本号，当前版本为 1
// HeadLen  (2 bytes) - 头部总长度，包含固定前缀，最小值为 8
// DataLen  (8 bytes)  - 可选字段，表示数据体长度，默认为 0
// BuildId  (16 bytes) - 可选字段，表示构建 ID，默认为全零
type SymxHeader struct {
	Magic    uint32   // 4 bytes
	FileType uint8    // 1 byte
	Version  uint8    // 1 byte
	HeadLen  uint16   // 2 bytes, 包含固定前缀的头部总长度，最小值为 8, 最大值为 65535
	DataLen  uint64   // 8 bytes, 可选字段，表示数据体长度，默认为 0
	BuildId  [16]byte // 16 bytes, 可选字段，表示构建 ID
}

// NormalizeBuildId 将输入的 raw 字节切片规范化为一个 16 字节的 BuildId，
// 并返回规范化后的 BuildId、BuildId 类型和原始长度。
func NormalizeBuildId(raw []byte) ([16]byte, int, int) {
	var bid [16]byte
	n := copy(bid[:], raw)
	if n < 16 {
		_, _ = rand.Read(bid[n:])
	}

	typ := BIDFull16
	if len(raw) == 0 {
		typ = BIDGenerate
	} else if len(raw) < 16 {
		typ = BIDRandFill
	} else if len(raw) > 16 {
		typ = BIDTrunc16
	}

	return bid, typ, n
}
