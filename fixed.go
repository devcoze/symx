package symx

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// FixedSize
// 固定前缀长度: 4 (Magic) + 1 (FileType) + 1 (Version) + 2 (HeaderExtLen) + 8 (PayloadLen) + 16 (BuildID) = 32 bytes
const FixedSize = 32

// FixedHead 字段在固定前缀中的偏移位置
const (
	MagicOffset      = 0  // Magic 字段在 FixedHead 中的偏移位置
	FileTypeOffset   = 4  // FileType 字段在 FixedHead 中的偏移位置
	VersionOffset    = 5  // Version 字段在 FixedHead 中的偏移位置
	ExtLenOffset     = 6  // HeaderExtLen 字段在 FixedHead 中的偏移位置
	PayloadLenOffset = 8  // PayloadLen 字段在 FixedHead 中的偏移位置
	BuildIDOffset    = 16 // BuildID 字段在 FixedHead 中的偏移位置
)

var (
	ErrInvalidMagic = errors.New("symx: invalid magic number")
)

// Magic SYMX 表示协议魔数，固定为 "SYMX"，用于标识 SymX 协议的文件头。
const Magic uint32 = 0x53594D58 //  = "SYMX" (SymX)

// FileType 类型定义，如 SourceMap、ProGuard 和 Dwarf 等。
const (
	SourceMap = 1 // Js Source Map文件
	ProGuard  = 2 // Java ProGuard 映射文件，或者 Android R8 映射文件
	Dwarf     = 3 // DWARF 调试信息索引文件
)

// BuildId 类型定义，表示 BuildID 的不同来源和处理方式。
// 为了固定头部长度，BuildID 字段始终占用 16 字节，所以会对BuildID进行规范化处理，具体类型如下：
const (
	BIDUnset    = 0 // BIDUnset    表示未设置或未知的 BID 类型
	BIDFull16   = 1 // BIDFull16   = 16 bytes eg: uuid
	BIDTrunc16  = 2 // BIDTrunc16  > 16 bytes 被截断 16 , eg: sha1 或 sha256
	BIDRandFill = 3 // BIDRandFill < 16 bytes 随机填充到 16
	BIDGenerate = 4 // BIDGenerate 没有BID 由 symx 生成一个随机的 16 字节 BID
)

// FixedHead 是 SymX 协议的头部结构体，包含固定前缀和可选字段。
// Magic        (4 bytes)  - 协议魔数，固定为 "SYMX"
// FileType     (1 byte)   - 文件类型
// Version      (1 byte)   - 协议版本号，当前版本为 1
// ExtLen       (2 bytes)  - TLV 变长头长度（不包含固定 32 字节头）
// PayloadLen   (8 bytes)  - 数据体长度
// BuildID      (16 bytes) - 构建 ID，用于唯一标识构建版本，可以是一个 UUID、SHA-1 或 SHA-256 哈希值，或者由 SymX 生成的随机值。
type FixedHead struct {
	Magic      uint32
	FileType   uint8
	Version    uint8
	ExtLen     uint16
	PayloadLen uint64
	BuildID    [16]byte
}

// ParseFixedHeader 从固定 32 字节头中解析 FixedHead。
func ParseFixedHeader(buf []byte) (FixedHead, error) {
	if len(buf) < FixedSize {
		return FixedHead{}, fmt.Errorf("file too small to contain SymxHeader")
	}

	h := FixedHead{
		Magic:      binary.LittleEndian.Uint32(buf[MagicOffset : MagicOffset+4]),
		FileType:   buf[FileTypeOffset],
		Version:    buf[VersionOffset],
		ExtLen:     binary.LittleEndian.Uint16(buf[ExtLenOffset : ExtLenOffset+2]),
		PayloadLen: binary.LittleEndian.Uint64(buf[PayloadLenOffset : PayloadLenOffset+8]),
	}
	copy(h.BuildID[:], buf[BuildIDOffset:BuildIDOffset+len(h.BuildID)])

	return h, nil
}

// NormalizeBuildID 将输入字符串规范化为一个 16 字节的 BuildID。
// 规则：
// 1) 支持 UUID（含 '-'）与纯十六进制字符串，优先按 hex 解析；
// 2) 非 hex 输入按原始字节前缀写入；
// 3) 最终固定为 16 字节，不足随机填充，超长截断。
func NormalizeBuildID(raw string) ([16]byte, int, int) {
	raw = strings.TrimSpace(raw)

	parsed := []byte(raw)
	if raw != "" {
		hexText := raw
		if len(hexText) == 36 && strings.Count(hexText, "-") == 4 {
			hexText = strings.ReplaceAll(hexText, "-", "")
		}
		if len(hexText)%2 == 0 {
			if decoded, err := hex.DecodeString(hexText); err == nil {
				parsed = decoded
			}
		}
	}

	var bid [16]byte
	n := copy(bid[:], parsed)
	if n < 16 {
		_, _ = rand.Read(bid[n:])
	}

	typ := BIDFull16
	if len(parsed) == 0 {
		typ = BIDGenerate
	} else if len(parsed) < 16 {
		typ = BIDRandFill
	} else if len(parsed) > 16 {
		typ = BIDTrunc16
	}

	return bid, typ, len(parsed)
}

// Validate 检查 FixedHead 的 Magic 字段是否正确，如果不正确则返回 ErrInvalidMagic 错误。
func (h *FixedHead) Validate() error {
	if h.Magic != Magic {
		return ErrInvalidMagic
	}
	return nil
}
