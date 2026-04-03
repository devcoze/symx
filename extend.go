package symx

import (
	"encoding/binary"
	"fmt"
)

// TLV 是一个简单的 Type-Length-Value 结构体，用于表示可选字段或扩展字段。
type TLV struct {
	Typ   uint8  // 1 byte  字段类型
	Len   uint16 // 2 bytes 字段值的长度，最大值为 65535
	Value []byte // value   字段值，长度由 Len 指定
}

// ExtendedHead 是 SymX 文件的可选头部结构体，
// 包含一个 TLV 列表，用于存储文件类型特有的元数据。
type ExtendedHead struct {
	TLVs []TLV // 可选字段列表，长度由 FixedHead 中的 ExtLen 字段指定
}

// ParseExtendedHeader 从给定的字节切片中解析出一个 ExtendedHead 结构体，
func ParseExtendedHeader(segment []byte) (ExtendedHead, error) {
	tlvs := make([]TLV, 0)
	for off := 0; off < len(segment); {
		remain := len(segment) - off
		if remain < 3 {
			return ExtendedHead{}, fmt.Errorf("malformed TLV at offset %d: need at least 3 bytes, got %d", off, remain)
		}

		ln := int(binary.LittleEndian.Uint16(segment[off+1 : off+3]))
		n := 3 + ln
		if n > remain {
			return ExtendedHead{}, fmt.Errorf("malformed TLV at offset %d: len=%d exceeds remaining=%d", off, ln, remain)
		}

		tlv, _ := ReadTLV(segment[off : off+n])
		tlvs = append(tlvs, tlv)
		off += n
	}
	return ExtendedHead{
		TLVs: tlvs,
	}, nil
}

// WriteTLV 将一个 TLV 结构体写入到给定的字节切片中，并返回写入的字节数。
func WriteTLV(buf []byte, t *TLV) int {
	buf[0] = t.Typ
	binary.LittleEndian.PutUint16(buf[1:3], t.Len)
	copy(buf[3:], t.Value)
	return 3 + int(t.Len)
}

// ReadTLV 从给定的字节切片中读取一个 TLV 结构体，并返回该结构体和读取的字节数。
func ReadTLV(buf []byte) (TLV, int) {
	typ := buf[0]
	ln := binary.LittleEndian.Uint16(buf[1:3])
	val := buf[3 : 3+ln]
	return TLV{
		Typ:   typ,
		Len:   ln,
		Value: val,
	}, 3 + int(ln)
}
