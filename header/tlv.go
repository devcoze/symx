package header

import "encoding/binary"

const ()

// TLV 是一个简单的 Type-Length-Value 结构体，用于表示可选字段或扩展字段。
type TLV struct {
	Type   uint8  // 1 byte,   字段类型,
	Length uint16 // 2 bytes,  字段值的长度，最大值为 65535
	Value  []byte // variable, 字段值，长度由 Length 指定
}

// WriteTLV 将一个 TLV 结构体写入到给定的字节切片中，并返回写入的字节数。
func WriteTLV(buf []byte, t *TLV) int {
	buf[0] = byte(t.Type)
	binary.LittleEndian.PutUint16(buf[1:3], t.Length)
	copy(buf[3:], t.Value)
	return 3 + int(t.Length)
}

// ReadTLV 从给定的字节切片中读取一个 TLV 结构体，并返回该结构体和读取的字节数。
func ReadTLV(buf []byte) (TLV, int) {
	typ := buf[0]
	ln := binary.LittleEndian.Uint16(buf[1:3])
	val := buf[3 : 3+ln]
	return TLV{
		Type:   typ,
		Length: ln,
		Value:  val,
	}, 3 + int(ln)
}
