package dwarf

import (
	"encoding/binary"
	"io"

	"github.com/devcoze/symx"
)

// TLV 字段类型：DWARF 专用（30-39 区间）
const (
	tlvArch       uint8 = 30
	tlvStringPool uint8 = 31
)

// Arch 表示目标架构类型。
type Arch uint8

const (
	ArchUnknown Arch = 0
	ArchARM64   Arch = 1
	ArchX86_64  Arch = 2
	ArchX86     Arch = 3
	ArchARM     Arch = 4
)

// RangeEntry 表示 DWARF 中一条地址区间到源码位置的映射。
// 固定 24 字节：StartAddr(8) + EndAddr(8) + FileIdx(4) + Line(4)
type RangeEntry struct {
	StartAddr uint64
	EndAddr   uint64
	FileIdx   uint32
	Line      uint32
}

// Encoder 将 DWARF 调试信息编码为 SymX 格式。
//
// ExtHead 布局：
//
//	TLV(tlvArch,       uint8)   — 目标架构
//	TLV(tlvStringPool, []byte)  — 源文件路径字符串池（uint16 长度前缀 + UTF-8 内容）
//
// Payload 布局（每条 24 字节，按 StartAddr 升序排列）：
//
//	StartAddr uint64 | EndAddr uint64 | FileIdx uint32 | Line uint32
type Encoder struct {
	Arch        Arch
	SourceFiles []string
	Ranges      []RangeEntry
	BuildID     []byte
}

func (e *Encoder) FileType() uint8 { return symx.Dwarf }

func (e *Encoder) poolSize() int {
	n := 0
	for _, s := range e.SourceFiles {
		n += 2 + len(s)
	}
	return n
}

func (e *Encoder) ExtHeadSize() int {
	// TLV(tlvArch): 3 + 1 = 4
	// TLV(tlvStringPool): 3 + poolSize
	return symx.TLVSize(1) + symx.TLVSize(e.poolSize())
}

func (e *Encoder) PayloadSize() int { return len(e.Ranges) * 24 }

func (e *Encoder) WriteExtHead(w io.Writer) error {
	if err := symx.WriteTLVTo(w, tlvArch, 1, func(w io.Writer) error {
		_, err := w.Write([]byte{byte(e.Arch)})
		return err
	}); err != nil {
		return err
	}

	return symx.WriteTLVTo(w, tlvStringPool, e.poolSize(), func(w io.Writer) error {
		var lenBuf [2]byte
		for _, s := range e.SourceFiles {
			binary.LittleEndian.PutUint16(lenBuf[:], uint16(len(s)))
			if _, err := w.Write(lenBuf[:]); err != nil {
				return err
			}
			if _, err := io.WriteString(w, s); err != nil {
				return err
			}
		}
		return nil
	})
}

func (e *Encoder) WritePayload(w io.Writer) error {
	var buf [24]byte
	for _, r := range e.Ranges {
		binary.LittleEndian.PutUint64(buf[0:], r.StartAddr)
		binary.LittleEndian.PutUint64(buf[8:], r.EndAddr)
		binary.LittleEndian.PutUint32(buf[16:], r.FileIdx)
		binary.LittleEndian.PutUint32(buf[20:], r.Line)
		if _, err := w.Write(buf[:]); err != nil {
			return err
		}
	}
	return nil
}
