package symx

import (
	"encoding/binary"
	"math/bits"
)

// ---------------------------------------------------------------------------
// StringPool — 去重字符串池（写入侧），带紧凑 hash table。
//
// 编码格式（小端序）：每个唯一字符串存储一次，格式为 [uint16 长度][字节内容...]。
// Put 返回该字符串在序列化数据中的字节偏移。
// 偏移 0 固定为空字符串：[0x00, 0x00]（长度=0）。
//
// 内部使用 open-addressing（线性探测）hash table 替代 Go map[string]uint32，
// 将去重索引的内存开销从 ~110B/entry 降至 8B/entry（hash + offset）。
// 查找时通过偏移回查 data 比对原始字节，避免存储 string key 拷贝。
//
// 本类型供 Encoder（写入侧）使用。Decoder（读取侧）直接操作 mmap []byte，
// 使用 ReadStringAt 包级函数进行零拷贝读取。
// ---------------------------------------------------------------------------

const (
	// 初始 hash table 容量（必须为 2 的幂）
	spInitCap = 256
	// 最大负载因子：当 count >= cap * spLoadNum / spLoadDen 时扩容
	spLoadNum = 3
	spLoadDen = 4
)

// spEntry 是 hash table 的槽位。
// off == 0 表示空槽（偏移 0 已被空字符串占用，空字符串走快速路径不查表）。
type spEntry struct {
	hash uint32 // 字符串的 hash 值
	off  uint32 // 在 data 中的字节偏移
}

// StringPool 是去重字符串池，提供字符串→偏移的映射和序列化。
// 写入侧使用。
type StringPool struct {
	data  []byte    // 序列化数据：[uint16 len][bytes...]...
	table []spEntry // open-addressing hash table（2 的幂大小）
	mask  uint32    // len(table) - 1
	count uint32    // 已使用的槽位数
}

// NewStringPool 创建新的字符串池，偏移 0 为空字符串。
func NewStringPool() *StringPool {
	p := &StringPool{
		table: make([]spEntry, spInitCap),
		mask:  spInitCap - 1,
	}
	// 偏移 0：空字符串（长度为 0），不插入 hash table（走快速路径）
	p.data = append(p.data, 0, 0) // uint16(0)
	return p
}

// Put 将字符串插入池中（如果尚未存在），返回其在序列化数据中的字节偏移。
func (p *StringPool) Put(s string) uint32 {
	if len(s) == 0 {
		return 0
	}

	h := fnv1a32(s)
	idx := h & p.mask

	for {
		e := &p.table[idx]
		if e.off == 0 {
			// 空槽 → 插入新字符串
			break
		}
		if e.hash == h && p.dataEquals(e.off, s) {
			return e.off
		}
		idx = (idx + 1) & p.mask
	}

	// 写入 data
	off := uint32(len(p.data))
	b := []byte(s)
	var lenBuf [2]byte
	binary.LittleEndian.PutUint16(lenBuf[:], uint16(len(b)))
	p.data = append(p.data, lenBuf[:]...)
	p.data = append(p.data, b...)

	// 插入 hash table
	p.table[idx] = spEntry{hash: h, off: off}
	p.count++

	// 检查是否需要扩容
	if p.count*spLoadDen >= (p.mask+1)*spLoadNum {
		p.grow()
	}

	return off
}

// ReadAt 读取指定字节偏移处的字符串（从 data 中读取）。
// 编码期间需要回查时使用（如排序时比较键值）。
func (p *StringPool) ReadAt(off uint32) string {
	return ReadStringAt(p.data, off)
}

// Len 返回序列化后的总字节数。
func (p *StringPool) Len() int { return len(p.data) }

// Bytes 返回序列化后的池数据。
func (p *StringPool) Bytes() []byte { return p.data }

// ---------------------------------------------------------------------------
// 内部方法
// ---------------------------------------------------------------------------

// dataEquals 比较 data[off] 处的字符串与 s 是否相等（零拷贝）。
func (p *StringPool) dataEquals(off uint32, s string) bool {
	pos := int(off)
	if pos+2 > len(p.data) {
		return false
	}
	length := int(binary.LittleEndian.Uint16(p.data[pos : pos+2]))
	if length != len(s) {
		return false
	}
	pos += 2
	if pos+length > len(p.data) {
		return false
	}
	for i := 0; i < length; i++ {
		if p.data[pos+i] != s[i] {
			return false
		}
	}
	return true
}

// grow 将 hash table 扩容为 2 倍，重新插入所有条目。
func (p *StringPool) grow() {
	newCap := (p.mask + 1) * 2
	if newCap == 0 {
		newCap = spInitCap
	}
	newTable := make([]spEntry, newCap)
	newMask := newCap - 1

	for i := range p.table {
		e := &p.table[i]
		if e.off == 0 {
			continue
		}
		idx := e.hash & newMask
		for newTable[idx].off != 0 {
			idx = (idx + 1) & newMask
		}
		newTable[idx] = *e
	}

	p.table = newTable
	p.mask = newMask
}

// fnv1a32 计算字符串的 FNV-1a 32-bit hash。
func fnv1a32(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// ---------------------------------------------------------------------------
// ReadStringAt — 读取侧（Decoder）使用的包级函数
//
// 从原始字节切片（通常是 mmap 的子切片）的指定偏移处读取一个字符串。
// 注意：返回的 string 是从 data 中拷贝的（Go 语义要求）。
// ---------------------------------------------------------------------------

// ReadStringAt 从字节切片的指定偏移处读取一个长度前缀编码的字符串。
// 编码格式：[uint16 长度（小端序）][字节内容...]。
func ReadStringAt(data []byte, off uint32) string {
	if int(off)+2 > len(data) {
		return ""
	}
	length := binary.LittleEndian.Uint16(data[off : off+2])
	if length == 0 {
		return ""
	}
	start := off + 2
	end := start + uint32(length)
	if int(end) > len(data) {
		return ""
	}
	return string(data[start:end])
}

// nextPow2 is used internally. Keeping for reference.
func init() {
	// Verify spInitCap is a power of 2 at init time.
	if bits.OnesCount(spInitCap) != 1 {
		panic("symx: spInitCap must be a power of 2")
	}
}
