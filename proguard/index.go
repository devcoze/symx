package proguard

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

// ---------------------------------------------------------------------------
// Layer 3: Binary (High-Performance Storage)
//
// Produces a `mmap-friendly` binary format from IR.
// No struct-level information — only offsets and fixed-size entries.
//
// Layout (all little-endian):
//
//   [Header]            — 64 bytes, fixed
//   [ClassIndex]        — sorted by obfClassName hash, supports binary search
//   [DataBlock]         — variable-length per-class data (methods, lines, frames, metadata)
//   [StringPool]        — all interned strings, length-prefixed
//
// ---------------------------------------------------------------------------

const (
	pgidxMagic   = "PGIX"
	pgidxVersion = 2
	pgidxExt     = ".pgidx"
	headerSize   = 64
)

type Metadata struct {
}

// ---------------------------------------------------------------------------
// Binary Header (64 bytes)
// ---------------------------------------------------------------------------

// BinHeader is the file header (64 bytes).
type BinHeader struct {
	Magic         [4]byte  // "PGIX"
	Version       uint32   // format version (currently 2)
	ClassCount    uint32   // number of class index entries
	ClassIdxOff   uint32   // offset to ClassIndex section
	DataBlockOff  uint32   // offset to DataBlock section
	DataBlockLen  uint32   // length of DataBlock in bytes
	StringPoolOff uint32   // offset to StringPool section
	StringPoolLen uint32   // length of StringPool in bytes
	TotalMethods  uint32   // total method count (informational)
	TotalLines    uint32   // total line mapping count (informational)
	TotalMetadata uint32   // total metadata entry count (informational)
	_             [20]byte // reserved, pad to 64 bytes
}

// ---------------------------------------------------------------------------
// ClassIndex entry (32 bytes) — sorted, binary-searchable
// ---------------------------------------------------------------------------

const classIndexEntrySize = 32

// BinClassIndexEntry points from obfuscated class name into the DataBlock.
type BinClassIndexEntry struct {
	ObfName     uint32   // string pool offset of obfuscated class name
	OriName     uint32   // string pool offset of original class name
	DataOff     uint32   // offset within DataBlock to this class's data
	MethodCount uint16   // number of methods
	FieldCount  uint16   // number of fields
	MetaCount   uint16   // number of class-level metadata entries
	_           [10]byte // reserved / padding to 32 bytes
}

// ---------------------------------------------------------------------------
// DataBlock sub-entries (variable layout per class)
//
// Per class, the DataBlock contains:
//   [MethodEntry * MethodCount]
//   [FieldEntry * FieldCount]
//   [MetadataEntry * MetaCount]        (class-level metadata)
//
// Per MethodEntry:
//   Inline: the method's Lines and Frames follow contiguously after methods.
//           MethodEntry.LineOff is relative to DataBlock start.
//
// Per-method line data at LineOff:
//   [LineEntry * LineCount]
//
// Per LineEntry:
//   FrameOff points to [FrameEntry * FrameCount] relative to DataBlock start.
//
// Per-method metadata at MetaOff:
//   [MetadataEntry * MetaCount]
// ---------------------------------------------------------------------------

const methodEntrySize = 32

// BinMethodEntry (32 bytes)
type BinMethodEntry struct {
	ObfName   uint32  // string pool offset
	OriName   uint32  // string pool offset
	Return    uint32  // string pool offset
	Args      uint32  // string pool offset
	LineOff   uint32  // offset in DataBlock to LineEntry array
	LineCount uint16  // number of line entries
	MetaOff   uint32  // offset in DataBlock to method MetadataEntry array
	MetaCount uint16  // number of method-level metadata entries
	_         [4]byte // padding to 32 bytes
}

const fieldEntrySize = 12

// BinFieldEntry (12 bytes)
type BinFieldEntry struct {
	ObfName uint32 // string pool offset
	OriName uint32 // string pool offset
	Type    uint32 // string pool offset
}

const lineEntrySize = 16

// BinLineEntry (16 bytes) — one obfuscated line range
type BinLineEntry struct {
	ObfStart   uint32 // obfuscated line start
	ObfEnd     uint32 // obfuscated line end
	FrameOff   uint32 // offset in DataBlock to FrameEntry array
	FrameCount uint16 // number of frames (>1 = inline)
	_          [2]byte
}

const frameEntrySize = 24

// BinFrameEntry (24 bytes) — one original frame
type BinFrameEntry struct {
	OriClass  uint32 // string pool offset
	OriMethod uint32 // string pool offset
	Return    uint32 // string pool offset
	Args      uint32 // string pool offset
	OriStart  uint32 // original line start
	OriEnd    uint32 // original line end
}

const metadataEntrySize = 12

// BinMetadataEntry (12 bytes) — one metadata record
type BinMetadataEntry struct {
	ID      uint32 // string pool offset of metadata ID string
	CondOff uint32 // offset in DataBlock to conditions string ID array (uint32[])
	ActOff  uint32 // offset in DataBlock to actions string ID array (uint32[])
}

// We encode condition/action counts in the first uint32 at CondOff/ActOff:
//   [count:uint16][id0:uint32][id1:uint32]...
// For simplicity, metadata condition/action blocks are:
//   [count:uint16][padding:uint16][ids:uint32 * count]

const metaListHeaderSize = 4 // uint16 count + uint16 padding

// ---------------------------------------------------------------------------
// String Pool binary format
//
// Strings are stored as: [uint16 length][bytes...]
// Offset 0 is always the empty string: [0x00, 0x00] (length=0)
// ---------------------------------------------------------------------------

// BinStringPool is the serialized string pool.
type BinStringPool struct {
	data   []byte
	lookup map[uint32]uint32 // IR string ID → byte offset in data
}

func newBinStringPool() *BinStringPool {
	sp := &BinStringPool{
		lookup: make(map[uint32]uint32),
	}
	// Offset 0: empty string (length 0)
	sp.data = append(sp.data, 0, 0) // uint16(0)
	sp.lookup[0] = 0
	return sp
}

// put adds a string from the IR pool (by ID) to the binary pool.
func (sp *BinStringPool) put(irID uint32, s string) uint32 {
	if off, ok := sp.lookup[irID]; ok {
		return off
	}
	if len(s) == 0 {
		sp.lookup[irID] = 0
		return 0
	}
	off := uint32(len(sp.data))
	b := []byte(s)
	lenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBuf, uint16(len(b)))
	sp.data = append(sp.data, lenBuf...)
	sp.data = append(sp.data, b...)
	sp.lookup[irID] = off
	return off
}

// resolve maps an IR string ID to its binary pool offset.
func (sp *BinStringPool) resolve(irID uint32) uint32 {
	return sp.lookup[irID]
}

// ---------------------------------------------------------------------------
// Builder: IR → Binary
// ---------------------------------------------------------------------------

// PGIdxBuilder builds a PGIDX binary file from an IRModule.
type PGIdxBuilder struct {
	strPool    *BinStringPool
	classIndex []BinClassIndexEntry
	dataBlock  *bytes.Buffer

	// stats
	totalMethods  int
	totalLines    int
	totalMetadata int
}

// NewPGIdxBuilder creates a new builder.
func NewPGIdxBuilder() *PGIdxBuilder {
	return &PGIdxBuilder{
		strPool:   newBinStringPool(),
		dataBlock: new(bytes.Buffer),
	}
}

// Build populates the builder from an IRModule.
func (b *PGIdxBuilder) Build(mod *IRModule) {
	pool := mod.Pool

	// Phase 1: Intern all strings from IR into the binary string pool
	for _, s := range pool.Strings() {
		b.strPool.put(uint32(b.strPool.lookup[0]), s) // just pre-populate
	}
	// Actually, we intern on-demand below via str() helper.

	// Phase 2: Build class index + data block
	for _, ic := range mod.Classes {
		classEntry := BinClassIndexEntry{
			ObfName:     b.str(pool, ic.ObfName),
			OriName:     b.str(pool, ic.OriName),
			DataOff:     uint32(b.dataBlock.Len()),
			MethodCount: uint16(len(ic.Methods)),
			FieldCount:  uint16(len(ic.Fields)),
			MetaCount:   uint16(len(ic.Metadata)),
		}

		// Write method entries (placeholders, then fill offsets)
		methodBaseOff := b.dataBlock.Len()
		methodEntries := make([]BinMethodEntry, len(ic.Methods))

		// Reserve space for method entries
		for i := range ic.Methods {
			_ = i
			b.writeZeros(methodEntrySize)
		}

		// Write field entries
		for _, f := range ic.Fields {
			fe := BinFieldEntry{
				ObfName: b.str(pool, f.ObfName),
				OriName: b.str(pool, f.OriName),
				Type:    b.str(pool, f.Type),
			}
			_ = binary.Write(b.dataBlock, binary.LittleEndian, &fe)
		}

		// Write class-level metadata
		for _, m := range ic.Metadata {
			b.writeMetadata(pool, m)
			b.totalMetadata++
		}

		// Write per-method data (lines, frames, method metadata)
		for i, im := range ic.Methods {
			me := BinMethodEntry{
				ObfName:   b.str(pool, im.ObfName),
				OriName:   b.str(pool, im.OriName),
				Return:    b.str(pool, im.Return),
				Args:      b.str(pool, im.Args),
				LineCount: uint16(len(im.Lines)),
				MetaCount: uint16(len(im.Metadata)),
			}
			b.totalMethods++

			// Write line entries for this method
			me.LineOff = uint32(b.dataBlock.Len())
			lineEntries := make([]BinLineEntry, len(im.Lines))

			// Reserve space for line entries
			for range im.Lines {
				b.writeZeros(lineEntrySize)
			}

			// Write frames for each line
			for li, il := range im.Lines {
				lineEntries[li] = BinLineEntry{
					ObfStart:   uint32(il.ObfStart),
					ObfEnd:     uint32(il.ObfEnd),
					FrameOff:   uint32(b.dataBlock.Len()),
					FrameCount: uint16(len(il.Frames)),
				}
				b.totalLines++

				for _, fr := range il.Frames {
					fe := BinFrameEntry{
						OriClass:  b.str(pool, fr.OriClass),
						OriMethod: b.str(pool, fr.OriMethod),
						Return:    b.str(pool, fr.Return),
						Args:      b.str(pool, fr.Args),
						OriStart:  uint32(fr.OriStart),
						OriEnd:    uint32(fr.OriEnd),
					}
					_ = binary.Write(b.dataBlock, binary.LittleEndian, &fe)
				}
			}

			// Backfill line entries
			b.backfillLineEntries(me.LineOff, lineEntries)

			// Write method-level metadata
			me.MetaOff = uint32(b.dataBlock.Len())
			for _, m := range im.Metadata {
				b.writeMetadata(pool, m)
				b.totalMetadata++
			}

			methodEntries[i] = me
		}

		// Backfill method entries
		b.backfillMethodEntries(uint32(methodBaseOff), methodEntries)

		b.classIndex = append(b.classIndex, classEntry)
	}

	// Sort class index by obfuscated class name (for binary search)
	sort.Slice(b.classIndex, func(i, j int) bool {
		si := b.readStringAt(b.classIndex[i].ObfName)
		sj := b.readStringAt(b.classIndex[j].ObfName)
		return si < sj
	})
}

// str interns an IR string ID into the binary string pool and returns the binary offset.
func (b *PGIdxBuilder) str(pool *IRStringPool, irID uint32) uint32 {
	s := pool.Get(irID)
	return b.strPool.put(irID, s)
}

// writeZeros writes n zero bytes to the data block.
func (b *PGIdxBuilder) writeZeros(n int) {
	zeros := make([]byte, n)
	b.dataBlock.Write(zeros)
}

// writeMetadata writes a metadata entry + its condition/action lists.
func (b *PGIdxBuilder) writeMetadata(pool *IRStringPool, m *IRMetadata) {
	condOff := uint32(b.dataBlock.Len())
	b.writeIDList(m.Conditions, pool)

	actOff := uint32(b.dataBlock.Len())
	b.writeIDList(m.Actions, pool)

	me := BinMetadataEntry{
		ID:      b.str(pool, m.ID),
		CondOff: condOff,
		ActOff:  actOff,
	}
	binary.Write(b.dataBlock, binary.LittleEndian, &me)
}

// writeIDList writes a [count:uint16][pad:uint16][ids:uint32*count] block.
func (b *PGIdxBuilder) writeIDList(ids []uint32, pool *IRStringPool) {
	count := uint16(len(ids))
	_ = binary.Write(b.dataBlock, binary.LittleEndian, count)
	_ = binary.Write(b.dataBlock, binary.LittleEndian, uint16(0)) // padding
	for _, id := range ids {
		spOff := b.str(pool, id)
		_ = binary.Write(b.dataBlock, binary.LittleEndian, spOff)
	}
}

// backfillMethodEntries overwrites the reserved method entry slots.
func (b *PGIdxBuilder) backfillMethodEntries(baseOff uint32, entries []BinMethodEntry) {
	data := b.dataBlock.Bytes()
	for i, me := range entries {
		off := int(baseOff) + i*methodEntrySize
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, &me)
		copy(data[off:off+methodEntrySize], buf.Bytes())
	}
}

// backfillLineEntries overwrites the reserved line entry slots.
func (b *PGIdxBuilder) backfillLineEntries(baseOff uint32, entries []BinLineEntry) {
	data := b.dataBlock.Bytes()
	for i, le := range entries {
		off := int(baseOff) + i*lineEntrySize
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, &le)
		copy(data[off:off+lineEntrySize], buf.Bytes())
	}
}

// readStringAt reads a string from the binary string pool at the given offset.
func (b *PGIdxBuilder) readStringAt(off uint32) string {
	if int(off)+2 > len(b.strPool.data) {
		return ""
	}
	length := binary.LittleEndian.Uint16(b.strPool.data[off : off+2])
	if length == 0 {
		return ""
	}
	start := off + 2
	end := start + uint32(length)
	if int(end) > len(b.strPool.data) {
		return ""
	}
	return string(b.strPool.data[start:end])
}

// WriteTo serializes the complete PGIDX binary to the writer.
func (b *PGIdxBuilder) WriteTo(w io.Writer) error {
	buf := new(bytes.Buffer)

	// 1. Reserve header
	buf.Write(make([]byte, headerSize))

	// 2. Write ClassIndex
	classIdxOff := uint32(buf.Len())
	for i := range b.classIndex {
		if err := binary.Write(buf, binary.LittleEndian, &b.classIndex[i]); err != nil {
			return fmt.Errorf("writing class index entry %d: %w", i, err)
		}
	}

	// 3. Write DataBlock
	dataBlockOff := uint32(buf.Len())
	dataBlockLen := uint32(b.dataBlock.Len())
	buf.Write(b.dataBlock.Bytes())

	// 4. Write StringPool
	strPoolOff := uint32(buf.Len())
	strPoolLen := uint32(len(b.strPool.data))
	buf.Write(b.strPool.data)

	// 5. Backfill header
	header := BinHeader{
		Magic:         [4]byte{'P', 'G', 'I', 'X'},
		Version:       pgidxVersion,
		ClassCount:    uint32(len(b.classIndex)),
		ClassIdxOff:   classIdxOff,
		DataBlockOff:  dataBlockOff,
		DataBlockLen:  dataBlockLen,
		StringPoolOff: strPoolOff,
		StringPoolLen: strPoolLen,
		TotalMethods:  uint32(b.totalMethods),
		TotalLines:    uint32(b.totalLines),
		TotalMetadata: uint32(b.totalMetadata),
	}
	hdrBuf := new(bytes.Buffer)
	if err := binary.Write(hdrBuf, binary.LittleEndian, &header); err != nil {
		return fmt.Errorf("serializing header: %w", err)
	}
	final := buf.Bytes()
	copy(final[:headerSize], hdrBuf.Bytes())

	_, err := w.Write(final)
	return err
}

// Stats returns a human-readable summary.
func (b *PGIdxBuilder) Stats() string {
	return fmt.Sprintf("classes=%d methods=%d lines=%d metadata=%d strPoolSize=%d dataBlockSize=%d",
		len(b.classIndex), b.totalMethods, b.totalLines, b.totalMetadata,
		len(b.strPool.data), b.dataBlock.Len())
}
