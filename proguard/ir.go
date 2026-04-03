package proguard

import (
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// Layer 2: IR (Semantic Compression Layer)
//
// Converts AST (string-based) into ID-based structures via StringPool.
// All strings are replaced by uint32 IDs. No raw strings remain in IR.
// No file offsets — that belongs to the Binary layer.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// StringPool — bidirectional string ↔ uint32 ID mapping
// ---------------------------------------------------------------------------

// IRStringPool assigns a unique uint32 ID to each distinct string.
// ID 0 is reserved for the empty string.
type IRStringPool struct {
	dict map[string]uint32
	list []string
}

// NewIRStringPool creates a new string pool with ID 0 = "".
func NewIRStringPool() *IRStringPool {
	pool := &IRStringPool{
		dict: make(map[string]uint32),
	}
	pool.Put("") // reserve 0 for empty string
	return pool
}

// Put inserts s into the pool and returns its unique ID.
func (p *IRStringPool) Put(s string) uint32 {
	if id, ok := p.dict[s]; ok {
		return id
	}
	id := uint32(len(p.list))
	p.dict[s] = id
	p.list = append(p.list, s)
	return id
}

// Get returns the string for the given ID.
func (p *IRStringPool) Get(id uint32) string {
	if int(id) >= len(p.list) {
		return ""
	}
	return p.list[id]
}

// Len returns the number of unique strings.
func (p *IRStringPool) Len() int {
	return len(p.list)
}

// Strings returns all strings in ID order.
func (p *IRStringPool) Strings() []string {
	return p.list
}

// ---------------------------------------------------------------------------
// IR structures — all fields are uint32 IDs (from StringPool) or int values
// ---------------------------------------------------------------------------

// IRClass is the IR representation of a class.
type IRClass struct {
	OriName  uint32        // string pool ID
	ObfName  uint32        // string pool ID
	Methods  []*IRMethod   // methods belonging to this class
	Fields   []*IRField    // fields belonging to this class
	Metadata []*IRMetadata // class-level metadata
}

// IRField is the IR representation of a field.
type IRField struct {
	Type    uint32 // string pool ID
	OriName uint32 // string pool ID
	ObfName uint32 // string pool ID
}

// IRMethod is the IR representation of a method.
type IRMethod struct {
	ObfName  uint32        // string pool ID
	OriName  uint32        // string pool ID
	Return   uint32        // string pool ID
	Args     uint32        // string pool ID (joined args string)
	Lines    []*IRLine     // line mappings (one per obf range, may contain inline frames)
	Metadata []*IRMetadata // method-level metadata
}

// IRLine represents a single obfuscated line range mapping to one or more
// original frames (inline expansion).
type IRLine struct {
	ObfStart int        // obfuscated line start
	ObfEnd   int        // obfuscated line end
	Frames   []*IRFrame // original frames (multiple = inline)
}

// IRFrame is a single original method frame within an IRLine.
type IRFrame struct {
	OriClass  uint32 // string pool ID
	OriMethod uint32 // string pool ID
	Return    uint32 // string pool ID
	Args      uint32 // string pool ID (joined args string)
	OriStart  int    // original line start
	OriEnd    int    // original line end
}

// IRMetadata represents a parsed R8 metadata entry.
type IRMetadata struct {
	ID         uint32   // string pool ID of the metadata identifier
	Conditions []uint32 // string pool IDs of condition strings
	Actions    []uint32 // string pool IDs of action strings
}

// ---------------------------------------------------------------------------
// IRModule — the top-level IR container
// ---------------------------------------------------------------------------

// IRModule is the complete IR representation of a mapping file.
type IRModule struct {
	pool    *IRStringPool
	Classes []*IRClass
}

func (ir *IRModule) OnClass(ac *ASTClass) error {

	ic := &IRClass{
		OriName: ir.pool.Put(ac.OriName),
		ObfName: ir.pool.Put(ac.ObfName),
	}

	// Convert fields
	for _, af := range ac.Fields {
		ic.Fields = append(ic.Fields, &IRField{
			Type:    ir.pool.Put(af.Type),
			OriName: ir.pool.Put(af.OriName),
			ObfName: ir.pool.Put(af.ObfName),
		})
	}

	// Convert methods
	for _, am := range ac.Methods {
		im := &IRMethod{
			ObfName: ir.pool.Put(am.ObfName),
			OriName: ir.pool.Put(am.OriName),
			Return:  ir.pool.Put(am.Return),
			Args:    ir.pool.Put(joinArgs(am.Args)),
		}

		// Convert line groups → IRLine
		for _, lg := range am.LineGroups {
			il := &IRLine{
				ObfStart: lg.ObfStart,
				ObfEnd:   lg.ObfEnd,
			}
			for _, f := range lg.Frames {
				il.Frames = append(il.Frames, &IRFrame{
					OriClass:  ir.pool.Put(f.OriClass),
					OriMethod: ir.pool.Put(f.OriMethod),
					Return:    ir.pool.Put(f.Return),
					Args:      ir.pool.Put(joinArgs(f.Args)),
					OriStart:  f.OriStart,
					OriEnd:    f.OriEnd,
				})
			}
			im.Lines = append(im.Lines, il)
		}

		// Convert method metadata
		for _, m := range am.Metadata {
			im.Metadata = append(im.Metadata, convertMetadata(ir.pool, m))
		}

		ic.Methods = append(ic.Methods, im)
	}

	// Convert class metadata
	for _, m := range ac.Metadata {
		ic.Metadata = append(ic.Metadata, convertMetadata(ir.pool, m))
	}

	ir.Classes = append(ir.Classes, ic)

	return nil
}

// ---------------------------------------------------------------------------
// AST → IR conversion
// ---------------------------------------------------------------------------

// BuildIR converts a list of ASTClass nodes into an IRModule.
// All strings are interned into a shared StringPool.
func BuildIR(classes []*ASTClass) *IRModule {
	pool := NewIRStringPool()
	mod := &IRModule{Pool: pool}

	for _, ac := range classes {
		ic := &IRClass{
			OriName: pool.Put(ac.OriName),
			ObfName: pool.Put(ac.ObfName),
		}

		// Convert fields
		for _, af := range ac.Fields {
			ic.Fields = append(ic.Fields, &IRField{
				Type:    pool.Put(af.Type),
				OriName: pool.Put(af.OriName),
				ObfName: pool.Put(af.ObfName),
			})
		}

		// Convert methods
		for _, am := range ac.Methods {
			im := &IRMethod{
				ObfName: pool.Put(am.ObfName),
				OriName: pool.Put(am.OriName),
				Return:  pool.Put(am.Return),
				Args:    pool.Put(joinArgs(am.Args)),
			}

			// Convert line groups → IRLine
			for _, lg := range am.LineGroups {
				il := &IRLine{
					ObfStart: lg.ObfStart,
					ObfEnd:   lg.ObfEnd,
				}
				for _, f := range lg.Frames {
					il.Frames = append(il.Frames, &IRFrame{
						OriClass:  pool.Put(f.OriClass),
						OriMethod: pool.Put(f.OriMethod),
						Return:    pool.Put(f.Return),
						Args:      pool.Put(joinArgs(f.Args)),
						OriStart:  f.OriStart,
						OriEnd:    f.OriEnd,
					})
				}
				im.Lines = append(im.Lines, il)
			}

			// Convert method metadata
			for _, m := range am.Metadata {
				im.Metadata = append(im.Metadata, convertMetadata(pool, m))
			}

			ic.Methods = append(ic.Methods, im)
		}

		// Convert class metadata
		for _, m := range ac.Metadata {
			ic.Metadata = append(ic.Metadata, convertMetadata(pool, m))
		}

		mod.Classes = append(mod.Classes, ic)
	}

	// Sort classes by ObfName for deterministic output and binary search
	sort.Slice(mod.Classes, func(i, j int) bool {
		return pool.Get(mod.Classes[i].ObfName) < pool.Get(mod.Classes[j].ObfName)
	})

	return mod
}

// convertMetadata converts an ASTMetadata to an IRMetadata.
func convertMetadata(pool *IRStringPool, m *ASTMetadata) *IRMetadata {
	im := &IRMetadata{
		ID: pool.Put(m.ID),
	}
	for _, c := range m.Conditions {
		im.Conditions = append(im.Conditions, pool.Put(c))
	}
	for _, a := range m.Actions {
		im.Actions = append(im.Actions, pool.Put(a))
	}
	return im
}

// joinArgs joins argument types with ',' for pool interning.
func joinArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return strings.Join(args, ",")
}
