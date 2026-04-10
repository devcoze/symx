package dwarf

import (
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ---------------------------------------------------------------------------
// DWARF 解析器 — 从 ELF / Mach-O / dSYM 中提取地址→源码映射
//
// 支持的输入格式：
//   - ELF 二进制文件（Linux / Android / HarmonyOS）
//   - Mach-O 二进制文件（iOS / macOS，thin 或 fat）
//   - dSYM 包（自动导航到 Contents/Resources/DWARF/*）
//
// 提取的信息：
//   - 函数名、源文件、入口行号、地址范围
//   - 内联帧（DW_TAG_inlined_subroutine）
//   - 精确行号表（.debug_line）
//
// 使用 Go 标准库 debug/dwarf（支持 DWARF 2-5）。
// ---------------------------------------------------------------------------

// OnFunc 是提取回调，每个函数提取完成后调用。
type OnFunc func(fn *ParsedFunc) error

// ---------------------------------------------------------------------------
// 输入格式检测与打开
// ---------------------------------------------------------------------------

// openResult 是 openDWARF 的返回值，封装解析结果和需要关闭的资源。
type openResult struct {
	data    *dwarf.Data
	arch    string
	buildId string
	closer  func() error
}

// openDWARF 打开输入文件并提取 DWARF 数据。
// 自动检测 ELF、Mach-O（thin/fat）和 dSYM 包格式。
func openDWARF(path string, opts *Options) (*openResult, error) {
	// 检查是否为 dSYM 包目录
	resolved, err := resolveDSYM(path)
	if err != nil {
		return nil, err
	}
	if resolved != "" {
		path = resolved
	}

	// 读取文件头以判断格式
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("dwarf: open %s: %w", path, err)
	}

	var magic [4]byte
	if _, err := f.Read(magic[:]); err != nil {
		f.Close()
		return nil, fmt.Errorf("dwarf: read magic %s: %w", path, err)
	}
	f.Close()

	// ELF: 0x7F 'E' 'L' 'F'
	if magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F' {
		return openELF(path)
	}

	// Fat Mach-O: 0xCAFEBABE (big-endian) or 0xBEBAFECA (little-endian)
	fatMagic := binary.BigEndian.Uint32(magic[:])
	if fatMagic == 0xCAFEBABE || fatMagic == 0xBEBAFECA {
		return openFatMachO(path, opts)
	}

	// Thin Mach-O
	if isMachOMagic(magic) {
		return openThinMachO(path)
	}

	return nil, fmt.Errorf("dwarf: unsupported file format: %s (magic: %x)", path, magic)
}

// isMachOMagic 检查 4 字节 magic 是否为 Mach-O 格式。
func isMachOMagic(magic [4]byte) bool {
	magics := [][4]byte{
		{0xFE, 0xED, 0xFA, 0xCE}, // MH_MAGIC
		{0xCE, 0xFA, 0xED, 0xFE}, // MH_CIGAM
		{0xFE, 0xED, 0xFA, 0xCF}, // MH_MAGIC_64
		{0xCF, 0xFA, 0xED, 0xFE}, // MH_CIGAM_64
	}
	for _, m := range magics {
		if magic == m {
			return true
		}
	}
	return false
}

// resolveDSYM 检测路径是否为 dSYM 包，如果是则返回内部 Mach-O 文件路径。
// 非 dSYM 路径返回空字符串。
func resolveDSYM(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", nil // 文件不存在，让后续逻辑处理
	}

	// 如果不是目录，不处理
	if !info.IsDir() {
		return "", nil
	}

	// 目录：检查是否为 dSYM 包结构
	if !strings.HasSuffix(path, ".dSYM") {
		return "", nil
	}

	dwarfDir := filepath.Join(path, "Contents", "Resources", "DWARF")
	entries, err := os.ReadDir(dwarfDir)
	if err != nil {
		return "", fmt.Errorf("dwarf: invalid dSYM bundle %s: %w", path, err)
	}
	if len(entries) == 0 {
		return "", fmt.Errorf("dwarf: dSYM bundle %s has no DWARF files", path)
	}

	// 使用第一个文件
	return filepath.Join(dwarfDir, entries[0].Name()), nil
}

// ---------------------------------------------------------------------------
// ELF
// ---------------------------------------------------------------------------

func openELF(path string) (*openResult, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("dwarf: open ELF %s: %w", path, err)
	}

	dw, err := f.DWARF()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("dwarf: read DWARF from ELF %s: %w", path, err)
	}

	arch := elfArch(f.Machine)
	bid := elfBuildId(f)

	return &openResult{
		data:    dw,
		arch:    arch,
		buildId: bid,
		closer:  f.Close,
	}, nil
}

// elfArch 将 ELF Machine 类型转换为架构名称。
func elfArch(m elf.Machine) string {
	switch m {
	case elf.EM_AARCH64:
		return "arm64"
	case elf.EM_ARM:
		return "arm"
	case elf.EM_386:
		return "x86"
	case elf.EM_X86_64:
		return "x86_64"
	case elf.EM_MIPS:
		return "mips"
	case elf.EM_RISCV:
		return "riscv"
	default:
		return fmt.Sprintf("unknown(%d)", m)
	}
}

// elfBuildId 从 ELF .note.gnu.build-id section 提取 Build ID。
func elfBuildId(f *elf.File) string {
	sec := f.Section(".note.gnu.build-id")
	if sec == nil {
		return ""
	}
	data, err := sec.Data()
	if err != nil || len(data) < 16 {
		return ""
	}

	// ELF Note 格式: [namesz:4][descsz:4][type:4][name...][desc...]
	var bo binary.ByteOrder
	if f.ByteOrder == binary.LittleEndian {
		bo = binary.LittleEndian
	} else {
		bo = binary.BigEndian
	}

	namesz := bo.Uint32(data[0:4])
	descsz := bo.Uint32(data[4:8])

	// name 对齐到 4 字节
	nameAligned := (namesz + 3) &^ 3
	descStart := 12 + nameAligned
	if int(descStart+descsz) > len(data) {
		return ""
	}
	desc := data[descStart : descStart+descsz]
	return fmt.Sprintf("%x", desc)
}

// ---------------------------------------------------------------------------
// Mach-O（thin）
// ---------------------------------------------------------------------------

func openThinMachO(path string) (*openResult, error) {
	f, err := macho.Open(path)
	if err != nil {
		return nil, fmt.Errorf("dwarf: open Mach-O %s: %w", path, err)
	}

	dw, err := f.DWARF()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("dwarf: read DWARF from Mach-O %s: %w", path, err)
	}

	arch := machoArch(f.Cpu)
	bid := machoUUID(f)

	return &openResult{
		data:    dw,
		arch:    arch,
		buildId: bid,
		closer:  f.Close,
	}, nil
}

// ---------------------------------------------------------------------------
// Mach-O（fat/universal）
// ---------------------------------------------------------------------------

func openFatMachO(path string, opts *Options) (*openResult, error) {
	fat, err := macho.OpenFat(path)
	if err != nil {
		return nil, fmt.Errorf("dwarf: open Fat Mach-O %s: %w", path, err)
	}

	targetArch := ""
	if opts != nil {
		targetArch = opts.Arch
	}

	var chosen *macho.FatArch
	for i := range fat.Arches {
		a := &fat.Arches[i]
		archName := machoArch(a.Cpu)
		if targetArch == "" {
			chosen = a
			break
		}
		if archName == targetArch {
			chosen = a
			break
		}
	}

	if chosen == nil {
		var available []string
		for _, a := range fat.Arches {
			available = append(available, machoArch(a.Cpu))
		}
		fat.Close()
		return nil, fmt.Errorf("dwarf: architecture %q not found in Fat Mach-O %s (available: %s)",
			targetArch, path, strings.Join(available, ", "))
	}

	dw, err := chosen.DWARF()
	if err != nil {
		fat.Close()
		return nil, fmt.Errorf("dwarf: read DWARF from Fat Mach-O %s (arch %s): %w",
			path, machoArch(chosen.Cpu), err)
	}

	arch := machoArch(chosen.Cpu)
	bid := machoUUID(chosen.File)

	return &openResult{
		data:    dw,
		arch:    arch,
		buildId: bid,
		closer:  fat.Close,
	}, nil
}

// machoArch 将 Mach-O Cpu 类型转换为架构名称。
func machoArch(cpu macho.Cpu) string {
	switch cpu {
	case macho.CpuArm64:
		return "arm64"
	case macho.CpuArm:
		return "arm"
	case macho.Cpu386:
		return "x86"
	case macho.CpuAmd64:
		return "x86_64"
	case macho.CpuPpc:
		return "ppc"
	case macho.CpuPpc64:
		return "ppc64"
	default:
		return fmt.Sprintf("unknown(%d)", cpu)
	}
}

// machoUUID 从 Mach-O 文件的 LC_UUID load command 提取 UUID。
func machoUUID(f *macho.File) string {
	const lcUUID = 0x1B
	for _, load := range f.Loads {
		raw := load.Raw()
		if len(raw) < 8 {
			continue
		}
		cmd := binary.LittleEndian.Uint32(raw[0:4])
		if cmd == lcUUID && len(raw) >= 24 {
			uuid := raw[8:24]
			return fmt.Sprintf("%x", uuid)
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// DWARF 数据提取 — extractor
//
// 遍历所有编译单元，提取函数、内联帧和行号表。
// ---------------------------------------------------------------------------

// extractor 从 *dwarf.Data 中提取函数信息。
type extractor struct {
	dw   *dwarf.Data
	onFn OnFunc
}

// Extract 执行提取，对每个函数调用 onFn 回调。
func (ex *extractor) Extract() error {
	reader := ex.dw.Reader()

	for {
		entry, err := reader.Next()
		if err != nil {
			return fmt.Errorf("dwarf: reading DIE: %w", err)
		}
		if entry == nil {
			break
		}

		if entry.Tag != dwarf.TagCompileUnit {
			continue
		}

		if err := ex.extractCU(reader, entry); err != nil {
			return err
		}
	}

	return nil
}

// cuContext 保存一个编译单元的上下文信息。
type cuContext struct {
	files       []*dwarf.LineFile // CU 的文件表（从 LineReader 获取）
	lineEntries []dwarf.LineEntry // CU 的所有行号条目
}

// filePath 通过文件索引获取文件路径。
// DWARF 4: 文件索引从 1 开始；DWARF 5: 从 0 开始。
// Go 的 debug/dwarf.LineReader 已统一为 0-based 存储在 Files 中。
func (cu *cuContext) filePath(idx int64) string {
	if idx < 0 || int(idx) >= len(cu.files) {
		return ""
	}
	f := cu.files[idx]
	if f == nil {
		return ""
	}
	return f.Name
}

// extractCU 处理一个编译单元。
func (ex *extractor) extractCU(reader *dwarf.Reader, cuEntry *dwarf.Entry) error {
	// 获取该 CU 的 LineReader
	lr, err := ex.dw.LineReader(cuEntry)
	if err != nil || lr == nil {
		reader.SkipChildren()
		return nil
	}

	cu := &cuContext{
		files: lr.Files(),
	}

	// 收集 CU 中的所有行号条目
	for {
		var le dwarf.LineEntry
		err := lr.Next(&le)
		if err != nil {
			break
		}
		if !le.EndSequence {
			cu.lineEntries = append(cu.lineEntries, le)
		}
	}

	// 遍历 CU 的子 DIE
	for {
		entry, err := reader.Next()
		if err != nil {
			return fmt.Errorf("dwarf: reading CU children: %w", err)
		}
		if entry == nil || entry.Tag == 0 {
			break
		}

		if entry.Tag == dwarf.TagSubprogram {
			fn, err := ex.extractSubprogram(reader, entry, cu)
			if err != nil {
				return err
			}
			if fn != nil {
				if err := ex.onFn(fn); err != nil {
					return err
				}
			}
			continue
		}

		reader.SkipChildren()
	}

	return nil
}

// extractSubprogram 从一个 DW_TAG_subprogram DIE 提取函数信息。
func (ex *extractor) extractSubprogram(reader *dwarf.Reader, entry *dwarf.Entry, cu *cuContext) (*ParsedFunc, error) {
	name := entryName(ex.dw, entry)
	if name == "" {
		reader.SkipChildren()
		return nil, nil
	}

	// 获取地址范围
	ranges, err := ex.dw.Ranges(entry)
	if err != nil || len(ranges) == 0 {
		reader.SkipChildren()
		return nil, nil
	}

	startPC := ranges[0][0]
	endPC := ranges[0][1]
	if startPC == 0 && endPC == 0 {
		reader.SkipChildren()
		return nil, nil
	}

	// 合并多段范围
	for _, r := range ranges[1:] {
		if r[0] < startPC {
			startPC = r[0]
		}
		if r[1] > endPC {
			endPC = r[1]
		}
	}

	// 获取声明文件和行号
	file := entryFileResolved(entry, cu)
	line := entryLine(entry)

	fn := &ParsedFunc{
		StartPC: startPC,
		EndPC:   endPC,
		Name:    name,
		File:    file,
		Line:    line,
	}

	// 如果 DW_AT_decl_file 无法解析，尝试从行号表获取入口点信息
	if fn.File == "" || fn.Line == 0 {
		if ef, el := lookupEntryLine(cu.lineEntries, startPC); ef != "" {
			if fn.File == "" {
				fn.File = ef
			}
			if fn.Line == 0 {
				fn.Line = el
			}
		}
	}

	// 提取行号表
	fn.Lines = extractLinesForFunc(cu.lineEntries, startPC, endPC)

	// 提取内联帧
	if entry.Children {
		inlines, err := ex.extractInlines(reader, cu, 1)
		if err != nil {
			return nil, err
		}
		fn.Inlines = inlines
	}

	return fn, nil
}

// extractInlines 递归提取内联帧。
func (ex *extractor) extractInlines(reader *dwarf.Reader, cu *cuContext, depth int) ([]ParsedInline, error) {
	var inlines []ParsedInline

	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, fmt.Errorf("dwarf: reading inline children: %w", err)
		}
		if entry == nil || entry.Tag == 0 {
			break
		}

		if entry.Tag == dwarf.TagInlinedSubroutine {
			inline, nested, err := ex.extractOneInline(reader, entry, cu, depth)
			if err != nil {
				return nil, err
			}
			if inline != nil {
				inlines = append(inlines, *inline)
			}
			inlines = append(inlines, nested...)
			continue
		}

		// 其他 tag 也可能包含嵌套 inlined_subroutine（如 lexical_block）
		if entry.Children {
			nested, err := ex.extractInlines(reader, cu, depth)
			if err != nil {
				return nil, err
			}
			inlines = append(inlines, nested...)
		}
	}

	return inlines, nil
}

// extractOneInline 从一个 DW_TAG_inlined_subroutine DIE 提取内联帧。
// 返回当前内联帧和其子层级的展平内联帧列表。
func (ex *extractor) extractOneInline(reader *dwarf.Reader, entry *dwarf.Entry, cu *cuContext, depth int) (*ParsedInline, []ParsedInline, error) {
	name := entryName(ex.dw, entry)

	ranges, err := ex.dw.Ranges(entry)
	if err != nil || len(ranges) == 0 {
		reader.SkipChildren()
		return nil, nil, nil
	}

	startPC := ranges[0][0]
	endPC := ranges[0][1]
	for _, r := range ranges[1:] {
		if r[0] < startPC {
			startPC = r[0]
		}
		if r[1] > endPC {
			endPC = r[1]
		}
	}

	if startPC == 0 && endPC == 0 {
		reader.SkipChildren()
		return nil, nil, nil
	}

	callFile := entryCallFileResolved(entry, cu)
	callLine := entryCallLine(entry)

	inline := &ParsedInline{
		StartPC:  startPC,
		EndPC:    endPC,
		Name:     name,
		CallFile: callFile,
		CallLine: callLine,
		Depth:    depth,
	}

	var nested []ParsedInline
	if entry.Children {
		nested, err = ex.extractInlines(reader, cu, depth+1)
		if err != nil {
			return nil, nil, err
		}
	}

	return inline, nested, nil
}

// ---------------------------------------------------------------------------
// DIE 属性提取辅助函数
// ---------------------------------------------------------------------------

// entryName 获取 DIE 的名称，支持 DW_AT_abstract_origin/DW_AT_specification 解引用。
func entryName(dw *dwarf.Data, entry *dwarf.Entry) string {
	if name, ok := entry.Val(dwarf.AttrName).(string); ok && name != "" {
		return name
	}

	// DW_AT_abstract_origin 解引用
	if ref, ok := entry.Val(dwarf.AttrAbstractOrigin).(dwarf.Offset); ok {
		if name := resolveNameAt(dw, ref); name != "" {
			return name
		}
	}

	// DW_AT_specification 解引用
	if ref, ok := entry.Val(dwarf.AttrSpecification).(dwarf.Offset); ok {
		if name := resolveNameAt(dw, ref); name != "" {
			return name
		}
	}

	// linkage name 作为后备
	if name, ok := entry.Val(dwarf.AttrLinkageName).(string); ok && name != "" {
		return name
	}

	return ""
}

// resolveNameAt 在指定偏移处读取 DIE 并提取名称，支持链式解引用（最多 3 层防止死循环）。
func resolveNameAt(dw *dwarf.Data, off dwarf.Offset) string {
	for i := 0; i < 3; i++ {
		r := dw.Reader()
		r.Seek(off)
		e, err := r.Next()
		if err != nil || e == nil {
			return ""
		}

		if name, ok := e.Val(dwarf.AttrName).(string); ok && name != "" {
			return name
		}
		if name, ok := e.Val(dwarf.AttrLinkageName).(string); ok && name != "" {
			return name
		}

		// 继续链式解引用
		if ref, ok := e.Val(dwarf.AttrAbstractOrigin).(dwarf.Offset); ok {
			off = ref
			continue
		}
		if ref, ok := e.Val(dwarf.AttrSpecification).(dwarf.Offset); ok {
			off = ref
			continue
		}
		break
	}
	return ""
}

// entryFileResolved 获取 DIE 的声明文件路径，通过 CU 文件表解析索引。
func entryFileResolved(entry *dwarf.Entry, cu *cuContext) string {
	if idx, ok := entry.Val(dwarf.AttrDeclFile).(int64); ok {
		return cu.filePath(idx)
	}
	return ""
}

// entryLine 获取 DIE 的声明行号。
func entryLine(entry *dwarf.Entry) int {
	if line, ok := entry.Val(dwarf.AttrDeclLine).(int64); ok {
		return int(line)
	}
	return 0
}

// entryCallFileResolved 获取内联调用点的文件路径，通过 CU 文件表解析索引。
func entryCallFileResolved(entry *dwarf.Entry, cu *cuContext) string {
	if idx, ok := entry.Val(dwarf.AttrCallFile).(int64); ok {
		return cu.filePath(idx)
	}
	return ""
}

// entryCallLine 获取内联调用点的行号。
func entryCallLine(entry *dwarf.Entry) int {
	if line, ok := entry.Val(dwarf.AttrCallLine).(int64); ok {
		return int(line)
	}
	return 0
}

// ---------------------------------------------------------------------------
// 行号表提取
// ---------------------------------------------------------------------------

// extractLinesForFunc 从 CU 的行号条目中筛选属于指定函数范围的条目。
func extractLinesForFunc(lineEntries []dwarf.LineEntry, startPC, endPC uint64) []ParsedLine {
	var lines []ParsedLine
	for i := range lineEntries {
		le := &lineEntries[i]
		if le.Address >= startPC && le.Address < endPC {
			lines = append(lines, ParsedLine{
				PC:   le.Address,
				File: le.File.Name,
				Line: le.Line,
				Col:  le.Column,
			})
		}
	}
	return lines
}

// lookupEntryLine 在行号条目中查找指定 PC 地址的文件和行号。
// 返回最接近且不超过 pc 的条目的文件和行号。
func lookupEntryLine(lineEntries []dwarf.LineEntry, pc uint64) (string, int) {
	var bestFile string
	var bestLine int
	for i := range lineEntries {
		le := &lineEntries[i]
		if le.Address <= pc {
			bestFile = le.File.Name
			bestLine = le.Line
		}
		if le.Address > pc {
			break
		}
	}
	return bestFile, bestLine
}
