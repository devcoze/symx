package dwarf

// ---------------------------------------------------------------------------
// 二进制索引（高性能存储）
//
// 从 DWARF 调试信息中提取的地址→源码映射，存储为 mmap 友好的二进制 Payload。
// 本层仅生成 Payload 部分，文件级封装由 SymX FixedHead + ExtendedHead (TLV) 管理。
//
// Payload 布局（全部小端序，流式两趟写入）：
//
//   [FuncDetail blobs...]           — Pass 1: 每个函数的变长 detail blob，边提取边写入
//   [StringPool]                    — Pass 1 完成后写入，所有去重字符串，长度前缀编码
//   [FuncIndex × FuncCount]         — Pass 2: 按 StartPC 排序后追加写入（24B/条目）
//
// 各 section 的长度存储在 ExtendedHead 的 TLV 字段中（Metadata），
// section 位置由顺序布局隐式确定（与 ProGuard 保持一致）：
//   FuncDetail 起始于 Payload 偏移 0
//   StringPool 起始于 FuncDetailLen
//   FuncIndex  起始于 FuncDetailLen + StringPoolLen
//
// FuncIndex 是紧凑的索引数组，仅包含排序和查找所需的字段（StartPC, EndPC,
// DetailOff, DetailLen）。命中后通过 DetailOff 定位到 FuncDetail blob 读取完整信息。
//
// FuncDetail blob 是变长的，包含函数元数据 + 该函数的所有 InlineEntry 和
// LineTableEntry，保证同一函数的所有数据在磁盘/内存中连续存放，提高访问局部性。
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Metadata — 存储在 ExtendedHead 中的 TLV 条目。
//
// 字符串字段在写入 ExtHead 时一次性写入。
// 带 "Update" 标记的 uint32 字段初始写为 0，在 Payload 写入完成后
// 通过 AfterWrite 回填实际值。
//
// 与 ProGuard 保持一致：Metadata 只存长度和数量，不存偏移。
// section 位置由 Payload 顺序布局隐式确定。
// ---------------------------------------------------------------------------

// Metadata 是 DWARF SymX 文件的扩展头元数据。
type Metadata struct {
	// 文件级元数据
	Arch     string `json:"arch"     symx:"33"` // CPU 架构（arm64, x86_64 等）
	Producer string `json:"producer" symx:"34"` // DW_AT_producer（编译器信息）
	BuildId  string `json:"buildId"  symx:"35"` // 原始 Build ID

	// Payload 各 section 的布局信息（WritePayload 完成后回填）
	FuncCount     uint32 `symx:"40,Update"` // FuncIndex 条目数量
	FuncDetailLen uint32 `symx:"41,Update"` // FuncDetail section 总字节长度
	StringPoolLen uint32 `symx:"42,Update"` // StringPool 字节长度
}

// ---------------------------------------------------------------------------
// FuncIndex — 函数索引条目（24 字节，紧凑排列），按 StartPC 排序
//
// 仅包含二分查找所需的字段。命中后通过 DetailOff/DetailLen 定位到
// FuncDetail blob 读取完整的函数信息（名称、文件、行号、内联帧、行号表）。
// ---------------------------------------------------------------------------

const funcIndexSize = 24

// FuncIndex 表示一个函数在 Payload 中的索引条目。
type FuncIndex struct {
	StartPC   uint64 // 函数起始地址
	EndPC     uint64 // 函数结束地址（不包含）
	DetailOff uint32 // FuncDetail blob 在 Payload 中的字节偏移（FuncDetail 从 Payload 偏移 0 开始）
	DetailLen uint32 // FuncDetail blob 的字节长度
}

// ---------------------------------------------------------------------------
// FuncDetail blob — 每个函数的变长数据块
//
// 二进制格式（小端序）：
//
//   FuncName      uint32   // 字符串池偏移 → 函数名
//   File          uint32   // 字符串池偏移 → 源文件路径
//   Line          uint32   // 函数入口处的源码行号
//   InlineCount   uint16   // 内联帧数量
//   LineCount     uint16   // 行号表条目数量
//   [InlineEntry × InlineCount]   // 各 32 字节
//   [LineTableEntry × LineCount]  // 各 14 字节
//
// 固定头部 = 4 + 4 + 4 + 2 + 2 = 16 字节
// 总大小 = 16 + InlineCount*32 + LineCount*14
// ---------------------------------------------------------------------------

const funcDetailHeaderSize = 16

// ---------------------------------------------------------------------------
// InlineEntry — 内联帧条目（32 字节）
//
// 每个 InlineEntry 表示一个内联调用（DW_TAG_inlined_subroutine）。
// 同一函数的所有内联帧在其 FuncDetail blob 中连续存放。
// ---------------------------------------------------------------------------

const inlineEntrySize = 32

// InlineEntry 表示一个内联调用帧。
type InlineEntry struct {
	StartPC  uint64 // 内联范围起始地址
	EndPC    uint64 // 内联范围结束地址（不包含）
	FuncName uint32 // 字符串池偏移 → 被内联函数名
	CallFile uint32 // 字符串池偏移 → 调用点源文件
	CallLine uint32 // 调用点行号
	Depth    uint16 // 内联嵌套深度（1=直接内联，2+=嵌套）
	_pad     uint16 // 对齐填充
}

// ---------------------------------------------------------------------------
// LineTableEntry — 行号表条目（14 字节）
//
// 记录函数内精确的 PC→行号映射，由 DWARF .debug_line 提取。
// 同一函数的所有行号条目在其 FuncDetail blob 中连续存放，按 PCDelta 递增排序。
// ---------------------------------------------------------------------------

const lineTableEntrySize = 14

// LineTableEntry 表示函数内一个 PC 位置对应的行号信息。
type LineTableEntry struct {
	PCDelta uint32 // 相对于所属 FuncIndex.StartPC 的偏移
	File    uint32 // 字符串池偏移 → 源文件路径（0 = 与 FuncDetail.File 相同）
	Line    uint32 // 源码行号
	Col     uint16 // 源码列号（0 = 未知）
}

// ---------------------------------------------------------------------------
// 中间结构 — Parser 输出，Encoder 输入
//
// 这些结构由 parser.go 填充，encoder.go 消费。
// 纯内存结构，不涉及二进制编码。
// ---------------------------------------------------------------------------

// ParsedFunc 表示从 DWARF 中提取的一个函数。
type ParsedFunc struct {
	StartPC uint64
	EndPC   uint64
	Name    string
	File    string
	Line    int
	Inlines []ParsedInline
	Lines   []ParsedLine
}

// ParsedInline 表示从 DWARF 中提取的一个内联调用。
type ParsedInline struct {
	StartPC  uint64
	EndPC    uint64
	Name     string
	CallFile string
	CallLine int
	Depth    int
}

// ParsedLine 表示从 DWARF .debug_line 中提取的一个 PC→行号映射。
type ParsedLine struct {
	PC   uint64
	File string
	Line int
	Col  int
}
