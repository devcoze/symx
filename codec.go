package symx

type EncoderFactory func(*WriteOptions) Encoder

// Encoder 是写入 SymX 文件的核心接口。
// 接口分为两步：
//  1. 预计算尺寸（ExtHeadSize / PayloadSize）：用于填写固定头，无需分配数据。
//  2. 流式写入（WriteExtHead / WritePayload）：直接向 io.Writer 输出，无需整体缓冲。
type Encoder interface {
	// FileType 返回文件类型标识（SourceMap / ProGuard / Dwarf 等常量）。
	FileType() uint8

	// Identify 返回一个字符串标识，用于调试和日志输出，帮助区分不同类型的 Encoder 实现。可以包含输入文件路径、内容哈希等信息，以便追踪和诊断问题。
	Identify() string

	// ExtHeadSize 返回 TLV 扩展头的字节总长，用于填写固定头中的 ExtLen 字段。
	// 注意：此时不需要实际生成扩展头数据，只需计算总长度即可，避免不必要的内存分配。
	ExtHeadSize() uint16

	// PayloadSize 返回有效负载的字节总长，用于填写固定头中的 PayloadLen 字段。
	// 注意：此时不需要实际生成有效负载数据，只需计算总长度即可，避免不必要的内存分配。
	PayloadSize() uint64

	// WriteExtHead 将文件类型特有的元数据以 TLV 格式流式写入 w。
	// 写入的字节数必须等于 ExtHeadSize() 的返回值。
	WriteExtHead(cw *CountingWriter) error

	// WritePayload 将文件类型特有的索引数据流式写入 w。
	// 写入的字节数必须等于 PayloadSize() 的返回值。
	WritePayload(cw *CountingWriter) error
}
