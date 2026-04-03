package smap

const (
	lineSize      = 8  // Line 条目的固定大小：Start(4) + End(4)
	segmentSize   = 16 // Segment 条目的固定大小：GenCol(4) + SrcIdx(4) + SrcLine(4) + SrcCol(4)
	LineOffTag    = 33
	LineCntTag    = 34
	SegmentOffTag = 35
	SegmentCntTag = 36
)

// Metadata Js Source Map = > Symx 的头部扩展信息，包含行索引和段索引的偏移和数量，以及编译时间戳、SourceMap 版本、原始文件路径等信息。
type Metadata struct {
	LineOff     uint64 `json:"-"            symx:"33,update"` // 行索引在 Payload 中的偏移
	LineCnt     uint32 `json:"-"            symx:"34,update"` // 行索引条目数量
	SegmentOff  uint64 `json:"-"            symx:"35,update"` // 段索引在 Payload 中的偏移
	SegmentCnt  uint32 `json:"-"            symx:"36,update"` // 段索引条目数量
	CompileTime uint64 `json:"CompileTime"  symx:"37"`        // 编译时间戳
	Version     string `json:"Version"      symx:"38"`        // SourceMap 版本
	SourceRoot  string `json:"SourceRoot"   symx:"40"`        // 原始Js文件所在的目录，SourceMap 的 sourceRoot 字段
	OriFile     string `json:"OriFile"      symx:"41"`        // SourceMap 的 file 字段
	BuildId     string `json:"BuildId"      symx:"42"`        // 原始 BuildID, 由 NormalizeBuildID 规范化之前的值，供调试和日志输出使用
}

// Line 代表一个行索引条目，包含生成行的起始和结束位置（以 0 为基准的列号）。每个 Line 条目对应于一个生成行，指示该行在生成文件中的列范围。
type Line struct {
	Start, End uint32
}

// Segment represents a single mapping segment in the SMAP format.
type Segment struct {
	GenCol  uint32 // 生成列
	SrcIdx  uint32 // 源文件索引
	SrcLine uint32 // 源行
	SrcCol  uint32 // 源列
}
