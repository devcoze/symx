package dwarf

// Options DWARFOptions 包含 DWARF 编码器的特有选项，独立于通用 WriteOptions。
type Options struct {
	// Arch 指定 Fat (Universal) Mach-O 二进制文件中的目标架构（如 "arm64"、"x86_64"）。
	// 为空时选择第一个架构。对 ELF 和 thin Mach-O 无效。
	Arch string
}
