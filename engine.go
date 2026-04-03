package symx

import (
	"fmt"
)

// Engine 是 SymX 协议的基础引擎，负责加载和解析 SymX 文件的固定头部、可选头部和数据体。
type Engine struct {
	fh    FixedHead    // 固定头部信息，包含文件类型、版本、扩展头长度、数据体长度和 BuildID 等基本信息
	eh    ExtendedHead // 扩展头部信息，TLV 列表，包含文件类型特有的元数据
	bytes []byte       // 内存映射的文件字节切片，包含整个 SymX 文件内容，供解析使用
}

// Open 从指定文件加载 Symx 基础引擎。
func Open(filePath string) (*Engine, error) {

	// 只读模式 mmap 文件到内存
	mappedBytes, err := mapReadOnlyFile(filePath)
	if err != nil {
		return nil, err
	}

	// 固定头部的大小
	if len(mappedBytes) < FixedSize {
		unmapBytes(mappedBytes)
		return nil, fmt.Errorf("file too small to contain Symx Fixed Header: size=%d", len(mappedBytes))
	}

	e := &Engine{
		bytes: mappedBytes,
	}

	// 解析固定头部信息
	fh, err := ParseFixedHeader(mappedBytes[:FixedSize])
	if err != nil {
		unmapBytes(mappedBytes)
		return nil, err
	}
	e.fh = fh

	// 校验固定头部的 Magic 字段，确保文件格式正确
	err = fh.Validate()
	if err != nil {
		unmapBytes(mappedBytes)
		return nil, err
	}

	// 拓展头结束位置
	extHeadEnd, _, err := e.sectionBounds()
	if err != nil {
		unmapBytes(mappedBytes)
		return nil, err
	}

	// 解析拓展头部信息
	eh, err := ParseExtendedHeader(mappedBytes[FixedSize:extHeadEnd])
	if err != nil {
		unmapBytes(mappedBytes)
		return nil, err
	}

	e.eh = eh
	return e, nil
}

// Close 释放引擎占用的资源，主要是解除内存映射。
func (e *Engine) Close() error {
	unmapBytes(e.bytes)
	e.bytes = nil
	return nil
}

// ReadAt 从内存映射的字节切片中读取数据到给定的缓冲区 b 中，从指定的偏移 off 开始。返回实际读取的字节数和可能的错误。
func (e *Engine) ReadAt(b []byte, off int64) (int, error) {
	end := off + int64(len(b))
	if end > int64(len(e.bytes)) {
		return 0, fmt.Errorf("read out of bounds: offset=%d + len=%d exceeds file size %d", off, len(b), len(e.bytes))
	}
	copy(b, e.bytes[off:end])
	return len(b), nil
}

// sectionBounds 计算并返回头部扩展区间的结束位置和数据体长度，并验证文件布局的正确性。
// 返回值包括：
// - extHeadEnd: 扩展头部结束位置，即固定头部大小加上扩展头部长度
// - payloadLen: 数据体长度，从固定头部的 PayloadLen 字段获取
// - error: 如果文件布局不合法或验证失败，则返回一个错误
func (e *Engine) sectionBounds() (int, int, error) {
	if len(e.bytes) < FixedSize {
		return 0, 0, fmt.Errorf("file too small to contain SymxHeader")
	}

	if err := e.fh.Validate(); err != nil {
		return 0, 0, err
	}

	extLen := int(e.fh.ExtLen)
	payloadLen := int(e.fh.PayloadLen)
	extHeadEnd := FixedSize + extLen

	if extHeadEnd < FixedSize {
		return 0, 0, fmt.Errorf("invalid header length: fixed=%d + ext=%d overflow", FixedSize, extLen)
	}
	if extHeadEnd > len(e.bytes) {
		return 0, 0, fmt.Errorf("invalid header length: fixed=%d + ext=%d exceeds file size %d", FixedSize, extLen, len(e.bytes))
	}
	if extHeadEnd+payloadLen > len(e.bytes) {
		return 0, 0, fmt.Errorf("invalid payload length: headerEnd=%d + payloadLen=%d exceeds file size %d", extHeadEnd, payloadLen, len(e.bytes))
	}
	if extHeadEnd+payloadLen != len(e.bytes) {
		return 0, 0, fmt.Errorf("invalid file layout: headerEnd=%d + payloadLen=%d != file size %d", extHeadEnd, payloadLen, len(e.bytes))
	}

	return extHeadEnd, payloadLen, nil
}
