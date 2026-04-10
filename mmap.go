package symx

import (
	"fmt"
	"os"
	"syscall"
)

// mapReadOnlyFile mmap 文件到内存，返回一个字节切片和可能的错误。
func mapReadOnlyFile(filePath string) ([]byte, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}

	size := stat.Size()
	if size == 0 {
		return nil, fmt.Errorf("symx: cannot mmap zero-length file: %s", filePath)
	}

	return syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
}

// unmapBytes 解除内存映射，接受一个字节切片作为参数，如果切片长度为零则直接返回 nil，否则调用 syscall.Munmap 解除映射并返回可能的错误。
func unmapBytes(mappedBytes []byte) error {
	if len(mappedBytes) == 0 {
		return nil
	}
	return syscall.Munmap(mappedBytes)
}
