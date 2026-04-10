package smap

// b64 is a lookup table for decoding base64 VLQ characters.
var b64 = func() [256]int8 {
	var m [256]int8
	for i := range m {
		m[i] = -1
	}
	chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for i, c := range chars {
		m[c] = int8(i)
	}
	return m
}()

// parseMappings 解析 SourceMap 中的 mappings 字段，返回 Segment 切片和 Line 切片。
// 它通过遍历 VLQ 编码的 mappings 字符串，根据分隔符 ';' 和 ',' 来区分行和段，
// 并使用 decodeVLQ 函数解码每个段的信息。
// 每个 Segment 包含生成列、源文件索引、源行和源列等信息，
// 而 Line 则记录了每行的起始和结束段索引。
func parseMappings(mappings string) ([]Segment, []Line) {
	data := []byte(mappings)
	segments := make([]Segment, 0, 1024)
	lines := make([]Line, 0, 1024)
	var (
		i         = 0 // 当前解析位置
		genCol    = 0 // 生成列，初始为0
		srcIdx    = 0 // 源文件索引，初始为0
		srcLine   = 0 // 源行，初始为0
		srcCol    = 0 // 源列，初始为0
		lineStart = 0 // 当前行的起始段索引
	)
	for i < len(data) {
		switch data[i] {
		case ';': // 行结束
			lines = append(lines, Line{
				Start: uint32(lineStart),
				End:   uint32(len(segments)),
			})
			i++
			genCol = 0
			lineStart = len(segments)
		case ',': // 段结束
			i++
		default:
			// 解码生成列
			genCol += decodeVLQ(data, &i)

			if i >= len(data) || data[i] == ';' || data[i] == ',' {
				segments = append(segments, Segment{
					GenCol: uint32(genCol),
				})
				continue
			}

			srcIdx += decodeVLQ(data, &i)
			srcLine += decodeVLQ(data, &i)
			srcCol += decodeVLQ(data, &i)

			if i < len(data) && data[i] != ';' && data[i] != ',' {
				_ = decodeVLQ(data, &i) // nameIdx, currently unused
			}

			segments = append(segments, Segment{
				GenCol:  uint32(genCol),
				SrcIdx:  uint32(srcIdx),
				SrcLine: uint32(srcLine),
				SrcCol:  uint32(srcCol),
			})
		}
	}
	lines = append(lines, Line{
		Start: uint32(lineStart),
		End:   uint32(len(segments)),
	})
	return segments, lines
}

// decodeVLQ 从给定的字节切片中解码一个 VLQ（Variable Length Quantity）值。
func decodeVLQ(data []byte, i *int) int {
	result := 0
	shift := 0

	for {
		b := int(b64[data[*i]])
		*i++

		val := b & 31
		result += val << shift
		shift += 5

		if b&32 == 0 {
			break
		}
	}

	// zigzag
	if result&1 == 1 {
		return -(result >> 1)
	}
	return result >> 1
}
