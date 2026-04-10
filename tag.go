package symx

import (
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
)

// tag: 结构体字段的 symx tag 定义和解析逻辑。
// 用户在定义 struct 时，可以通过 `symx` tag 指定字段对应的 TLV type 编号，以及可选的 Update 标志（表示该字段在增量更新中也会被写入）。
// TLV type 编号必须是 uint8 范围内的整数，且建议使用 33-255 以避免与保留区冲突。
// 支持的格式：
// 1) symx:"33"
// 2) symx:"33,Update"
// 3) symx:"t=33"
// 4) symx:"t=33,Update"

const (
	TagK        = "symx"   // struct 字段的 tag 键，格式为 `symx:"t=N"`，N 为 uint8 类型的 TLV type 编号
	ReservedTyp = 33       // 0-32 是保留区，用户自定义字段应使用 33-255
	UpdateFlag  = "update" // Update 标志，表示该字段支持增量更新（Patch），在 WriteTLVsTo 时会记录 PatchBinding 信息，供后续增量更新时使用
	TypPrefix   = "t="     // 兼容性前缀，支持直接写 N 或 t=N 两种格式，推荐使用 t=N 以提高可读性
)

// patchBindingRecorder 允许 WriteTLVsTo 在写入 TLV 时记录 PatchBinding 信息，以便后续增量更新时使用。
type patchBindingRecorder interface {
	recordPatchBinding(binding PatchBinding)
}

// writeOffsetTracker 允许 WriteTLVsTo 在写入 TLV 时获取当前写入偏移，以便正确计算 PatchBinding 中的 Offset 字段。
type writeOffsetTracker interface {
	Offset() int64
}

// SymxTagField 包含一个带 symx tag 的 struct 字段的相关信息，
// 包括 TLV type 编号、Update 标志、字段反射信息、字段值和字段值的字节尺寸（不含 TLV 3 字节头）。
type symxTagField struct {
	typ       uint8
	update    bool
	field     reflect.StructField
	value     reflect.Value
	valueSize int
}

// parseTag 支持：
// 1) symx:"33"
// 2) symx:"33,Update"
// 3) symx:"t=33"
// 4) symx:"t=33,Update"
func parseTag(tag string) (typ uint8, update bool, ok bool) {
	if tag == "-" || strings.TrimSpace(tag) == "" {
		return 0, false, false
	}

	parts := strings.Split(tag, ",")
	for i, p := range parts {
		p := strings.TrimSpace(p)
		lp := strings.ToLower(p)
		// update 标志
		if lp == UpdateFlag {
			update = true
			continue
		}
		// 兼容 t=N
		if strings.HasPrefix(lp, TypPrefix) {
			n, err := strconv.ParseUint(strings.TrimSpace(lp[2:]), 10, 8)
			if err != nil {
				return 0, false, false
			}
			typ = uint8(n)
			continue
		}
		if i == 0 {
			// 兼容直接写 N
			n, err := strconv.ParseUint(p, 10, 8)
			if err == nil {
				typ = uint8(n)
				continue
			}
		}
	}
	// TLV type 编号必须是 uint8 范围内的整数，且建议使用 33-255 以避免与保留区冲突
	if typ < ReservedTyp {
		return 0, false, false
	}
	return typ, update, true
}

// fieldValueSize 计算字段序列化后的字节数（不含 TLV 3 字节头）。
func fieldValueSize(v reflect.Value) (int, error) {
	switch v.Kind() {
	case reflect.String:
		return len(v.String()), nil
	case reflect.Uint8:
		return 1, nil
	case reflect.Uint16:
		return 2, nil
	case reflect.Uint32:
		return 4, nil
	case reflect.Uint64:
		return 8, nil
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return v.Len(), nil
		}
	default:
		// do nothing
	}
	return 0, fmt.Errorf("symx: unsupported field type %s", v.Kind())
}

// isFixedWidthField 判断字段是否是固定宽度的 uint8/uint16/uint32/uint64，适用于增量更新（Patch）要求固定宽度的场景。
func isFixedWidthField(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	default:
		return false
	}
}

// writeFieldValue 将字段值流式写入 w。
func writeFieldValue(w io.Writer, v reflect.Value) error {
	switch v.Kind() {
	case reflect.String:
		_, err := io.WriteString(w, v.String())
		return err
	case reflect.Uint8:
		_, err := w.Write([]byte{byte(v.Uint())})
		return err
	case reflect.Uint16:
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], uint16(v.Uint()))
		_, err := w.Write(b[:])
		return err
	case reflect.Uint32:
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(v.Uint()))
		_, err := w.Write(b[:])
		return err
	case reflect.Uint64:
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], v.Uint())
		_, err := w.Write(b[:])
		return err
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			_, err := w.Write(v.Bytes())
			return err
		}
	default:
		// do nothing
	}
	return fmt.Errorf("symx: unsupported field type %s", v.Kind())
}

func fixedWidthFieldBytes(v reflect.Value, size int) ([]byte, error) {
	buf, err := marshalFieldBytes(v)
	if err != nil {
		return nil, err
	}
	if len(buf) != size {
		return nil, fmt.Errorf("symx: field width mismatch: got %d bytes, want %d", len(buf), size)
	}
	return buf, nil
}

// setFieldValue 将 TLV value 字节反序列化并写入字段 v。
func setFieldValue(v reflect.Value, data []byte) error {
	switch v.Kind() {
	case reflect.String:
		v.SetString(string(data))
	case reflect.Uint8:
		if len(data) < 1 {
			return fmt.Errorf("symx: data too short for uint8")
		}
		v.SetUint(uint64(data[0]))
	case reflect.Uint16:
		if len(data) < 2 {
			return fmt.Errorf("symx: data too short for uint16")
		}
		v.SetUint(uint64(binary.LittleEndian.Uint16(data)))
	case reflect.Uint32:
		if len(data) < 4 {
			return fmt.Errorf("symx: data too short for uint32")
		}
		v.SetUint(uint64(binary.LittleEndian.Uint32(data)))
	case reflect.Uint64:
		if len(data) < 8 {
			return fmt.Errorf("symx: data too short for uint64")
		}
		v.SetUint(binary.LittleEndian.Uint64(data))
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			cp := make([]byte, len(data))
			copy(cp, data)
			v.SetBytes(cp)
		}
	default:
		return fmt.Errorf("symx: unsupported field type %s", v.Kind())
	}
	return nil
}

// derefStruct 解引用指针并返回 struct 的 reflect.Value，失败则返回错误。
func derefStruct(v any) (reflect.Value, error) {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return reflect.Value{}, fmt.Errorf("symx: expected struct, got invalid value")
	}
	// 支持多层指针，但最终必须是 struct
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return reflect.Value{}, fmt.Errorf("symx: expected struct, got nil pointer")
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return reflect.Value{}, fmt.Errorf("symx: expected struct, got %s", rv.Kind())
	}
	return rv, nil
}

// symxTagFields 扫描 v 中所有带 symx tag 的字段，
// 解析 tag 获取 TLV type 编号和 Update 标志，并返回一个包含字段信息的切片。
func symxTagFields(v any) ([]symxTagField, error) {
	rv, err := derefStruct(v)
	if err != nil {
		return nil, err
	}
	rt := rv.Type()
	fields := make([]symxTagField, 0, rt.NumField())
	seen := make(map[uint8]string, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		tag, ok := field.Tag.Lookup(TagK)
		if !ok {
			continue
		}
		typ, update, ok := parseTag(tag)
		if !ok {
			continue
		}
		if prev, exists := seen[typ]; exists {
			return nil, fmt.Errorf("symx: duplicate TLV type %d on fields %s and %s", typ, prev, field.Name)
		}
		fv := rv.Field(i)
		sz, err := fieldValueSize(fv)
		if err != nil {
			return nil, fmt.Errorf("symx: field %s: %w", field.Name, err)
		}
		if update && !isFixedWidthField(fv) {
			return nil, fmt.Errorf("symx: field %s: Update requires fixed-width uint8/uint16/uint32/uint64", field.Name)
		}
		fields = append(fields, symxTagField{
			typ:       typ,
			update:    update,
			field:     field,
			value:     fv,
			valueSize: sz,
		})
		seen[typ] = field.Name
	}
	return fields, nil
}

// TLVsSize 预计算 v 中所有带 symx tag 字段序列化为 TLV 后的总字节数。
// 不分配数据缓冲，仅遍历计算，适合用于流式写入前填写固定头。
func TLVsSize(v any) (int, error) {
	fields, err := symxTagFields(v)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, field := range fields {
		total += TLVSize(field.valueSize)
	}
	return total, nil
}

// MustTLVsSize 与 TLVsSize 等价，但在遇到非法 tag/字段配置时直接 panic。
// 适合在 Encoder.ExtHeadSize 这类无法返回 error 的场景中使用。
func MustTLVsSize(v any) int {
	total, err := TLVsSize(v)
	if err != nil {
		panic(err)
	}
	return total
}

// MarshalTLVsSize 兼容旧接口；遇到非法 tag/字段配置时返回 0。
// 新代码推荐优先使用 TLVsSize 或 MustTLVsSize，以免把非法配置误判为空扩展头。
func MarshalTLVsSize(v any) int {
	total, err := TLVsSize(v)
	if err != nil {
		return 0
	}
	return total
}

// WriteTLVsTo 将 v 中所有带 symx tag 的字段流式序列化为 TLV 并写入 w。
// 字段按结构体声明顺序写入，写入总长等于 MarshalTLVsSize(v)。
func WriteTLVsTo(w io.Writer, v any) error {
	fields, err := symxTagFields(v)
	if err != nil {
		return err
	}
	recorder, _ := w.(patchBindingRecorder)
	offsets, _ := w.(writeOffsetTracker)
	for _, field := range fields {
		var binding PatchBinding
		if field.update && recorder != nil && offsets != nil {
			binding = PatchBinding{
				Type:       field.typ,
				Offset:     offsets.Offset() + 3,
				Size:       field.valueSize,
				FieldIndex: append([]int(nil), field.field.Index...),
				FieldName:  field.field.Name,
			}
		}
		if err := WriteTLVTo(w, field.typ, field.valueSize, func(w io.Writer) error {
			return writeFieldValue(w, field.value)
		}); err != nil {
			return fmt.Errorf("symx: field %s: %w", field.field.Name, err)
		}
		if field.update && recorder != nil && offsets != nil {
			recorder.recordPatchBinding(binding)
		}
	}
	return nil
}

// MarshalTLVs 将 v 中所有带 symx tag 的字段序列化为 TLV 字节切片。
// 适合字段少、尺寸小的场景；大数据量请优先使用 WriteTLVsTo。
func MarshalTLVs(v any) ([]byte, error) {
	fields, err := symxTagFields(v)
	if err != nil {
		return nil, err
	}
	// 直接从已解析的 fields 计算总大小，避免重复反射
	total := 0
	for _, field := range fields {
		total += TLVSize(field.valueSize)
	}
	buf := make([]byte, 0, total)
	for _, field := range fields {
		valBytes, err := marshalFieldBytes(field.value)
		if err != nil {
			return nil, fmt.Errorf("symx: field %s: %w", field.field.Name, err)
		}
		tlv := NewTLV(field.typ, valBytes)
		entry := make([]byte, 3+len(valBytes))
		WriteTLV(entry, &tlv)
		buf = append(buf, entry...)
	}
	return buf, nil
}

// marshalFieldBytes 将字段值序列化为字节切片（MarshalTLVs 内部使用）。
func marshalFieldBytes(v reflect.Value) ([]byte, error) {
	switch v.Kind() {
	case reflect.String:
		return []byte(v.String()), nil
	case reflect.Uint8:
		return []byte{byte(v.Uint())}, nil
	case reflect.Uint16:
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(v.Uint()))
		return b, nil
	case reflect.Uint32:
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(v.Uint()))
		return b, nil
	case reflect.Uint64:
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, v.Uint())
		return b, nil
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return v.Bytes(), nil
		}
	default:
		return nil, fmt.Errorf("symx: unsupported type %v", v.Kind())
	}
	return nil, fmt.Errorf("symx: unsupported field type %s", v.Kind())
}

// ApplyPatchBindings 根据 PatchBinding 中绑定的 FieldIndex，从 target 当前字段值回填到文件对应位置。
// target 可以是 struct 或 *struct；仅支持固定宽度整数字段的回填。
func ApplyPatchBindings(wa io.WriterAt, target any, bindings []PatchBinding) error {
	rv, err := derefStruct(target)
	if err != nil {
		return err
	}
	for _, binding := range bindings {
		if len(binding.FieldIndex) == 0 {
			return fmt.Errorf("symx: patch binding type=%d has empty FieldIndex", binding.Type)
		}
		fv := rv.FieldByIndex(binding.FieldIndex)
		buf, err := fixedWidthFieldBytes(fv, binding.Size)
		if err != nil {
			if binding.FieldName != "" {
				return fmt.Errorf("symx: patch field %s: %w", binding.FieldName, err)
			}
			return fmt.Errorf("symx: patch type=%d: %w", binding.Type, err)
		}
		if _, err := wa.WriteAt(buf, binding.Offset); err != nil {
			if binding.FieldName != "" {
				return fmt.Errorf("symx: patch field %s: %w", binding.FieldName, err)
			}
			return fmt.Errorf("symx: patch type=%d: %w", binding.Type, err)
		}
	}
	return nil
}

// UnmarshalTLVs 解析 data 中的 TLV 字节流，按 type 编号回填到 v 的对应字段。
// 未知的 TLV type 会被跳过，字段顺序无要求。
func UnmarshalTLVs(data []byte, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer {
		return fmt.Errorf("symx: UnmarshalTLVs requires a pointer to struct")
	}
	rv = rv.Elem()
	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("symx: UnmarshalTLVs requires a pointer to struct")
	}
	rt := rv.Type()

	// 构建 TLV type → 字段索引 映射
	typeIndex := make(map[uint8]int, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		tag, ok := rt.Field(i).Tag.Lookup(TagK)
		if !ok {
			continue
		}
		typ, _, ok := parseTag(tag)
		if !ok {
			continue
		}
		typeIndex[typ] = i
	}

	// 顺序解析 TLV
	off := 0
	for off < len(data) {
		tlv, n := ReadTLV(data[off:])
		off += n
		idx, ok := typeIndex[tlv.Typ]
		if !ok {
			continue // 未知 type，跳过
		}
		if err := setFieldValue(rv.Field(idx), tlv.Value); err != nil {
			return fmt.Errorf("symx: TLV type=%d: %w", tlv.Typ, err)
		}
	}
	return nil
}
