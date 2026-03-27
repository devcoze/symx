package header

import (
	"reflect"
	"testing"
)

func TestNormalizeBID(t *testing.T) {
	type args struct {
		raw []byte
	}
	tests := []struct {
		name  string
		args  args
		want  [16]byte
		want1 int
		want2 int
	}{
		{
			name: "16 bytes BID",
			args: args{
				raw: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			},
			want:  [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			want1: BIDFull16,
			want2: 16,
		},
		{
			name: "20 bytes BID (truncated to 16)",
			args: args{
				raw: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
			},
			want:  [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			want1: BIDTrunc16,
			want2: 20,
		},
		{
			name: "10 bytes BID (randomly filled to 16)",
			args: args{
				raw: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			},
			want:  [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0}, // 后面6字节随机填充，测试时不比较
			want1: BIDRandFill,
			want2: 10,
		},
		{
			name: "empty BID (generated random BID)",
			args: args{
				raw: []byte{},
			},
			want:  [16]byte{}, // 全零，测试时不比较
			want1: BIDGenerate,
			want2: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2 := NormalizeBID(tt.args.raw)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NormalizeBID() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("NormalizeBID() got1 = %v, want %v", got1, tt.want1)
			}
			if got2 != tt.want2 {
				t.Errorf("NormalizeBID() got2 = %v, want %v", got2, tt.want2)
			}
		})
	}
}
