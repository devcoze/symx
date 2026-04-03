package proguard

import (
	"github.com/devcoze/symx"
)

type Encoder struct {
}

func (e *Encoder) FileType() uint8 {
	return symx.ProGuard
}

func (e *Encoder) Identify() string {
	return ""
}

func (e *Encoder) ExtHeadSize() uint16 {
	return 0
}

func (e *Encoder) PayloadSize() uint64 {
	return 0
}

func (e *Encoder) WriteExtHead(cw *symx.CountingWriter) error {

	return nil
}

func (e *Encoder) WritePayload(cw *symx.CountingWriter) error {

	return nil
}
