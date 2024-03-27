package packet

import (
	"bytes"
	"sync"
)

var (
	bufPool5k sync.Pool
	bufPool2k sync.Pool
	bufPool1k sync.Pool
	bufPool   sync.Pool

	bufferPool sync.Pool
)

func ApplyBytes(size int) []byte {
	if size <= 0 {
		return nil
	}
	var x interface{}
	if size >= 5*1024 {
		x = bufPool5k.Get()
	} else if size >= 2*1024 {
		x = bufPool2k.Get()
	} else if size >= 1*1024 {
		x = bufPool1k.Get()
	} else {
		x = bufPool.Get()
	}
	if x == nil {
		return make([]byte, size)
	}
	buf := x.([]byte)
	if cap(buf) < size {
		return make([]byte, size)
	}
	return buf[:size]
}

func ReleaseBytes(buf []byte) {
	size := cap(buf)
	if size <= 0 {
		return
	}
	if size >= 5*1024 {
		bufPool5k.Put(buf)
	} else if size >= 2*1024 {
		bufPool2k.Put(buf)
	} else if size >= 1*1024 {
		bufPool1k.Put(buf)
	} else {
		bufPool.Put(buf)
	}
}

func ApplyBuffer() *bytes.Buffer {
	if v := bufferPool.Get(); v != nil {
		return v.(*bytes.Buffer)
	}
	return bytes.NewBuffer([]byte{})
}

func ReleaseBuffer(b *bytes.Buffer) {
	b.Reset()
	bufferPool.Put(b)
}
