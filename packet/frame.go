package packet

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"io"
)

var (
	ErrorPacket = errors.New("packet invalid")

	PacketMagic uint16 = 8497

	HelloToken = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
)

type Frame struct {
	Magic    uint16
	Length   uint16
	Reserved uint32
	DeviceID uint32
	Stamp    uint32
	Checksum []byte
	Data     []byte
	token    []byte
	buf      []byte
}

func (f *Frame) zeroBytes(buf []byte) {
	l := len(buf)
	for i := 0; i < l; i++ {
		buf[i] = 0x00
	}
}

func (f *Frame) isTokenZero() bool {
	for _, c := range f.Checksum {
		if c != 0 {
			return false
		}
	}
	return true
}

func (f *Frame) Pack() []byte {
	buf := ApplyBuffer()
	defer func() {
		ReleaseBuffer(buf)
	}()
	_, _ = f.WriteTo(buf)
	dst := make([]byte, buf.Len())
	copy(dst[:], buf.Bytes())
	return dst
}

func (f *Frame) ReadFrom(r io.Reader) (n int64, err error) {
	var (
		m   int
		buf []byte
	)
	buf = ApplyBytes(MaxFrameLength)
	f.zeroBytes(buf)
	defer func() {
		ReleaseBytes(buf)
	}()
	if m, err = r.Read(buf); err != nil {
		return
	}
	if m < HeadLength {
		return int64(m), io.ErrShortBuffer
	}
	f.Magic = binary.BigEndian.Uint16(buf[:])
	f.Length = binary.BigEndian.Uint16(buf[2:])
	f.DeviceID = binary.BigEndian.Uint32(buf[8:])
	f.Stamp = binary.BigEndian.Uint32(buf[12:])
	f.Checksum = make([]byte, 16)
	copy(f.Checksum[:], buf[16:])
	if f.Magic != PacketMagic {
		return int64(m), ErrorPacket
	}
	if f.Length != uint16(m) {
		return int64(m), ErrorPacket
	}
	if f.Length > HeadLength {
		f.Data = ApplyBytes(int(f.Length - HeadLength))
		copy(f.Data[:], buf[HeadLength:])
	}
	return
}

func (f *Frame) WriteTo(w io.Writer) (n int64, err error) {
	var (
		buf *bytes.Buffer
	)
	if f.Length == 0 {
		f.Length = uint16(HeadLength + len(f.Data))
	}
	buf = ApplyBuffer()
	defer func() {
		ReleaseBuffer(buf)
	}()
	_ = binary.Write(buf, binary.BigEndian, PacketMagic)
	_ = binary.Write(buf, binary.BigEndian, f.Length)
	_ = binary.Write(buf, binary.BigEndian, f.Reserved)
	_ = binary.Write(buf, binary.BigEndian, f.DeviceID)
	_ = binary.Write(buf, binary.BigEndian, f.Stamp)
	if f.Checksum != nil {
		buf.Write(f.Checksum)
	} else if f.token != nil {
		hash := md5.New()
		hash.Write(buf.Bytes())
		hash.Write(f.token)
		if f.Data != nil {
			hash.Write(f.Data)
		}
		f.Checksum = hash.Sum(nil)
		buf.Write(f.Checksum)
	}
	if f.Data != nil {
		buf.Write(f.Data)
	}
	return buf.WriteTo(w)
}

func (f *Frame) Release() {
	if f.Data != nil {
		ReleaseBytes(f.Data)
		f.Data = nil
	}
}

func NewHelloFrame() *Frame {
	return &Frame{
		Magic:    PacketMagic,
		Reserved: 4294967295,
		DeviceID: 4294967295,
		Stamp:    4294967295,
		Length:   HeadLength,
		Checksum: HelloToken,
	}
}

func NewFrame(deviceId uint32, stamp uint32, token []byte, data []byte) *Frame {
	return &Frame{
		Magic:    PacketMagic,
		Length:   uint16(len(data) + HeadLength),
		DeviceID: deviceId,
		Stamp:    stamp,
		token:    token,
		Data:     data,
	}
}
