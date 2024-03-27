package miio

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/uole/miio/cipher"
	"github.com/uole/miio/packet"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type (
	Conn struct {
		conn         net.Conn
		address      string              //device address
		sequence     int                 //message sequence
		deviceID     uint32              //device id
		deviceUptime int64               //device uptime
		cipher       *cipher.TokenCipher //device token cipher
		mutex        sync.Mutex
	}
)

func (c *Conn) nextID() int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.sequence++
	if c.sequence >= 9999 {
		c.sequence = 1
	}
	return c.sequence
}

func (c *Conn) nextStamp() uint32 {
	return uint32(time.Now().Unix() - c.deviceUptime)
}

func (c *Conn) handshake(ctx context.Context) (err error) {
	var (
		in   []byte
		resp *packet.Frame
	)
	c.mutex.Lock()
	in = packet.ApplyBytes(HeadLength)
	defer func() {
		packet.ReleaseBytes(in)
		c.mutex.Unlock()
	}()
	frame := packet.NewHelloFrame()
	frame.Reserved = 4294967295
	if _, err = frame.WriteTo(c.conn); err != nil {
		return
	}
	if resp, err = c.ReadMsg(ctx); err != nil {
		return
	}
	c.deviceID = resp.DeviceID
	c.deviceUptime = time.Now().Unix() - int64(resp.Stamp)
	return
}

func (c *Conn) reconnect(ctx context.Context) (err error) {
	var (
		dialer net.Dialer
	)
	if c.conn != nil {
		if err = c.conn.Close(); err != nil {
			return
		}
	}
	if c.conn, err = dialer.DialContext(ctx, "udp", c.address); err != nil {
		return
	}
	return c.handshake(ctx)
}

func (c *Conn) Dial(ctx context.Context, address string, token string) (err error) {
	var (
		pos    int
		buf    []byte
		dialer net.Dialer
	)
	if buf, err = hex.DecodeString(token); err != nil {
		return ErrorTokenInvalid
	}
	if pos = strings.IndexByte(address, ':'); pos == -1 {
		address += ":" + strconv.Itoa(DefaultPort)
	}
	if c.conn, err = dialer.DialContext(ctx, "udp", address); err != nil {
		return
	}
	c.address = address
	c.cipher = cipher.NewTokenCipher(buf)
	err = c.handshake(ctx)
	return
}

func (c *Conn) Write(ctx context.Context, b []byte) (n int, err error) {
	var (
		m        int64
		ok       bool
		buf      []byte
		deadline time.Time
	)
	if buf, err = c.cipher.Encrypt(b); err != nil {
		return
	}
	if c.deviceID == 0 {
		if err = c.handshake(ctx); err != nil {
			return
		}
	}
	frame := packet.NewFrame(c.deviceID, c.nextStamp(), c.cipher.Token, buf)
	if deadline, ok = ctx.Deadline(); ok {
		if err = c.conn.SetWriteDeadline(deadline); err != nil {
			return
		}
		defer func() {
			_ = c.conn.SetDeadline(time.Time{})
		}()
	}
	m, err = frame.WriteTo(c.conn)
	return int(m), err
}

func (c *Conn) Read(ctx context.Context, b []byte) (n int, err error) {
	var (
		ok       bool
		buf      []byte
		frame    *packet.Frame
		deadline time.Time
	)
	if deadline, ok = ctx.Deadline(); ok {
		if err = c.conn.SetWriteDeadline(deadline); err != nil {
			return
		}
		defer func() {
			_ = c.conn.SetDeadline(time.Time{})
		}()
	}
	frame = &packet.Frame{}
	if _, err = frame.ReadFrom(c.conn); err == nil {
		if len(frame.Data) > 0 {
			if buf, err = c.cipher.Decrypt(frame.Data); err == nil {
				frame.Release()
				frame.Data = buf
				copy(b[:], frame.Data[:])
			}
		}
	}
	return
}

func (c *Conn) WriteMsg(ctx context.Context, msg any) (err error) {
	var (
		ok       bool
		buf      []byte
		deadline time.Time
	)
	if buf, err = json.Marshal(msg); err != nil {
		return
	}
	if buf, err = c.cipher.Encrypt(buf); err != nil {
		return
	}
	if c.deviceID == 0 {
		if err = c.handshake(ctx); err != nil {
			return
		}
	}
	frame := packet.NewFrame(c.deviceID, c.nextStamp(), c.cipher.Token, buf)
	if deadline, ok = ctx.Deadline(); ok {
		if err = c.conn.SetWriteDeadline(deadline); err != nil {
			return
		}
		defer func() {
			_ = c.conn.SetDeadline(time.Time{})
		}()
	}
	_, err = frame.WriteTo(c.conn)
	return
}

func (c *Conn) ReadMsg(ctx context.Context) (frame *packet.Frame, err error) {
	var (
		ok       bool
		buf      []byte
		deadline time.Time
	)
	if deadline, ok = ctx.Deadline(); ok {
		if err = c.conn.SetWriteDeadline(deadline); err != nil {
			return
		}
		defer func() {
			_ = c.conn.SetDeadline(time.Time{})
		}()
	}
	frame = &packet.Frame{}
	if _, err = frame.ReadFrom(c.conn); err == nil {
		if len(frame.Data) > 0 {
			if buf, err = c.cipher.Decrypt(frame.Data); err == nil {
				frame.Release()
				frame.Data = buf
			}
		}
	}
	return
}

func (c *Conn) Execute(ctx context.Context, req *CommandRequest) (res *CommandResponse, err error) {
	var (
		frame *packet.Frame
	)
	req.ID = c.nextID()
	c.mutex.Lock()
	defer func() {
		c.mutex.Unlock()
	}()
	if err = c.WriteMsg(ctx, req); err != nil {
		return
	}
	if frame, err = c.ReadMsg(ctx); err == nil {
		res = &CommandResponse{Method: req.Method}
		if err = json.Unmarshal(frame.Data, res); err == nil {
			if res.Error != nil {
				err = res.Error
			}
		}
	}
	return
}

func (c *Conn) Close() (err error) {
	err = c.conn.Close()
	return
}
