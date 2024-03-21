package miio

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type DevTool struct {
}

func (dev *DevTool) ParsePcap(filename string, token string) (err error) {
	var (
		ok        bool
		buf       []byte
		magic     uint16
		frame     *Frame
		cipher    *tokenCipher
		handle    *pcap.Handle
		ipv4Layer *layers.IPv4
		udpLayer  *layers.UDP
	)
	if buf, err = hex.DecodeString(token); err != nil {
		return
	}
	if handle, err = pcap.OpenOffline(filename); err != nil {
		return
	}
	defer func() {
		handle.Close()
	}()
	frame = &Frame{}
	cipher = newTokenCipher(buf)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		udpTypeLayer := packet.Layer(layers.LayerTypeUDP)
		if udpTypeLayer == nil {
			continue
		}
		ipTypeLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipTypeLayer == nil {
			continue
		}
		if ipv4Layer, ok = ipTypeLayer.(*layers.IPv4); !ok {
			continue
		}
		if udpLayer, ok = udpTypeLayer.(*layers.UDP); !ok {
			continue
		}
		buf = udpLayer.LayerPayload()
		if len(buf) < HeadLength {
			continue
		}
		magic = binary.BigEndian.Uint16(buf[:])
		if magic != PacketMagic {
			continue
		}
		if _, err = frame.ReadFrom(bytes.NewBuffer(buf)); err != nil {
			continue
		}
		fmt.Printf("%s:%d -> %s:%d [did: %d; stamp: %d: length: %d] \n", ipv4Layer.SrcIP, udpLayer.SrcPort, ipv4Layer.DstIP, udpLayer.DstPort, frame.DeviceID, frame.Stamp, frame.Length)
		if frame.Length > HeadLength {
			if buf, err = cipher.Decrypt(frame.Data); err == nil {
				fmt.Printf("%s\n", string(buf))
			}
		}
		fmt.Println("")
		frame.Release()
	}
	return
}

func NewDevTool() *DevTool {
	return &DevTool{}
}
