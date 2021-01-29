package arp

import (
	"io"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/mdlayher/raw"
)

var (
	ParamMap = sync.Map{}
)

type ParamKey struct {
	Interface    string
	TargetString string
}

type Parameter struct {
	Intf   *net.Interface
	SrcMAC net.HardwareAddr
	DstMAC net.HardwareAddr
	SPA    net.IP
	TPA    net.IP
	Tags   []Tag
}

type Tag struct {
	K string
	V string
}

type ARPReceiver struct {
	c *raw.Conn
}

func OpenARPReceiver(ifi *net.Interface) (*ARPReceiver, error) {
	// ETH_P_ARP = 0x806
	c, err := raw.ListenPacket(ifi, 0x806, nil)
	if err != nil {
		return nil, err
	}
	return &ARPReceiver{
		c: c,
	}, nil
}

func (r *ARPReceiver) Close() {
	r.c.Close()
}

func (r *ARPReceiver) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	// 64 bytes is enough for ARP packets
	b := make([]byte, 64)
	n, _, err := r.c.ReadFrom(b)
	if n == 0 {
		err = io.EOF
	}
	if err != nil {
		return
	}
	ci.CaptureLength = n
	ci.Length = n
	data = b
	return
}
