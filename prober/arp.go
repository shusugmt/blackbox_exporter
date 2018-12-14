package prober

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/prometheus/blackbox_exporter/config"
)

func ProbeARP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, _ log.Logger) (success bool) {

	setupStart := time.Now()
	logger := ctx.Value("logger").(log.Logger)
	logger = log.With(logger, "target", target)

	var durationGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_arp_duration_seconds",
		Help: "Duration of ARP request by phase",
	}, []string{"phase"})

	for _, lv := range []string{"setup", "rtt"} {
		durationGaugeVec.WithLabelValues(lv)
	}

	registry.MustRegister(durationGaugeVec)

	arpConfig := module.ARP
	srcIntfName := arpConfig.SourceInterfaceName
	iface, err := net.InterfaceByName(srcIntfName)
	if err != nil {
		// インターフェース名が間違っている
		level.Error(logger).Log("msg", err, "errsrc", srcIntfName)
		return false
	}
	logger = log.With(logger, "interface", srcIntfName)

	// targetの最後にタグ情報があれば、すべてログに付与
	params, err := parseTargetString(target)
	if err != nil {
		level.Error(logger).Log("msg", err)
		return false
	}
	for _, t := range params.tags {
		logger = log.With(logger, t.key, t.value)
	}

	tpa := net.ParseIP(params.tpa).To4()
	if tpa == nil {
		// IPv4アドレスでない
		level.Error(logger).Log("msg", "Not a valid IPv4 address", "errsrc", params.tpa)
		return false
	}
	logger = log.With(logger, "tpa", tpa)

	dstmac, err := net.ParseMAC(params.dstmac)
	if err != nil {
		// MACアドレスでない
		level.Error(logger).Log("msg", err, "errsrc", params.dstmac)
		return false
	}
	logger = log.With(logger, "dstmac", dstmac)

	// We just look for IPv4 addresses, so try to find if the interface has one.
	var spa net.IP
	addrs, err := iface.Addrs()
	if err != nil {
		level.Error(logger).Log("msg", err)
		return false
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				if ipnet.Contains(tpa) {
					spa = ip4
					break
				}
			}
		}
	}
	// Sanity-check that the interface has a good address.
	if spa == nil {
		level.Error(logger).Log("msg", "Couldn't find any suitable IPv4 for spa")
		return false
	} else if spa[0] == 127 {
		level.Error(logger).Log("msg", "Can't use loopback address for spa", "errsrc", spa)
		return false
	}

	sha := iface.HardwareAddr
	srcmac := sha

	ethHdr, arpRequestHdr, arpResponseHdr := buildARPRequest(srcmac, dstmac, sha, spa, tpa)

	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(iface.Name, 128, false, pcap.BlockForever)
	if err != nil {
		level.Error(logger).Log("msg", err)
		return false
	}
	defer handle.Close()
	// 送信したARP Requestに対する返答のみを対象とするフィルタをセット
	bpfFilter := fmt.Sprintf("ether src %s and arp and arp[6:2] = 2", dstmac.String())
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		level.Error(logger).Log("msg", err)
		return false
	}

	// Start up a goroutine to read in packet data.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wg := &sync.WaitGroup{}
	wg.Add(1)
	responseReceived := false
	go readARP(ctx, handle, arpResponseHdr, &responseReceived, wg)

	durationGaugeVec.WithLabelValues("setup").Add(time.Since(setupStart).Seconds())
	rttStart := time.Now()
	if err := writeARP(handle, ethHdr, arpRequestHdr); err != nil {
		level.Error(logger).Log("msg", err)
		return false
	}

	wg.Wait()
	if responseReceived {
		rtt := time.Since(rttStart).Seconds()
		durationGaugeVec.WithLabelValues("rtt").Add(rtt)
		level.Info(logger).Log("state", "up", "rtt", rtt, "msg", "Got reply")
	} else {
		level.Info(logger).Log("state", "down", "msg", "Time out")
	}
	return responseReceived
}

type tag struct {
	key   string
	value string
}

type targetParams struct {
	tpa    string
	dstmac string
	tags   []tag
}

func (params *targetParams) addTag(t tag) {
	params.tags = append(params.tags, t)
}

func parseTargetString(targetString string) (params targetParams, err error) {
	p := strings.SplitN(targetString, "|", 3)
	if len(p) < 2 {
		return params, errors.New("Couldn't parse target string")
	}
	params.tpa = p[0]
	params.dstmac = p[1]
	if len(p) == 3 {
		t := p[2]
		for _, tagkv := range strings.Split(t, ",") {
			kv := strings.SplitN(tagkv, "=", 2)
			if len(kv) != 2 || kv[0] == "" {
				continue
			}
			params.addTag(tag{key: kv[0], value: kv[1]})
		}
	}
	return params, nil
}

func buildARPRequest(srcmac, dstmac, sha net.HardwareAddr, spa, tpa net.IP) (*layers.Ethernet, *layers.ARP, *layers.ARP) {
	ethHdr := layers.Ethernet{
		SrcMAC:       srcmac,
		DstMAC:       dstmac,
		EthernetType: layers.EthernetTypeARP,
	}
	arpRequestHdr := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(sha),
		SourceProtAddress: []byte(spa),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(tpa),
	}
	arpReplyHdr := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(dstmac),
		SourceProtAddress: []byte(tpa),
		DstHwAddress:      []byte(sha),
		DstProtAddress:    []byte(spa),
	}
	return &ethHdr, &arpRequestHdr, &arpReplyHdr
}

func readARP(ctx context.Context, handle *pcap.Handle, arpResponseHdr *layers.ARP, responseReceived *bool, wg *sync.WaitGroup) {
	defer wg.Done()
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-src.Packets():
			if packet == nil {
				continue
			}
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation == layers.ARPReply &&
				bytes.Equal(arp.SourceHwAddress, arpResponseHdr.SourceHwAddress) &&
				bytes.Equal(arp.SourceProtAddress, arpResponseHdr.SourceProtAddress) &&
				bytes.Equal(arp.DstHwAddress, arpResponseHdr.DstHwAddress) &&
				bytes.Equal(arp.DstProtAddress, arpResponseHdr.DstProtAddress) {
				// This is a reply packet
				*responseReceived = true
				return
			}
		}
	}
}

// writeARP writes an ARP request for each address on our local network to the
// pcap handle.
func writeARP(handle *pcap.Handle, ethHdr *layers.Ethernet, arpRequestHdr *layers.ARP) error {
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, ethHdr, arpRequestHdr)
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}
	return nil
}
