package scan

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/xerrors"
)

func (s *Scanner) Ping() error {
	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       s.dstHwAddr,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    s.src,
		DstIP:    s.target,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
	}
	icmp := layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, uint8(0)),
	}
	dataCh := make(chan []byte)
	errCh := make(chan error)
	filter := fmt.Sprintf("icmp and src net %s", s.target.String())

	go s.recv(dataCh, errCh, filter)

	var recErr error
	for i := 0; i <= 2; i++ {
		err := s.send(&eth, &ip4, &icmp)
		if err != nil {
			err = xerrors.Errorf("Failed to send icmp packet: %v", err)
			return err
		}
		select {
		case rawData := <-dataCh:
			icmpTypeCode, err := s.decodeICMPpacket(rawData)
			if err != nil {
				return xerrors.Errorf("Failed to decode icmp packet: %w", err)
			}
			if icmpTypeCode.Type() != layers.ICMPv4TypeEchoReply {
				return xerrors.Errorf("ICMP status: %s", icmpTypeCode.String())
			}
			return nil
		case recErr = <-errCh:
			continue
		}
	}
	return xerrors.Errorf("Failed to receive packet from target machine: %v", recErr)
}

func (s *Scanner) decodeICMPpacket(rawData []byte) (layers.ICMPv4TypeCode, error) {
	var (
		eth     layers.Ethernet
		ip4     layers.IPv4
		tcp     layers.TCP
		udp     layers.UDP
		icmp    layers.ICMPv4
		payload gopacket.Payload
	)
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth,
		&ip4,
		&tcp,
		&udp,
		&icmp,
		&payload,
	)
	decodedLayers := make([]gopacket.LayerType, 0, 10)
	// decodedLayers is [0]=eth, [1]=ip4...etc
	err := parser.DecodeLayers(rawData, &decodedLayers)
	var icmpTypeCode layers.ICMPv4TypeCode
	for _, typ := range decodedLayers {
		fmt.Println("Successfully decoded layer type", typ)
		switch typ {
		case layers.LayerTypeEthernet:
			srcMAC := eth.SrcMAC.String()
			dstMAC := eth.DstMAC.String()
			fmt.Printf("    Eth SrcMAC: %s ---> DstMAC: %s\n", srcMAC, dstMAC)
		case layers.LayerTypeIPv4:
			srcIP4 := ip4.SrcIP.String()
			dstIP4 := ip4.DstIP.String()
			fmt.Printf("    IP4 SrcIP: %s ---> DstIP: %s\n", srcIP4, dstIP4)
		case layers.LayerTypeICMPv4:
			icmpType := icmp.TypeCode.Type()
			icmpCode := icmp.TypeCode.Code()
			fmt.Printf("    ICMP Type: %v, Code: %v Status: %s\n", icmpType, icmpCode, icmpTypeCode.String())
		}
	}
	// TODO:ここの返り値を何とかしたい
	if err != nil {
		err := xerrors.Errorf("Failed to Decode: %w", err)
		return 1111, err
	}
	icmpTypeCode = icmp.TypeCode
	return icmpTypeCode, nil
}
