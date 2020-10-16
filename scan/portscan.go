package scan

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"golang.org/x/xerrors"
)

type Scanner struct {
	iface           *net.Interface
	target, gw, src net.IP
	dstHwAddr net.HardwareAddr
	handle *pcap.Handle

	opts gopacket.SerializeOptions
	buf  gopacket.SerializeBuffer
}

func NewScanner(targetIP string) (*Scanner, error) {
	targetIPAddr := net.ParseIP(targetIP)
	s := &Scanner{
		target: targetIPAddr,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf: gopacket.NewSerializeBuffer(),
	}

	router, err := newRouter()
	if err != nil {
		return nil, err
	}

	iface, gw, src, err := router.Route(targetIPAddr)
	if err != nil {
		return nil, err
	}
	log.Printf("Scaninng ip %v with interface %v, gateway %v, src %v", targetIPAddr, iface.Name, gw, src)
	s.gw, s.src, s.iface = gw, src, iface

	// Timeout setting depends on your network environment
	handle, err := pcap.OpenLive(iface.Name, 65536, false, time.Second*1)
	if err != nil {
		return nil, err
	}
	s.handle = handle

	s.dstHwAddr, err = s.Arp()
	if err != nil {
		return nil, err
	}
	return s, nil
}


func (s *Scanner) close() {
	fmt.Println("Scanner will close")
	s.handle.Close()
}

func (s *Scanner) Arp() (net.HardwareAddr, error) {
	start := time.Now()
	arpDst := s.target // s.target is target machine address

	//ToDo: How to detect host up or down
	if s.gw != nil {
		arpDst = s.gw
	}

	// Prepare the layers to send for an ARP request
	eth := layers.Ethernet{
		SrcMAC: s.iface.HardwareAddr, // eno2
		// arp request is broadcast
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.iface.HardwareAddr),
		SourceProtAddress: []byte(s.src),
		// DstHwAddress is unknown
		DstHwAddress:   []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress: []byte(arpDst),
	}

	if err := s.send(&eth, &arp); err != nil {
		return nil, err
	}

	for {
		if time.Since(start) > time.Second*20 {
			return nil, xerrors.New("Timeout getting ARP reply")
		}
		data, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			/*
				//Check arp packet status
				log.Println("Arp data: ", arp)
				log.Printf("arpDstIP: %s, arpReplySrcIP:%s\n", net.IP.String(arpDst), net.IP.String(arp.SourceProtAddress))
				log.Printf("arpReplySrcHwAddress: %s\n", net.HardwareAddr.String(arp.SourceHwAddress))
			*/
			// compare source ip and arpDst
			if net.IP(arp.SourceProtAddress).Equal(net.IP(arpDst)) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
}

func (s *Scanner) recv(dataCh chan []byte, errCh chan error, filter string) {
	if filter != "" {
		err := s.handle.SetBPFFilter(filter)
		if err != nil {
			err = xerrors.Errorf("BPF filter error: %w", err)
			errCh <- err
		}
	}
	timeoutCount := 0
	for {
		// Must call s.handle.ReadPacketData() once.
		data, _, err := s.handle.ReadPacketData()
		/*
			Check s.handle status
			fmt.Printf("%+v\n", *s.handle)
		*/
		if err == pcap.NextErrorTimeoutExpired {
			timeoutCount++
			// When timeCount == 2, target port was filtered
			if timeoutCount == 2 {
				timeoutCount = 0
				errCh <- err
			}
			continue
		} else if err != nil {
			err = xerrors.Errorf("Error reading packet: %v", err)
			timeoutCount = 0
			errCh <- err
		} else {
			timeoutCount = 0
			dataCh <- data
		}
	}
}

func (s *Scanner) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(s.buf, s.opts, l...); err != nil {
		return err
	}
	// Send packet
	return s.handle.WritePacketData(s.buf.Bytes())
}

func (s *Scanner) judgePortStatus(rawData []byte) (string, error) {
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
		case layers.LayerTypeTCP:
			fmt.Printf("    TCP SrcPort: %d ---> DstPort: %d\n", tcp.SrcPort, tcp.DstPort)
			if tcp.RST {
				log.Printf(" port %v Closed", tcp.SrcPort)
			} else if tcp.SYN && tcp.ACK {
				log.Printf(" port %v open", tcp.SrcPort)
			}
		case layers.LayerTypeUDP:
			fmt.Printf("    UDP SrcPort: %d ---> DstPort: %d\n", udp.SrcPort, udp.DstPort)
			log.Printf(" port %v open", udp.SrcPort)
		case layers.LayerTypeICMPv4:
			retType := icmp.TypeCode.Type()
			retCode := icmp.TypeCode.Code()
			fmt.Printf("    ICMP Type: %v, ICMP Code: %v\n", retType, retCode)
			if retType == layers.ICMPv4TypeDestinationUnreachable {
				if retCode == layers.ICMPv4CodeHost || retCode == layers.ICMPv4CodeProtocol || retCode == layers.ICMPv4CodeNetAdminProhibited || retCode == layers.ICMPv4CodeHostAdminProhibited || retCode == layers.ICMPv4CodeCommAdminProhibited {
					return "filtered", nil
				} else if retCode == layers.ICMPv4CodePort {
					return "Closed", nil
				}
			}
		}
	}
	if err != nil {
		err := xerrors.Errorf("Failed to Decode: %w", err)
		return "", err
	}
	return "", nil
}

func newRouter() (routing.Router, error) {
	router, err := routing.New()
	if err != nil {
		return nil, xerrors.Errorf("routing error: %w", err)
	}
	return router, nil
}

func parseArgIP() (net.IP, error) {
	var ip net.IP
	flag.Parse()
	if ip = net.ParseIP(flag.Arg(0)); ip == nil {
		return nil, xerrors.Errorf("non-ip target: %q", flag.Arg(0))
	} else if ip = ip.To4(); ip == nil {
		return nil, xerrors.Errorf("non-ipv4 target: %q", flag.Arg(0))
	}
	return ip, nil
}

func PortScan(targetIP string) error {
	s, err := NewScanner(targetIP)
	if err != nil {
		err = xerrors.Errorf("Failed to create Scanner for %v: %v", targetIP, err)
		return err
	}
	defer s.close()

	err = s.Ping()
	if err != nil {
		return xerrors.Errorf("Failed to communicate target machine: %w", err)
	}

	err = s.SynScan()
	if err != nil {
		return xerrors.Errorf("Failed to TCP SYN Scan: %w", err)
	}

	err = s.UDPScan()
	if err != nil {
		return xerrors.Errorf("Failed to UDP scan: %w", err)
	}

	return nil
}
