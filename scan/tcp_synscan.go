package scan

import (
	"fmt"
	"log"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/xerrors"
)

func (s *Scanner) SynScan() error {
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
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: 54321,
		Window:  64240,
		SYN:     true,
	}
	type tcpOptions []layers.TCPOption

	opts := &tcpOptions{
		{
			OptionType:   layers.TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{0x05, 0xb4},
		},
		{
			OptionType:   layers.TCPOptionKindWindowScale,
			OptionLength: 3,
			OptionData:   []byte{0x07},
		},
		{
			OptionType:   layers.TCPOptionKindSACKPermitted,
			OptionLength: 2,
		},
	}
	tcp.Options = *opts
	tcp.SetNetworkLayerForChecksum(&ip4)

	dataCh := make(chan []byte)
	errCh := make(chan error)
	filter := fmt.Sprintf("tcp and src net %s", s.target.String())

	// start to goroutine of receive packet func
	go s.recv(dataCh, errCh, filter)

	targetPort := []layers.TCPPort{22, 23, 25, 53, 80, 443, 465, 3610, 135, 139, 445, 2179, 111}
	var confirmFilteredPort []layers.TCPPort
	for _, dstPort := range targetPort {
		tcp.DstPort = dstPort
		fmt.Printf("\n【Scan target port: %d】\n", tcp.DstPort)
		err := s.send(&eth, &ip4, &tcp)
		if err != nil {
			err = xerrors.Errorf("Error sending to port %v: %v", tcp.DstPort, err)
			return err
		}
		select {
		case rawData := <-dataCh:
			_, err := s.judgePortStatus(rawData)
			if err != nil {
				log.Println("Failed to judge port status: ", err)
			}
		case err := <-errCh:
			confirmFilteredPort = append(confirmFilteredPort, dstPort)
			log.Println(dstPort, err)
		}
	}

	if len(confirmFilteredPort) != 0 {
		log.Println("Confirm filtered packet")
		for _, dstPort := range confirmFilteredPort {
			tcp.DstPort = dstPort
			fmt.Printf("\n【Scan target port: %d】\n", tcp.DstPort)
			err := s.send(&eth, &ip4, &tcp)
			if err != nil {
				err = xerrors.Errorf("Error sending to port %v: %v", tcp.DstPort, err)
				return err
			}
			select {
			case rawData := <-dataCh:
				_, err := s.judgePortStatus(rawData)
				if err != nil {
					log.Println("Failed to judge port status: ", err)
				}
			case err := <-errCh:
				if err == pcap.NextErrorTimeoutExpired {
					log.Printf(" port %v filtered", tcp.DstPort)
				} else {
					log.Println("Unexpected error: ", err)
				}
			}
		}
	}
	return nil
}
