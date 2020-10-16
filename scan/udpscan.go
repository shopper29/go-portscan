package scan

import (
	"fmt"
	"log"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/xerrors"
)

func (s *Scanner) UDPScan() error {
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
		Protocol: layers.IPProtocolUDP,
	}
	udp := layers.UDP{
		SrcPort: 54321,
		Length:  0,
	}
	udp.SetNetworkLayerForChecksum(&ip4)
	dataCh := make(chan []byte)
	errCh := make(chan error)
	filter := fmt.Sprintf("(udp or icmp) and src net %s", s.target.String())

	go s.recv(dataCh, errCh, filter)

	targetPort := []layers.UDPPort{135, 139, 3610}
	var confirmFilteredPort []layers.UDPPort
	for _, dstPort := range targetPort {
		udp.DstPort = dstPort
		fmt.Printf("\n【Scan target port: %d】\n", udp.DstPort)
		err := s.send(&eth, &ip4, &udp)
		if err != nil {
			err = xerrors.Errorf("Error sending to port %v: %v", udp.DstPort, err)
		}
		select {
		case rawData := <-dataCh:
			udpStatus, err := s.judgePortStatus(rawData)
			if err != nil {
				log.Println("Failed to judge port status: ", err)
			} else {
				log.Printf(" port %v %s\n", dstPort, udpStatus)
			}
		case err := <-errCh:
			confirmFilteredPort = append(confirmFilteredPort, dstPort)
			log.Println(dstPort, err)
		}
	}
	if len(confirmFilteredPort) != 0 {
		log.Println("Confirm filtered packet")
		for _, dstPort := range confirmFilteredPort {
			udp.DstPort = dstPort
			fmt.Printf("\n【Scan target port: %d】\n", udp.DstPort)
			err := s.send(&eth, &ip4, &udp)
			if err != nil {
				err = xerrors.Errorf("Error sending to port %v: %v", udp.DstPort, err)
				return err
			}
			select {
			case rawData := <-dataCh:
				udpStatus, err := s.judgePortStatus(rawData)
				if err != nil {
					log.Println("Failed to judge port status: ", err)
				} else {
					log.Printf(" port %v %s\n", dstPort, udpStatus)
				}
			case err := <-errCh:
				if err == pcap.NextErrorTimeoutExpired {
					log.Printf(" port %v open|filtered", udp.DstPort)
				} else {
					log.Println("Unexpected error: ", err)
				}
			}
		}
	}
	return nil
}
