package main

import (
	"fmt"
	"os"

	"github.com/msarvar/godns/pkg"
)

func main() {
	f, err := os.Open("./response_packet.txt")
	if err != nil {
		fmt.Printf("%s: reading response_packet.txt\n", err)
	}

	buffer := pkg.NewBytePacketBuffer()

	f.Read(buffer.Buf)

	packet, err := pkg.DNSPacketFromBuffer(buffer)
	if err != nil {
		fmt.Printf("%s: reading packet from buffer", err)
	}
	fmt.Printf("%+v\n", packet.Header)

	for _, q := range packet.Questions {
		fmt.Printf("%+v\n", q)
	}

	for _, r := range packet.Answers {
		fmt.Printf("%+v\n", r)
	}

	for _, r := range packet.Authorities {
		fmt.Printf("%+v\n", r)
	}

	for _, r := range packet.Resources {
		fmt.Printf("%+v\n", r)
	}
}
