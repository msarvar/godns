package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/msarvar/godns/pkg"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	socket := net.Dialer{}
	conn, err := socket.DialContext(ctx, "udp", "8.8.8.8:53")
	logAndExitIfErr(ctx, "Failed creating UDP connection: %s", err)

	defer conn.Close()

	qname := "yahoo.com"
	qtype := pkg.MXQueryType

	packet := pkg.NewDNSPacket()
	q := pkg.NewDNSQuestion(qname, qtype)

	packet.Header.ID = 6666
	packet.Header.Questions = 1
	packet.Header.RecursionDesired = true
	packet.Questions = append(packet.Questions, q)

	reqBuffer := pkg.NewBytePacketBuffer()
	err = packet.Write(reqBuffer)
	logAndExitIfErr(ctx, "Failed populating dns packet: %s", err)

	_, err = conn.Write(reqBuffer.Buf)
	logAndExitIfErr(ctx, "Failed sending dns request: %s", err)

	// Receive DNS response
	resBuffer := pkg.NewBytePacketBuffer()

	_, err = conn.Read(resBuffer.Buf)
	logAndExitIfErr(ctx, "Failed receiveing dns response: %s", err)

	resPacket, err := pkg.DNSPacketFromBuffer(resBuffer)
	logAndExitIfErr(ctx, "Failed reading response buffer: %s", err)

	fmt.Printf("%+v\n", resPacket.Header)

	for _, q := range resPacket.Questions {
		fmt.Printf("%+v\n", q)
	}

	for _, r := range resPacket.Answers {
		fmt.Printf("%+v\n", r)
	}

	for _, r := range resPacket.Authorities {
		fmt.Printf("%+v\n", r)
	}

	for _, r := range resPacket.Resources {
		fmt.Printf("%+v\n", r)
	}
}

func logAndExitIfErr(ctx context.Context, msg string, err error) {
	if err != nil {
		fmt.Printf(msg, err)
		ctx.Done()
		os.Exit(1)
	}
}
