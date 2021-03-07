package main

import (
	"fmt"
	"net"

	"github.com/msarvar/godns/pkg"
	"github.com/pkg/errors"
)

func lookup(qname string, qtype pkg.QueryType) (*pkg.DNSPacket, error) {
	socket := net.Dialer{}
	conn, err := socket.Dial("udp", "8.8.8.8:53")
	logAndExitIfErr("Failed creating UDP connection: %s", err)

	defer conn.Close()

	packet := pkg.NewDNSPacket()
	q := pkg.NewDNSQuestion(qname, qtype)

	packet.Header.ID = 6666
	packet.Header.Questions = 1
	packet.Header.RecursionDesired = true
	packet.Questions = append(packet.Questions, q)

	reqBuffer := pkg.NewBytePacketBuffer()
	err = packet.Write(reqBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "preparing dns request packet")
	}

	_, err = conn.Write(reqBuffer.Buf)
	if err != nil {
		return nil, errors.Wrap(err, "sending dns request")
	}

	// Receive DNS response
	resBuffer := pkg.NewBytePacketBuffer()

	_, err = conn.Read(resBuffer.Buf)
	if err != nil {
		return nil, errors.Wrap(err, "reading dns server response")
	}

	resPacket, err := pkg.DNSPacketFromBuffer(resBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "parsing dns server response")
	}

	return resPacket, nil
}

func handleQuery(udpConn net.PacketConn, reqBuffer *pkg.BytePacketBuffer, addr net.Addr) {
	request, err := pkg.DNSPacketFromBuffer(reqBuffer)
	logAndExitIfErr("Error: initializing response: %s\n", err)

	packet := pkg.NewDNSPacket()
	packet.Header.ID = request.Header.ID
	packet.Header.RecursionDesired = true
	packet.Header.RecursionAvailable = true
	packet.Header.Response = true

	// only handling cases where there is 1 question
	if len(request.Questions) == 1 {
		q := request.Questions[0]
		fmt.Println(fmt.Sprintf("Received query: %+v", q))

		result, err := lookup(q.Name.String(), q.QType)
		if err == nil {
			packet.Header.Questions = 1
			packet.Header.ResCode = result.Header.ResCode

			for _, ans := range result.Answers {
				fmt.Println(fmt.Sprintf("Answer: %+v", ans))

				packet.Answers = append(packet.Answers, ans)
			}

			for _, auth := range result.Authorities {
				fmt.Println(fmt.Sprintf("Authority: %+v", auth))

				packet.Authorities = append(packet.Authorities, auth)
			}

			for _, res := range result.Resources {
				fmt.Println(fmt.Sprintf("Resource: %+v", res))

				packet.Resources = append(packet.Resources, res)
			}
		} else {
			packet.Header.ResCode = pkg.ServFail
		}
	} else {
		packet.Header.ResCode = pkg.FormErr
	}

	resBuffer := pkg.NewBytePacketBuffer()

	err = packet.Write(resBuffer)
	logAndExitIfErr("Error: generating dns response packet: %s\n", err)

	len := resBuffer.Pos()
	data, err := resBuffer.GetRange(0, len)
	logAndExitIfErr("Error: generating dns response packet: %s\n", err)

	_, err = udpConn.WriteTo(data, addr)
	logAndExitIfErr("Error: sending response: %s\n", err)
}

func main() {
	// ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	// defer cancel()
	udpConn, err := net.ListenPacket("udp", ":2053")
	logAndExitIfErr("Error: receiving udp request: %s\n", err)
	defer udpConn.Close()

	for {
		fmt.Println("Waiting for requests...")
		reqBuffer := pkg.NewBytePacketBuffer()

		_, addr, err := udpConn.ReadFrom(reqBuffer.Buf)
		logAndExitIfErr("Error: reading request: %s\n", err)

		handleQuery(udpConn, reqBuffer, addr)
	}
}

func logAndExitIfErr(msg string, err error) {
	if err != nil {
		fmt.Printf(msg, err)
	}
}
