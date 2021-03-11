package main

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"time"

	"github.com/msarvar/godns/pkg"
	"github.com/pkg/errors"
)

func lookup(qname string, qtype pkg.QueryType, server net.IP) (*pkg.DNSPacket, error) {
	remote := &net.UDPAddr{
		IP:   server,
		Port: 53,
	}

	conn, err := net.Dial("udp", remote.String())
	logAndExitIfErr("Failed creating UDP connection: %s", err)

	defer conn.Close()

	packet := pkg.NewDNSPacket()
	q := pkg.NewDNSQuestion(qname, qtype)

	rand.Seed(time.Now().UnixNano())

	packet.Header.ID = uint16(10000 + rand.Intn(100000-5000))
	packet.Header.RecursionDesired = true
	packet.Header.Opcode = 0
	packet.Questions = append(packet.Questions, q)

	reqBuffer := pkg.NewBytePacketBuffer()
	err = packet.Write(reqBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "preparing dns request packet")
	}

	fmt.Println("Sending the request...")
	ioutil.WriteFile("query.txt", reqBuffer.Buf[0:reqBuffer.Pos()], 0666)
	_, err = conn.Write(reqBuffer.Buf[0:reqBuffer.Pos()])
	if err != nil {
		return nil, errors.Wrap(err, "sending dns request")
	}

	// Receive DNS response
	resBuffer := pkg.NewBytePacketBuffer()

	fmt.Println("Receiving the response...")
	_, err = conn.Read(resBuffer.Buf)
	// fmt.Printf("response packet: %+v\n", resBuffer.Buf)
	if err != nil {
		return nil, errors.Wrap(err, "reading dns server response")
	}

	fmt.Println("Decoding the response...")
	resPacket, err := pkg.DNSPacketFromBuffer(resBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "parsing dns server response")
	}

	return resPacket, nil
}

func recursiveLookup(qName string, qType pkg.QueryType) (*pkg.DNSPacket, error) {
	// ns := net.ParseIP("198.41.0.4")
	// failing ns
	ns := net.ParseIP("192.33.14.30")

	for {
		fmt.Printf("Attempting to lookup %s %s with ns %s\n", qType, qName, ns)
		nsCopy := ns
		response, err := lookup(qName, qType, nsCopy)
		if err != nil {
			return nil, errors.Wrap(err, "looking up query name")
		}

		// if there are answers and no errors return the response
		if len(response.Answers) != 0 && response.Header.ResCode == pkg.NoError {
			return response, nil
		}

		// If response code is NXDomain it means domain name doesn't exists, we
		// return the response
		if response.Header.ResCode == pkg.NxDomain {
			fmt.Println("domain not found")
			return response, nil
		}

		// Get new name server for a query
		if newNS := response.GetResolverNS(qName); newNS != nil {
			ns = newNS
			continue
		}

		newNSName := response.GetUnresolvedNS(qName)
		if newNSName == "" {
			fmt.Println("no new name servers to traverse")
			return response, nil
		}

		recursiveResponse, err := recursiveLookup(newNSName, pkg.AQueryType)
		if err != nil {
			return nil, errors.New("recursive lookup")
		}

		newNs := recursiveResponse.GetRandomA()
		if newNs != nil {
			ns = newNs
		} else {
			fmt.Println("nothing to do returning")
			return response, nil
		}
	}
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

		result, err := recursiveLookup(q.Name.String(), q.QType)
		if err == nil {
			pq := *q
			packet.Questions = append(packet.Questions, &pq)
			packet.Header.Questions = uint16(len(packet.Questions))
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
			fmt.Println(err)
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
	query, _ := ioutil.ReadFile("./query_packet.txt")
	fmt.Println(query)
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
