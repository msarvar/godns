package server

import (
	"context"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"path/filepath"
	"time"

	"github.com/msarvar/godns/pkg/buffer"
	"github.com/msarvar/godns/pkg/dns"
	"github.com/pkg/errors"
)

func lookup(qname string, qtype dns.QueryType, server net.IP) (*dns.DNSPacket, error) {
	remote := &net.UDPAddr{
		IP:   server,
		Port: 53,
	}

	conn, err := net.Dial("udp", remote.String())
	if err != nil {
		return nil, errors.Wrap(err, "creating UDP connection")
	}
	defer conn.Close()

	packet := dns.NewDNSPacket()
	q := dns.NewDNSQuestion(qname, qtype)

	rand.Seed(time.Now().UnixNano())

	packet.Header.ID = uint16(10000 + rand.Intn(100000-5000))
	packet.Header.RecursionDesired = true
	packet.Questions = append(packet.Questions, q)

	reqBuffer := buffer.NewBytePacketBuffer()
	err = packet.Write(reqBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "preparing dns request packet")
	}

	req, err := reqBuffer.GetRangeAtPos()
	if err != nil {
		return nil, errors.Wrap(err, "retrieving buffer")
	}

	ioutil.WriteFile("query.txt", req, 0666)
	_, err = conn.Write(req)
	if err != nil {
		return nil, errors.Wrap(err, "sending dns request")
	}

	// Receive DNS response
	resBuffer := buffer.NewBytePacketBuffer()

	_, err = conn.Read(resBuffer.Buf)
	if err != nil {
		return nil, errors.Wrap(err, "reading dns server response")
	}

	resPacket, err := dns.DNSPacketFromBuffer(resBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "parsing dns server response")
	}

	res, _ := resBuffer.GetRangeAtPos()
	ioutil.WriteFile("response.txt", res, 0666)

	return resPacket, nil
}

func recursiveLookup(qName string, qType dns.QueryType) (*dns.DNSPacket, error) {
	ns := net.ParseIP("198.41.0.4")

	for {
		fmt.Printf("Attempting to lookup %s %s with ns %s\n", qType, qName, ns)
		nsCopy := ns
		response, err := lookup(qName, qType, nsCopy)
		if err != nil {
			return nil, errors.Wrap(err, "looking up query name")
		}

		// if there are answers and no errors return the response
		if len(response.Answers) != 0 && response.Header.ResCode == dns.NoError {
			return response, nil
		}

		// If response code is NXDomain it means domain name doesn't exists, we
		// return the response
		if response.Header.ResCode == dns.NxDomain {
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

		recursiveResponse, err := recursiveLookup(newNSName, dns.AQueryType)
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

func handleQuery(udpConn net.PacketConn, reqBuffer *buffer.BytePacketBuffer, addr net.Addr) {
	request, err := dns.DNSPacketFromBuffer(reqBuffer)
	logAndExitIfErr("Error: initializing response: %s\n", err)

	// Uncomment for fixture generation
	// d, _ := reqBuffer.GetRangeAtPos()
	// requestFile := filepath.Join(
	// 	"pkg",
	// 	"testfixtures",
	// 	fmt.Sprintf("query_%s_packet.txt", request.Questions[0].QType.String()),
	// )
	// ioutil.WriteFile(requestFile, d, 0666)

	packet := dns.NewDNSPacket()
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
				packet.Answers = append(packet.Answers, ans)
			}

			for _, auth := range result.Authorities {
				packet.Authorities = append(packet.Authorities, auth)
			}

			for _, res := range result.Resources {
				packet.Resources = append(packet.Resources, res)
			}
		} else {
			fmt.Println(err)
			packet.Header.ResCode = dns.ServFail
		}
	} else {
		packet.Header.ResCode = dns.FormErr
	}

	resBuffer := buffer.NewBytePacketBuffer()
	err = packet.Write(resBuffer)
	logAndExitIfErr("Error: generating dns response packet: %s\n", err)

	data, err := resBuffer.GetRangeAtPos()
	logAndExitIfErr("Error: generating dns response packet: %s\n", err)

	// Uncomment for fixture generation
	// responseFile := filepath.Join(
	// 	"pkg",
	// 	"testfixtures",
	// 	fmt.Sprintf("response_%s_packet.txt", packet.Questions[0].QType.String()),
	// )
	// ioutil.WriteFile(responseFile, data, 0666)

	_, err = udpConn.WriteTo(data, addr)
	logAndExitIfErr("Error: sending response: %s\n", err)
}

func Serve(ctx context.Context) {
	// ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	// defer cancel()
	udpConn, err := net.ListenPacket("udp", ":2053")
	logAndExitIfErr("Error: receiving udp request: %s\n", err)
	defer udpConn.Close()

	for {
		fmt.Println("Waiting for requests...")
		reqBuffer := buffer.NewBytePacketBuffer()

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
