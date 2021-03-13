package dns_test

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	. "github.com/stretchr/testify/assert"

	"github.com/msarvar/godns/pkg/buffer"
	"github.com/msarvar/godns/pkg/dns"
)

func TestDNSPacket(t *testing.T) {
	t.Run("creating_request_question", func(t *testing.T) {
		packetBinary, err := ioutil.ReadFile(filepath.Join("../testfixtures", "query_a_packet.txt"))
		NoError(t, err, "failed read")
		buffer := buffer.NewBytePacketBuffer()
		buffer.Buf = packetBinary
		packet := dns.NewDNSPacket()
		packet.Read(buffer)

		Equal(t, uint16(1), packet.Header.Questions, "Questions must match")
		Equal(t, uint16(1), packet.Questions[0].Class, "ID must match")
	})

	t.Run("write_a_type_response", func(t *testing.T) {
		packetBinary, err := ioutil.ReadFile(filepath.Join("../testfixtures", "response_A_packet.txt"))
		NoError(t, err, "failed read")
		buffer := buffer.NewBytePacketBuffer()
		buffer.Buf = packetBinary
		packet := dns.NewDNSPacket()
		packet.Read(buffer)

		Equal(t, 1, int(packet.Header.Questions))
		Equal(t, 1, int(packet.Header.Answers))

		Equal(t, "www.google.com", packet.Questions[0].Name.String())
		Equal(t, dns.QueryType(1), packet.Questions[0].QType)

		Equal(t, dns.QueryType(1), packet.Answers[0].QType)
		Equal(t, "172.217.164.100", packet.Answers[0].Addr.String())
		Equal(t, "www.google.com", packet.Answers[0].Domain.String())
	})

	t.Run("write_cname_type_response", func(t *testing.T) {
		packetBinary, err := ioutil.ReadFile(filepath.Join("../testfixtures", "response_CNAME_packet.txt"))
		NoError(t, err, "failed read")
		buffer := buffer.NewBytePacketBuffer()
		buffer.Buf = packetBinary
		packet := dns.NewDNSPacket()
		packet.Read(buffer)

		Equal(t, 1, int(packet.Header.Questions))
		Equal(t, 1, int(packet.Header.Answers))
		Equal(t, 5, int(packet.Header.AuthoritativeEntries))
		Equal(t, 9, int(packet.Header.ResourceEntries))

		Equal(t, "www.yahoo.com", packet.Questions[0].Name.String())
		Equal(t, dns.QueryType(5), packet.Questions[0].QType)

		Equal(t, dns.QueryType(5), packet.Answers[0].QType)
		Equal(t, 0, len(packet.Answers[0].Addr))
		Equal(t, "www.yahoo.com", packet.Answers[0].Domain.String())

		Equal(t, 5, len(packet.Authorities))
		for _, a := range packet.Authorities {
			Equal(t, dns.NSQueryType, a.QType)
		}
		Equal(t, 9, len(packet.Resources))
	})

	t.Run("write_NX_type_response", func(t *testing.T) {
		packetBinary, err := ioutil.ReadFile(filepath.Join("../testfixtures", "response_NX_packet.txt"))
		NoError(t, err, "failed read")
		buffer := buffer.NewBytePacketBuffer()
		buffer.Buf = packetBinary
		packet := dns.NewDNSPacket()
		packet.Read(buffer)

		Equal(t, 1, int(packet.Header.Questions))
		Equal(t, 0, int(packet.Header.Answers))
		Equal(t, 1, int(packet.Header.AuthoritativeEntries))
		Equal(t, 0, int(packet.Header.ResourceEntries))

		Equal(t, "www.goa1o.com", packet.Questions[0].Name.String())
		Equal(t, dns.QueryType(1), packet.Questions[0].QType)

		Equal(t, 1, len(packet.Authorities))
		for _, a := range packet.Authorities {
			Equal(t, dns.SOAQueryType, a.QType)
		}
	})

	// TODO: Add tests for other query types
	// SOA, MX, NS, AAAA
}
