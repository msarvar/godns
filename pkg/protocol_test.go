package pkg_test

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	. "github.com/stretchr/testify/assert"

	"github.com/msarvar/godns/pkg"
)

func TestDNSPacket(t *testing.T) {
	t.Run("creating request question", func(t *testing.T) {
		packetBinary, _ := ioutil.ReadFile(filepath.Join("testfixtures", "query_packet.txt"))
		buffer := pkg.NewBytePacketBuffer()
		buffer.Buf = packetBinary
		packet := pkg.NewDNSPacket()
		packet.Read(buffer)

		Equal(t, uint16(44023), packet.Header.ID, "ID must match")
		Equal(t, uint16(1), packet.Header.Questions, "Questions must match")
		Equal(t, uint16(1), packet.Questions[0].Class, "ID must match")
	})
}
