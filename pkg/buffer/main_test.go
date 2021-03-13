package buffer_test

import (
	"testing"

	"github.com/msarvar/godns/pkg/buffer"
	. "github.com/stretchr/testify/assert"
)

func TestNewBytePacketBuffer_WriteQname(t *testing.T) {
	t.Run("write_qname_without_jumps", func(t *testing.T) {
		buf := buffer.NewBytePacketBuffer()
		buf.WriteQname(buffer.NewDomainName("www.google.com"))
		// starts with length
		Equal(t, byte(3), buf.Buf[0])
		Equal(t, []byte("www"), buf.Buf[1:4])
		Equal(t, byte(6), buf.Buf[4])
		Equal(t, []byte("google"), buf.Buf[5:11])
		Equal(t, byte(3), buf.Buf[11])
		Equal(t, []byte("com"), buf.Buf[12:15])

	})

	t.Run("write_qname_with_jumps", func(t *testing.T) {
		buf := buffer.NewBytePacketBuffer()
		buf.WriteQname(buffer.NewDomainName("www.google.com"))
		buf.WriteQname(buffer.NewDomainName("www.google.com"))

		// MSB is set, instuction for jump
		Equal(t, byte(0xC0), buf.Buf[16])
		Equal(t, byte(0), buf.Buf[17])
	})

	t.Run("write_qname_with_complex_jumps", func(t *testing.T) {
		buf := buffer.NewBytePacketBuffer()
		buf.WriteQname(buffer.NewDomainName("www.google.com"))
		buf.WriteQname(buffer.NewDomainName("google.com"))

		// MSB is set, instuction for jump
		Equal(t, byte(0xC0), buf.Buf[16])
		Equal(t, byte(4), buf.Buf[17])
	})

	t.Run("write_two_qname_with_no_jumps", func(t *testing.T) {
		buf := buffer.NewBytePacketBuffer()
		buf.WriteQname(buffer.NewDomainName("www.google.com"))
		buf.WriteQname(buffer.NewDomainName("yahoo.com"))

		// MSB is set, instuction for jump
		// yahoo
		Equal(t, byte(5), buf.Buf[16])
		Equal(t, []byte("yahoo"), buf.Buf[17:22])
		// com
		Equal(t, byte(0xC0), buf.Buf[22])
		Equal(t, byte(11), buf.Buf[23])
	})
}

func TestNewBytePacketBuffer_ReadQname(t *testing.T) {
	t.Run("read_qname_without_jumps", func(t *testing.T) {
		buf := buffer.NewBytePacketBuffer()
		buf.WriteQname(buffer.NewDomainName("www.google.com"))
		buf.Seek(0)

		qname := buffer.NewDomainName("")
		buf.ReadQname(qname)
		// starts with length
		Equal(t, "www.google.com", qname.String())
	})

	t.Run("write_qname_with_jumps", func(t *testing.T) {
		buf := buffer.NewBytePacketBuffer()
		buf.WriteQname(buffer.NewDomainName("www.google.com"))
		buf.WriteQname(buffer.NewDomainName("www.google.com"))
		buf.Seek(0)

		// read the label name
		qname1 := buffer.NewDomainName("")
		buf.ReadQname(qname1)
		Equal(t, "www.google.com", qname1.String())

		// Read the second label with jumps
		qname2 := buffer.NewDomainName("")
		buf.ReadQname(qname2)
		Equal(t, "www.google.com", qname2.String())
	})

	t.Run("write_qname_with_complex_jumps", func(t *testing.T) {
		buf := buffer.NewBytePacketBuffer()
		buf.WriteQname(buffer.NewDomainName("www.google.com"))
		buf.WriteQname(buffer.NewDomainName("google.com"))
		buf.Seek(0)

		// read the label name
		qname1 := buffer.NewDomainName("")
		buf.ReadQname(qname1)
		Equal(t, "www.google.com", qname1.String())

		// Read the second label with jumps
		qname2 := buffer.NewDomainName("")
		buf.ReadQname(qname2)
		Equal(t, "google.com", qname2.String())
	})

	t.Run("write_two_qname_with_no_jumps", func(t *testing.T) {
		buf := buffer.NewBytePacketBuffer()
		buf.WriteQname(buffer.NewDomainName("www.google.com"))
		buf.WriteQname(buffer.NewDomainName("yahoo.com"))
		buf.Seek(0)

		// read the label name
		qname1 := buffer.NewDomainName("")
		buf.ReadQname(qname1)
		Equal(t, "www.google.com", qname1.String())

		// Read the second label with jumps
		qname2 := buffer.NewDomainName("")
		buf.ReadQname(qname2)
		Equal(t, "yahoo.com", qname2.String())
	})
}

func TestNewBytePacketBuffer_Write(t *testing.T) {
	t.Run("write_4_bytes", func(t *testing.T) {
		buf := buffer.NewBytePacketBuffer()
		buf.Write32(uint32(65535))

		// write 4 bytes
		Equal(t, 4, buf.Pos())

		// []byte{0,0,255,255} => 65535
		Equal(t, byte(0), buf.Buf[0])
		Equal(t, byte(0), buf.Buf[1])
		Equal(t, byte(255), buf.Buf[2])
		Equal(t, byte(255), buf.Buf[3])
	})
}
