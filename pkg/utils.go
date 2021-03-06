package pkg

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

const (
	MAX_JUMPS = 5
)

func BoolToUint8(value bool) uint8 {
	var converted uint8
	if value {
		converted = 1
	}

	return converted
}

func NewBytePacketBuffer() *BytePacketBuffer {
	return &BytePacketBuffer{
		Buf: make([]uint8, 512),
		pos: 0,
	}
}

type BytePacketBuffer struct {
	Buf []uint8
	pos int
}

func (b *BytePacketBuffer) Pos() int {
	return b.pos
}

func (b *BytePacketBuffer) Steps(steps int) {
	b.pos += steps
}

func (b *BytePacketBuffer) Seek(pos int) {
	b.pos = pos
}

func (b *BytePacketBuffer) Get(pos int) (uint8, error) {
	if pos >= 512 {
		return 0, errors.New("End of buffer")
	}

	return b.Buf[pos], nil
}

func (b *BytePacketBuffer) GetRange(start int, len int) ([]uint8, error) {
	if start+len >= 512 {
		return nil, errors.New("End of buffer")
	}

	return b.Buf[start : start+len], nil
}

func (b *BytePacketBuffer) Read() (uint8, error) {
	if b.pos >= 512 {
		return 0, errors.New("end of buffer")
	}

	res := b.Buf[b.pos]
	b.pos += 1

	return res, nil
}

func (b *BytePacketBuffer) Read16() (uint16, error) {
	f, err := b.Read()
	if err != nil {
		return 0, err
	}

	s, err := b.Read()
	if err != nil {
		return 0, err
	}

	// Reading 2 bytes and converting to uint16
	//     f        s
	// 00000000 00000000 = 16 bits
	// Shifting first byte by 8 bits and adding second byte
	res := (uint16(f)<<8 | uint16(s))
	return res, nil
}

func (b *BytePacketBuffer) Read32() (uint32, error) {
	f, err := b.Read16()
	if err != nil {
		return 0, err
	}

	s, err := b.Read16()
	if err != nil {
		return 0, err
	}

	res := uint32(f)<<16 | uint32(s)
	return res, nil
}

func (b *BytePacketBuffer) ReadQname(outStr *outStr) error {
	pos := b.Pos()

	jumped := false
	jumps_performed := 0
	delim := ""

	for {
		if jumps_performed > MAX_JUMPS {
			return errors.New(fmt.Sprintf("Limit of %d max jumps exceeded", MAX_JUMPS))
		}

		len, err := b.Get(pos)
		if err != nil {
			return errors.Wrap(err, "reading query name")
		}

		// If two most significant bits(MSB) are set, it means jump is required
		// to other part of the packet.
		// 11000000 -> MSBs are set
		// 00001100 -> MSB are not set
		if (len & 0xC0) == 0xC0 {
			// If no jumps were performed put the cursor 2 positions ahead.
			if !jumped {
				b.Seek(pos + 2)
			}

			b2, err := b.Get(pos + 1)
			if err != nil {
				return errors.Wrap(err, "reading offset instructions")
			}
			// bitwise xor
			// 11000000^11000000 = 00000000
			offset := uint16(len^0xC0)<<8 | uint16(b2)
			pos = int(offset)

			// Jump was performed and loop continues to next part
			jumped = true
			jumps_performed += 1

			continue
		} else {
			pos += 1

			if len == 0 {
				break
			}

			outStr.str = fmt.Sprintf("%s%s", outStr.str, delim)
			str_buffer, err := b.GetRange(pos, int(len))
			if err != nil {
				return errors.Wrap(err, "reading the label")
			}
			outStr.str = fmt.Sprintf("%s%s", outStr.str, str_buffer)

			delim = "."

			pos += int(len)
		}
	}

	if !jumped {
		b.Seek(pos)
	}

	return nil
}

func (b *BytePacketBuffer) Write(value uint8) error {
	if b.pos >= 512 {
		return errors.New("end of buffer")
	}

	b.Buf[b.pos] = value
	b.pos += 1

	return nil
}

func (b *BytePacketBuffer) Write8(value uint8) error {
	return b.Write(value)
}

func (b *BytePacketBuffer) Write16(value uint16) error {
	err := b.Write(uint8(value >> 8))
	if err != nil {
		return err
	}

	return b.Write(uint8(value & 0xFF))
}

func (b *BytePacketBuffer) Write32(value uint32) error {
	err := b.Write(uint8((value >> 24) & 0xFF))
	if err != nil {
		return err
	}

	err = b.Write(uint8((value >> 16) & 0xFF))
	if err != nil {
		return err
	}

	err = b.Write(uint8((value >> 8) & 0xFF))
	if err != nil {
		return err
	}

	return b.Write(uint8(value & 0xFF))
}

func (b *BytePacketBuffer) WriteQname(qname string) error {
	for _, label := range strings.Split(qname, ".") {
		len := len(label)
		if len > 0x3f {
			return errors.New("single label exceeds 63 character of length")
		}

		err := b.Write8(uint8(len))
		if err != nil {
			return errors.Wrap(err, "writing single label")
		}
	}

	err := b.Write8(0)
	if err != nil {
		return errors.Wrap(err, "writing last byte")
	}

	return nil
}
