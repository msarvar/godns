package dns

import (
	"github.com/msarvar/godns/pkg/buffer"
	"github.com/msarvar/godns/pkg/utils"
	"github.com/pkg/errors"
)

type ResultCode int8

const (
	NoError ResultCode = iota
	FormErr
	ServFail
	NxDomain
	NoTimp
	Refused
)

// DNSPacketReadWriter implements dns packet reader and writer.
// Based on RFC1035 dns request/response should be 512 byte long
type DNSPacketReadWriter interface {
	// Read reads dns request of size 512 bytes and populates DNS structs
	Read(buffer *buffer.BytePacketBuffer) error
	// Write packs dns response values into 512 byte array
	Write(buffer *buffer.BytePacketBuffer) error
}

// DNSHeader contains header information.
// This should be 12 byte long header based on DNS RFC but golang doesn't have 4
// bit types. So ResultCode is 8bit int, bool types is also 8bits.
type DNSHeader struct {
	ID                   uint16
	RecursionDesired     bool
	TruncatedMessage     bool
	AuthoritativeAnswer  bool
	Opcode               uint8
	Response             bool
	ResCode              ResultCode
	CheckingDisabled     bool
	AuthedData           bool
	Z                    bool
	RecursionAvailable   bool
	Questions            uint16
	Answers              uint16
	AuthoritativeEntries uint16
	ResourceEntries      uint16
}

func NewDNSHeader() *DNSHeader {
	return &DNSHeader{
		ID: 0,

		RecursionDesired:    false,
		TruncatedMessage:    false,
		AuthoritativeAnswer: false,
		Opcode:              0,
		Response:            false,

		ResCode:            NoError,
		CheckingDisabled:   false,
		AuthedData:         false,
		Z:                  false,
		RecursionAvailable: false,

		Questions:            0,
		Answers:              0,
		AuthoritativeEntries: 0,
		ResourceEntries:      0,
	}
}

func (d *DNSHeader) Read(buffer *buffer.BytePacketBuffer) error {
	id, err := buffer.Read16()
	if err != nil {
		return errors.Wrap(err, "reading the header id")
	}
	d.ID = id

	flags, err := buffer.Read16()
	if err != nil {
		return errors.Wrap(err, "reading the header flags")
	}

	a := uint8(flags >> 8)
	b := uint8(flags & 0xFF)

	d.RecursionDesired = (a & (1 << 0)) > 0
	d.TruncatedMessage = (a & (1 << 1)) > 0
	d.AuthoritativeAnswer = (a & (1 << 2)) > 0
	d.Opcode = (a >> 3) & 0x0F
	d.Response = (a & (1 << 7)) > 0

	d.ResCode = d.GetResCode(b & 0x0F)
	d.CheckingDisabled = (b & (1 << 4)) > 0
	d.AuthedData = (b & (1 << 5)) > 0
	d.Z = (b & (1 << 6)) > 0
	d.RecursionAvailable = (b & (1 << 7)) > 0

	d.Questions, err = buffer.Read16()
	if err != nil {
		return errors.Wrap(err, "reading header question")
	}

	d.Answers, err = buffer.Read16()
	if err != nil {
		return errors.Wrap(err, "reading header answers")
	}

	d.AuthoritativeEntries, err = buffer.Read16()
	if err != nil {
		return errors.Wrap(err, "reading header authoritative entries")
	}

	d.ResourceEntries, err = buffer.Read16()
	if err != nil {
		return errors.Wrap(err, "reading header resource entries")
	}

	return nil
}

func (h *DNSHeader) Write(buffer *buffer.BytePacketBuffer) error {
	err := buffer.Write16(h.ID)
	if err != nil {
		return errors.Wrap(err, "writing dns header id")
	}

	err = buffer.Write8(utils.BoolToUint8(h.RecursionDesired) |
		(utils.BoolToUint8(h.TruncatedMessage) << 1) |
		(utils.BoolToUint8(h.AuthoritativeAnswer) << 2) |
		(h.Opcode << 3) |
		(utils.BoolToUint8(h.Response) << 7))
	if err != nil {
		return errors.Wrap(err, "writing dns header flags first byte")
	}

	err = buffer.Write8(uint8(h.ResCode) |
		utils.BoolToUint8(h.CheckingDisabled)<<4 |
		utils.BoolToUint8(h.AuthedData)<<5 |
		utils.BoolToUint8(h.Z)<<6 |
		utils.BoolToUint8(h.RecursionAvailable)<<7)
	if err != nil {
		return errors.Wrap(err, "writing dns header flags second byte")
	}

	err = buffer.Write16(h.Questions)
	if err != nil {
		return errors.Wrap(err, "writing dns header questions")
	}

	buffer.Write16(h.Answers)
	if err != nil {
		return errors.Wrap(err, "writing dns header answers")
	}

	buffer.Write16(h.AuthoritativeEntries)
	if err != nil {
		return errors.Wrap(err, "writing dns header authoritative entries")
	}

	buffer.Write16(h.ResourceEntries)
	if err != nil {
		return errors.Wrap(err, "writing dns header resource entries")
	}

	return nil
}

func (d *DNSHeader) GetResCode(code uint8) ResultCode {
	switch code {
	case 0:
		return NoError
	case 1:
		return FormErr
	case 2:
		return ServFail
	case 3:
		return NxDomain
	case 4:
		return NoTimp
	case 5:
		return Refused
	default:
		return NoError
	}
}
