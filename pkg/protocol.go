package pkg

import (
	"fmt"
	"net"

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
	Read(buffer *BytePacketBuffer) error
	// Write packs dns response values into 512 byte array
	Write(buffer *BytePacketBuffer) error
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

func (d *DNSHeader) Read(buffer *BytePacketBuffer) error {
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

func (h *DNSHeader) Write(buffer *BytePacketBuffer) error {
	err := buffer.Write16(h.ID)
	if err != nil {
		return errors.Wrap(err, "writing dns header id")
	}

	err = buffer.Write8(BoolToUint8(h.RecursionDesired) |
		(BoolToUint8(h.TruncatedMessage) << 1) |
		(BoolToUint8(h.AuthoritativeAnswer) << 2) |
		(h.Opcode << 3) |
		(BoolToUint8(h.Response) << 7))
	if err != nil {
		return errors.Wrap(err, "writing dns header flags first byte")
	}

	err = buffer.Write8(uint8(h.ResCode) |
		BoolToUint8(h.CheckingDisabled)<<4 |
		BoolToUint8(h.AuthedData)<<5 |
		BoolToUint8(h.Z)<<6 |
		BoolToUint8(h.RecursionAvailable)<<7)
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

type QueryType int

func (q QueryType) String() string {
	switch q {
	case AQueryType:
		return "A"
	case NSQueryType:
		return "NS"
	case MXQueryType:
		return "MX"
	case CNAMEQueryType:
		return "CNAME"
	case AAAAQueryType:
		return "AAAA"
	default:
		return fmt.Sprintf("%v", int(q))
	}
}

const (
	UnknownQueryType QueryType = 0
	AQueryType       QueryType = 1
	NSQueryType      QueryType = 2
	CNAMEQueryType   QueryType = 5
	MXQueryType      QueryType = 15
	AAAAQueryType    QueryType = 28
)

type domainName struct {
	str string
}

func (n *domainName) String() string {
	return n.str
}

type DNSQuestion struct {
	Name  *domainName
	QType QueryType
}

func NewDNSQuestion(qname string, qtype QueryType) *DNSQuestion {
	return &DNSQuestion{
		Name: &domainName{
			str: qname,
		},
		QType: qtype,
	}
}

func (q *DNSQuestion) Read(buffer *BytePacketBuffer) error {
	err := buffer.ReadQname(q.Name)
	if err != nil {
		return errors.Wrap(err, "reading dns question name")
	}

	// reading query type
	i, err := buffer.Read16()
	if err != nil {
		return errors.Wrap(err, "reading dns question query type")
	}
	q.QType = QueryType(i)

	// reading class
	_, err = buffer.Read16()
	if err != nil {
		return errors.Wrap(err, "reading dns question query class")
	}

	return nil
}

func (q *DNSQuestion) Write(buffer *BytePacketBuffer) error {
	err := buffer.WriteQname(q.Name)
	if err != nil {
		return errors.Wrap(err, "writing qname")
	}

	err = buffer.Write16(uint16(q.QType))
	if err != nil {
		return errors.Wrap(err, "writing query type")
	}

	// Class of the DNSQuestion in practise always 1
	err = buffer.Write16(1)
	if err != nil {
		return errors.Wrap(err, "writing query class")
	}

	return nil
}

type DNSRecord struct {
	QType    QueryType
	Domain   *domainName
	Host     *domainName
	Priority uint16
	Addr     net.IP
	TTL      uint32
	DataLen  uint16
}

func (r *DNSRecord) convertTo32to8(value uint32) (byte, byte, byte, byte) {
	return byte(value >> 24 & 0xFF), byte(value >> 16 & 0xFF), byte(value >> 8 & 0xFF), byte(value >> 0 & 0xFF)
}

func (r *DNSRecord) Read(buffer *BytePacketBuffer) error {
	var domain domainName
	err := buffer.ReadQname(&domain)
	if err != nil {
		return errors.Wrap(err, "reading dns record domain name")
	}
	r.Domain = &domain

	qtype_num, err := buffer.Read16()
	if err != nil {
		return errors.Wrap(err, "reading dns record query type")
	}

	r.QType = QueryType(qtype_num)

	_, err = buffer.Read16()
	if err != nil {
		return errors.Wrap(err, "reading dns record class")
	}

	ttl, err := buffer.Read32()
	if err != nil {
		return errors.Wrap(err, "reading dns record ttl")
	}
	r.TTL = ttl

	dataLen, err := buffer.Read16()
	if err != nil {
		return errors.Wrap(err, "reading dns record data_len")
	}

	switch r.QType {
	case AQueryType:
		rawIpv4Addr, err := buffer.Read32()
		if err != nil {
			return errors.Wrap(err, "reading dns record ip address")
		}

		r.Addr = net.IPv4(
			byte(rawIpv4Addr>>24&0xFF),
			byte(rawIpv4Addr>>16&0xFF),
			byte(rawIpv4Addr>>8&0xFF),
			byte(rawIpv4Addr>>0&0xFF),
		)
	case NSQueryType:
		ns := &domainName{}
		err := buffer.ReadQname(ns)
		if err != nil {
			return errors.Wrap(err, "reading dns record nameserver")
		}

		r.Host = ns
	case CNAMEQueryType:
		cname := &domainName{}
		err := buffer.ReadQname(cname)
		if err != nil {
			return errors.Wrap(err, "reading dns record host")
		}

		r.Host = cname
	case AAAAQueryType:
		ipv6Addr := make(net.IP, 0)

		rawAddr1, err := buffer.Read32()
		if err != nil {
			return errors.Wrap(err, "reading dns record ip address")
		}

		ipv6Addr = append(ipv6Addr,
			byte(rawAddr1>>24&0xFF),
			byte(rawAddr1>>16&0xFF),
			byte(rawAddr1>>8&0xFF),
			byte(rawAddr1>>0&0xFF))

		rawAddr2, err := buffer.Read32()
		if err != nil {
			return errors.Wrap(err, "reading dns record ip address")
		}
		ipv6Addr = append(ipv6Addr,
			byte(rawAddr2>>24&0xFF),
			byte(rawAddr2>>16&0xFF),
			byte(rawAddr2>>8&0xFF),
			byte(rawAddr2>>0&0xFF))

		rawAddr3, err := buffer.Read32()
		if err != nil {
			return errors.Wrap(err, "reading dns record ip address")
		}
		ipv6Addr = append(ipv6Addr,
			byte(rawAddr3>>24&0xFF),
			byte(rawAddr3>>16&0xFF),
			byte(rawAddr3>>8&0xFF),
			byte(rawAddr3>>0&0xFF))

		rawAddr4, err := buffer.Read32()
		if err != nil {
			return errors.Wrap(err, "reading dns record ip address")
		}
		ipv6Addr = append(ipv6Addr,
			byte(rawAddr4>>24&0xFF),
			byte(rawAddr4>>16&0xFF),
			byte(rawAddr4>>8&0xFF),
			byte(rawAddr4>>0&0xFF))

		fmt.Println(len(ipv6Addr), net.IPv6len)

		r.Addr = ipv6Addr
	case MXQueryType:
		priority, err := buffer.Read16()
		if err != nil {
			return errors.Wrap(err, "reading mail server priority")
		}

		mx := &domainName{}
		err = buffer.ReadQname(mx)
		if err != nil {
			return errors.Wrap(err, "reading mail server name")
		}

		r.Host = mx
		r.Priority = priority
	default:
		// Ensure position is set to after the datalen
		buffer.Steps(int(dataLen))
		r.DataLen = dataLen
	}

	return nil
}

func (r *DNSRecord) Write(buffer *BytePacketBuffer) (int, error) {
	startPos := buffer.Pos()

	err := buffer.WriteQname(r.Domain)
	if err != nil {
		return 0, errors.Wrap(err, "writing dns record domain name")
	}

	err = buffer.Write16(uint16(r.QType))
	if err != nil {
		return 0, errors.Wrap(err, "writing dns record query type")
	}

	// DNS Record Class which always 1
	err = buffer.Write16(1)
	if err != nil {
		return 0, errors.Wrap(err, "writing dns record class")
	}

	err = buffer.Write32(r.TTL)
	if err != nil {
		return 0, errors.Wrap(err, "writing dns record TTL")
	}

	switch r.QType {
	case AQueryType:
		err = buffer.Write16(4)
		if err != nil {
			return 0, errors.Wrap(err, "setting datalen A type")
		}

		addrRaw := r.Addr.To4()
		err = buffer.Write8(addrRaw[0])
		if err != nil {
			return 0, errors.Wrap(err, "reading first byte of dns record ip")
		}

		err = buffer.Write8(addrRaw[1])
		if err != nil {
			return 0, errors.Wrap(err, "reading second byte of dns record ip")
		}

		err = buffer.Write8(addrRaw[2])
		if err != nil {
			return 0, errors.Wrap(err, "reading third byte of dns record ip")
		}

		err = buffer.Write8(addrRaw[3])
		if err != nil {
			return 0, errors.Wrap(err, "reading fourth byte of dns record ip")
		}
	case NSQueryType:
		pos := buffer.Pos()

		// Setting mock to data len to make sure it bytes are in right order
		err = buffer.Write16(0)
		if err != nil {
			return 0, errors.Wrap(err, "setting datalen NS type")
		}

		err = buffer.WriteQname(r.Host)
		if err != nil {
			return 0, errors.Wrap(err, "setting nameserver host")
		}

		sizeu16 := uint16(buffer.Pos() - (pos + 2))
		buffer.Set16(pos, sizeu16)
	case CNAMEQueryType:
		pos := buffer.Pos()

		// Setting mock to data len to make sure it bytes are in right order
		err = buffer.Write16(0)
		if err != nil {
			return 0, errors.Wrap(err, "setting datalen CNAME type")
		}

		err = buffer.WriteQname(r.Host)
		if err != nil {
			return 0, errors.Wrap(err, "setting CNAME host")
		}

		// Update data len to actual value
		sizeu16 := uint16(buffer.Pos() - (pos + 2))
		buffer.Set16(pos, sizeu16)
	case MXQueryType:
		pos := buffer.Pos()

		// Setting mock to data len to make sure it bytes are in right order
		err = buffer.Write16(0)
		if err != nil {
			return 0, errors.Wrap(err, "setting datalen MX type")
		}

		err = buffer.Write16(r.Priority)
		if err != nil {
			return 0, errors.Wrap(err, "setting priority")
		}

		err = buffer.WriteQname(r.Host)
		if err != nil {
			return 0, errors.Wrap(err, "setting nameserver host")
		}

		sizeu16 := uint16(buffer.Pos() - (pos + 2))
		buffer.Set16(pos, sizeu16)
	case AAAAQueryType:
		err = buffer.Write16(16)
		if err != nil {
			return 0, errors.Wrap(err, "setting datalen for AAAA type")
		}

		for _, bt := range r.Addr {
			err = buffer.Write8(bt)
			if err != nil {
				return 0, errors.Wrap(err, "setting ipv6 value")
			}
		}
	default:
		fmt.Printf("Skipping record: %+v\n", r)
	}

	return buffer.Pos() - startPos, nil
}

type DNSPacket struct {
	Header      *DNSHeader
	Questions   []*DNSQuestion
	Answers     []*DNSRecord
	Authorities []*DNSRecord
	Resources   []*DNSRecord
}

func NewDNSPacket() *DNSPacket {
	return &DNSPacket{
		Header:      NewDNSHeader(),
		Answers:     make([]*DNSRecord, 0),
		Authorities: make([]*DNSRecord, 0),
		Resources:   make([]*DNSRecord, 0),
	}
}

func (p *DNSPacket) Read(buffer *BytePacketBuffer) error {
	err := p.Header.Read(buffer)
	if err != nil {
		return errors.Wrap(err, "reading header")
	}

	questions := make([]*DNSQuestion, 0)
	for i := 0; i < int(p.Header.Questions); i++ {
		question := NewDNSQuestion("", UnknownQueryType)
		err := question.Read(buffer)
		if err != nil {
			return errors.Wrap(err, "reading dns question")
		}

		questions = append(questions, question)
	}
	p.Questions = questions

	answers := make([]*DNSRecord, 0)
	for i := 0; i < int(p.Header.Answers); i++ {
		rec := DNSRecord{}
		err := rec.Read(buffer)
		if err != nil {
			return errors.Wrap(err, "reading dns record answers")
		}

		answers = append(answers, &rec)
	}
	p.Answers = answers

	authorities := make([]*DNSRecord, 0)
	for i := 0; i < int(p.Header.AuthoritativeEntries); i++ {
		rec := DNSRecord{}
		err := rec.Read(buffer)
		if err != nil {
			return errors.Wrap(err, "reading dns record authoritative entries")
		}

		authorities = append(authorities, &rec)
	}
	p.Authorities = authorities

	resources := make([]*DNSRecord, 0)
	for i := 0; i < int(p.Header.ResourceEntries); i++ {
		rec := DNSRecord{}
		err := rec.Read(buffer)
		if err != nil {
			return errors.Wrap(err, "reading dns record resources")
		}

		resources = append(resources, &rec)
	}
	p.Resources = resources

	return nil
}

func (p *DNSPacket) Write(buffer *BytePacketBuffer) error {
	// Populating packet header with right array length for questions, answers,
	// authEntries, and resourceEntries
	p.Header.Questions = uint16(len(p.Questions))
	p.Header.Answers = uint16(len(p.Answers))
	p.Header.AuthoritativeEntries = uint16(len(p.Authorities))
	p.Header.ResourceEntries = uint16(len(p.Resources))

	err := p.Header.Write(buffer)
	if err != nil {
		return errors.Wrap(err, "writing header information")
	}

	for _, q := range p.Questions {
		err = q.Write(buffer)
		if err != nil {
			return errors.Wrap(err, "updating packet with questions")
		}
	}

	for _, a := range p.Answers {
		_, err = a.Write(buffer)
		if err != nil {
			return errors.Wrap(err, "updating packet with answers")
		}
	}

	for _, a := range p.Authorities {
		_, err = a.Write(buffer)
		if err != nil {
			return errors.Wrap(err, "updating packet with authoritative answers")
		}
	}

	for _, r := range p.Resources {
		_, err = r.Write(buffer)
		if err != nil {
			return errors.Wrap(err, "updating packet with resource entries")
		}
	}

	return nil
}

func DNSPacketFromBuffer(buffer *BytePacketBuffer) (*DNSPacket, error) {
	packet := NewDNSPacket()

	err := packet.Read(buffer)
	if err != nil {
		return nil, err
	}

	return packet, nil
}
