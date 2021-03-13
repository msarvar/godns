package dns

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	buf "github.com/msarvar/godns/pkg/buffer"
	"github.com/pkg/errors"
)

type DNSPacket struct {
	Header      *DNSHeader
	Questions   []*DNSQuestion
	Answers     []*DNSRecord
	Authorities []*DNSRecord
	Resources   []*DNSRecord
}

func NewDNSPacket() *DNSPacket {
	return &DNSPacket{
		Header: NewDNSHeader(),
	}
}

func (p *DNSPacket) String() string {

	qStr := make([]string, 0)
	for _, q := range p.Questions {
		qStr = append(qStr, fmt.Sprintf("%+v", q))
	}

	answers := make([]string, 0)
	for _, q := range p.Answers {
		answers = append(answers, fmt.Sprintf("%+v", q))
	}

	authorities := make([]string, 0)
	for _, q := range p.Authorities {
		authorities = append(authorities, fmt.Sprintf("%+v", q))
	}

	resources := make([]string, 0)
	for _, q := range p.Resources {
		resources = append(resources, fmt.Sprintf("%+v", q))
	}

	return fmt.Sprintf("Header: %+v\nQuestions: [%s]\nAnswers: [%s]\nAuthorities: [%s]\nResources [%s]",
		p.Header,
		strings.Join(qStr, ","),
		strings.Join(answers, ","),
		strings.Join(authorities, ","),
		strings.Join(resources, ","),
	)
}

func (p *DNSPacket) Read(buffer *buf.BytePacketBuffer) error {
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

func (p *DNSPacket) Write(buffer *buf.BytePacketBuffer) error {
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

	for _, auth := range p.Authorities {
		_, err = auth.Write(buffer)
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

func (p *DNSPacket) GetRandomA() net.IP {
	rand.Seed(time.Now().UnixNano())

	aRecords := make([]*DNSRecord, 0)
	for _, record := range p.Answers {
		if record.QType == AQueryType {
			aRecords = append(aRecords, record)
		}
	}

	if len(aRecords) == 0 {
		return nil
	}

	randRecord := aRecords[rand.Intn(len(aRecords))]
	return randRecord.Addr
}

type DomainHostTuple []string

func (p *DNSPacket) getNS(qname string) []DomainHostTuple {
	domainHostTuple := make([]DomainHostTuple, 0)

	for _, record := range p.Authorities {
		if record.QType == NSQueryType && strings.HasSuffix(qname, record.Domain.String()) {
			domainHostTuple = append(
				domainHostTuple,
				DomainHostTuple{
					record.Domain.String(),
					record.Host.String(),
				})
		}
	}

	return domainHostTuple
}

func (p *DNSPacket) GetResolverNS(qname string) net.IP {
	for _, tuple := range p.getNS(qname) {
		for _, r := range p.Resources {
			if r.QType == AQueryType && tuple[1] == r.Domain.String() {
				return r.Addr
			}
		}
	}
	return nil
}

func (p *DNSPacket) GetUnresolvedNS(qname string) string {
	for _, tuple := range p.getNS(qname) {
		if tuple[1] != "" {
			return tuple[1]
		}
	}

	return ""
}

func DNSPacketFromBuffer(buffer *buf.BytePacketBuffer) (*DNSPacket, error) {
	packet := NewDNSPacket()

	err := packet.Read(buffer)
	if err != nil {
		return nil, err
	}

	return packet, nil
}
