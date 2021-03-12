package dns

import (
	"fmt"

	"github.com/msarvar/godns/pkg/buffer"
	"github.com/pkg/errors"
)

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
	case SOAQueryType:
		return "SOA"
	default:
		return fmt.Sprintf("%v", int(q))
	}
}

const (
	UnknownQueryType QueryType = 0
	AQueryType       QueryType = 1
	NSQueryType      QueryType = 2
	CNAMEQueryType   QueryType = 5
	SOAQueryType     QueryType = 6
	MXQueryType      QueryType = 15
	AAAAQueryType    QueryType = 28
)

type DNSQuestion struct {
	Name  *buffer.DomainName
	Class uint16
	QType QueryType
}

func NewDNSQuestion(qname string, qtype QueryType) *DNSQuestion {
	return &DNSQuestion{
		Name:  buffer.NewDomainName(qname),
		Class: 1,
		QType: qtype,
	}
}

func (q *DNSQuestion) Read(buffer *buffer.BytePacketBuffer) error {
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
	c, err := buffer.Read16()
	if err != nil {
		return errors.Wrap(err, "reading dns question query class")
	}
	q.Class = c

	return nil
}

func (q *DNSQuestion) Write(buffer *buffer.BytePacketBuffer) error {
	err := buffer.WriteQname(q.Name)
	if err != nil {
		return errors.Wrap(err, "writing qname")
	}

	err = buffer.Write16(uint16(q.QType))
	if err != nil {
		return errors.Wrap(err, "writing query type")
	}

	// Class of the DNSQuestion in practise always 1
	err = buffer.Write16(q.Class)
	if err != nil {
		return errors.Wrap(err, "writing query class")
	}

	return nil
}
