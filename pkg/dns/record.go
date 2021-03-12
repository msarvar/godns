package dns

import (
	"fmt"
	"net"

	bufHandler "github.com/msarvar/godns/pkg/buffer"
	"github.com/pkg/errors"
)

type DNSRecord struct {
	QType    QueryType
	Domain   *bufHandler.DomainName
	Host     *bufHandler.DomainName
	MailHost *bufHandler.DomainName
	Serial   uint32
	Refresh  uint32
	Retry    uint32
	Expire   uint32
	Minimum  uint32
	Class    uint16
	Priority uint16
	Addr     net.IP
	TTL      uint32
	DataLen  uint16
}

func (r *DNSRecord) String() string {
	return fmt.Sprintf(`
%s: {
	Addr: %s,
	Host: %s,
	Domain: %s,
	MailHost: %s,
}`, r.QType, r.Addr, r.Host, r.Domain, r.MailHost)
}

func (r *DNSRecord) convertTo32to8(value uint32) []byte {
	return []byte{
		byte(value >> 24 & 0xFF),
		byte(value >> 16 & 0xFF),
		byte(value >> 8 & 0xFF),
		byte(value >> 0 & 0xFF),
	}
}

func (r *DNSRecord) Read(buffer *bufHandler.BytePacketBuffer) error {
	var domain bufHandler.DomainName
	err := buffer.ReadQname(&domain)
	if err != nil {
		return errors.Wrap(err, "reading dns record domain name")
	}
	r.Domain = &domain

	qtype_num, err := buffer.Read16()
	fmt.Printf("Query Type: %s, Num: %d\n", QueryType(qtype_num), qtype_num)
	if err != nil {
		return errors.Wrap(err, "reading dns record query type")
	}
	r.QType = QueryType(qtype_num)

	class, err := buffer.Read16()
	if err != nil {
		return errors.Wrap(err, "reading dns record class")
	}
	r.Class = class

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
		ns := bufHandler.NewDomainName("")
		err := buffer.ReadQname(ns)
		if err != nil {
			return errors.Wrap(err, "reading dns record nameserver")
		}

		r.Host = ns
	case CNAMEQueryType:
		cname := bufHandler.NewDomainName("")
		err := buffer.ReadQname(cname)
		if err != nil {
			return errors.Wrap(err, "reading dns record host")
		}

		r.Host = cname
	case SOAQueryType:
		host := bufHandler.NewDomainName("")
		err := buffer.ReadQname(host)
		if err != nil {
			return errors.Wrap(err, "reading dns record host")
		}
		r.Host = host

		mailHost := bufHandler.NewDomainName("")
		err = buffer.ReadQname(mailHost)
		if err != nil {
			return errors.Wrap(err, "reading dns record host")
		}
		r.MailHost = mailHost

		serial, err := buffer.Read32()
		if err != nil {
			return errors.Wrap(err, "reading dns record serial")
		}
		r.Serial = serial

		refresh, err := buffer.Read32()
		if err != nil {
			return errors.Wrap(err, "reading dns record refresh")
		}
		r.Refresh = refresh

		retry, err := buffer.Read32()
		if err != nil {
			return errors.Wrap(err, "reading dns record retry")
		}
		r.Retry = retry

		expire, err := buffer.Read32()
		if err != nil {
			return errors.Wrap(err, "reading dns record expire")
		}
		r.Expire = expire

		minimum, err := buffer.Read32()
		if err != nil {
			return errors.Wrap(err, "reading dns record minimum")
		}
		r.Minimum = minimum
	case AAAAQueryType:
		ipv6Addr := make(net.IP, 0)

		rawAddr1, err := buffer.Read32()
		if err != nil {
			return errors.Wrap(err, "reading dns record ip address")
		}

		for _, b := range r.convertTo32to8(rawAddr1) {
			ipv6Addr = append(ipv6Addr, b)
		}

		rawAddr2, err := buffer.Read32()
		if err != nil {
			return errors.Wrap(err, "reading dns record ip address")
		}
		for _, b := range r.convertTo32to8(rawAddr2) {
			ipv6Addr = append(ipv6Addr, b)
		}

		rawAddr3, err := buffer.Read32()
		if err != nil {
			return errors.Wrap(err, "reading dns record ip address")
		}
		for _, b := range r.convertTo32to8(rawAddr3) {
			ipv6Addr = append(ipv6Addr, b)
		}

		rawAddr4, err := buffer.Read32()
		if err != nil {
			return errors.Wrap(err, "reading dns record ip address")
		}
		for _, b := range r.convertTo32to8(rawAddr4) {
			ipv6Addr = append(ipv6Addr, b)
		}

		r.Addr = ipv6Addr
	case MXQueryType:
		priority, err := buffer.Read16()
		if err != nil {
			return errors.Wrap(err, "reading mail server priority")
		}

		mx := &bufHandler.DomainName{}
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

func (r *DNSRecord) Write(buffer *bufHandler.BytePacketBuffer) (int, error) {
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
	err = buffer.Write16(r.Class)
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
	case SOAQueryType:
		pos := buffer.Pos()

		// Setting mock to data len to make sure it bytes are in right order
		err = buffer.Write16(0)
		if err != nil {
			return 0, errors.Wrap(err, "setting datalen SOA type")
		}

		err = buffer.WriteQname(r.Host)
		if err != nil {
			return 0, errors.Wrap(err, "setting SOA host")
		}

		err = buffer.WriteQname(r.MailHost)
		if err != nil {
			return 0, errors.Wrap(err, "setting SOA mailing host")
		}

		err = buffer.Write32(r.Serial)
		if err != nil {
			return 0, errors.Wrap(err, "setting SOA serial number")
		}

		err = buffer.Write32(r.Refresh)
		if err != nil {
			return 0, errors.Wrap(err, "setting SOA refresh number")
		}

		err = buffer.Write32(r.Retry)
		if err != nil {
			return 0, errors.Wrap(err, "setting SOA retry number")
		}

		err = buffer.Write32(r.Expire)
		if err != nil {
			return 0, errors.Wrap(err, "setting SOA expire number")
		}

		err = buffer.Write32(r.Minimum)
		if err != nil {
			return 0, errors.Wrap(err, "setting SOA minimum number")
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

		for _, bt := range r.Addr.To16() {
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
