package ldap

import (
	"errors"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

var (
	errRespChanClosed = errors.New("ldap: response channel closed")
	errCouldNotRetMsg = errors.New("ldap: could not retrieve message")
	ErrNilConnection  = errors.New("ldap: conn is nil, expected net.Conn")
)

type request interface {
	appendTo(*ber.Packet) error
}

type requestFunc func(*ber.Packet) error

func (f requestFunc) appendTo(p *ber.Packet) error {
	return f(p)
}

func (l *Conn) doRequest(req request) (*messageContext, error) {
	if l == nil || l.conn == nil {
		return nil, ErrNilConnection
	}

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, l.nextMessageID(), "MessageID"))
	if err := req.appendTo(packet); err != nil {
		return nil, err
	}

	if l.Debug {
		l.Debug.PrintPacket(packet)
	}

	msgCtx, err := l.sendMessage(packet)
	if err != nil {
		return nil, err
	}
	l.Debug.Printf("%d: returning", msgCtx.id)
	return msgCtx, nil
}

func (l *Conn) readPacket(msgCtx *messageContext) (*ber.Packet, error) {
	l.Debug.Printf("%d: waiting for response", msgCtx.id)
	packetResponse, ok := <-msgCtx.responses
	if !ok {
		return nil, NewError(ErrorNetwork, errRespChanClosed)
	}
	packet, err := packetResponse.ReadPacket()
	l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if err != nil {
		return nil, err
	}

	if packet == nil {
		return nil, NewError(ErrorNetwork, errCouldNotRetMsg)
	}

	if l.Debug {
		if err = addLDAPDescriptions(packet); err != nil {
			return nil, err
		}
		l.Debug.PrintPacket(packet)
	}
	return packet, nil
}

func getReferral(err error, packet *ber.Packet) (referral string, e error) {
	if !IsErrorWithCode(err, LDAPResultReferral) {
		return "", nil
	}

	if len(packet.Children) < 2 {
		return "", fmt.Errorf("ldap: returned error indicates the packet contains a referral but it doesn't have sufficient child nodes: %w", err)
	}

	if packet.Children[1].Tag != ber.TagObjectDescriptor {
		return "", fmt.Errorf("ldap: returned error indicates the packet contains a referral but the relevant child node isn't an object descriptor: %w", err)
	}

	var ok bool

	for _, child := range packet.Children[1].Children {
		if child.Tag == ber.TagBitString && len(child.Children) >= 1 {
			if referral, ok = child.Children[0].Value.(string); ok {
				return referral, nil
			}
		}
	}

	return "", fmt.Errorf("ldap: returned error indicates the packet contains a referral but the referral couldn't be decoded: %w", err)
}
