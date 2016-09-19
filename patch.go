package main

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type myEAPOL struct {
	*layers.EAPOL
	Length uint16
}

func (e *myEAPOL) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, _ := b.PrependBytes(4)
	bytes[0] = e.Version
	bytes[1] = byte(e.Type)
	binary.BigEndian.PutUint16(bytes[2:], e.Length)
	return nil
}

func (e *myEAPOL) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	e.Version = data[0]
	e.Type = layers.EAPOLType(data[1])
	e.Length = binary.BigEndian.Uint16(data[2:4])
	e.BaseLayer = layers.BaseLayer{data[:4], data[4:]}
	return nil
}
