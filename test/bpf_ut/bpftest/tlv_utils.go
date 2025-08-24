package bpftests

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
)

// TLV protocol constants and structs
const (
	TLV_ORG_DST_ADDR_TYPE = 0x01
	TLV_PAYLOAD_TYPE      = 0xFE
	TLV_END_LENGTH        = 0x00000000
)

// TLV header structure
type TLVHeader struct {
	Type   uint8
	Length uint32
}

// TLV data content
type TLVData struct {
	IP   net.IP
	Port uint16
}

// ParseTLVMessage: parse TLV message
func ParseTLVMessage(data []byte) (*TLVData, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("data too short for TLV format: got %d bytes, need at least 16", len(data))
	}

	// parse TLV header
	header := TLVHeader{
		Type:   data[0],
		Length: binary.BigEndian.Uint32(data[1:5]),
	}

	// test
	if header.Type != TLV_ORG_DST_ADDR_TYPE {
		return nil, fmt.Errorf("unexpected TLV type: got %#x, want %#x", header.Type, TLV_ORG_DST_ADDR_TYPE)
	}

	var tlvData TLVData
	var expectedMinSize int

	if header.Length == 6 {

		if len(data) < 16 {
			return nil, fmt.Errorf("IPv4 TLV data too short: got %d bytes, need at least 16", len(data))
		}

		tlvData.IP = net.IPv4(data[5], data[6], data[7], data[8])
		tlvData.Port = binary.BigEndian.Uint16(data[9:11])
		expectedMinSize = 16

	} else if header.Length == 18 {

		if len(data) < 28 {
			return nil, fmt.Errorf("IPv6 TLV data too short: got %d bytes, need at least 28", len(data))
		}

		tlvData.IP = net.IP(data[5:21])
		tlvData.Port = binary.BigEndian.Uint16(data[21:23])
		expectedMinSize = 28

	} else {
		return nil, fmt.Errorf("unsupported TLV length: %d (expected 6 for IPv4 or 18 for IPv6)", header.Length)
	}

	if len(data) < expectedMinSize {
		return nil, fmt.Errorf("data too short for end tag validation: got %d bytes, need at least %d", len(data), expectedMinSize)
	}

	endTag := data[expectedMinSize-5]
	if endTag != TLV_PAYLOAD_TYPE {
		return nil, fmt.Errorf("missing or wrong TLV end tag: got %#x, want %#x", endTag, TLV_PAYLOAD_TYPE)
	}

	endLength := binary.BigEndian.Uint32(data[expectedMinSize-4 : expectedMinSize])
	if endLength != TLV_END_LENGTH {
		return nil, fmt.Errorf("unexpected TLV end length: got %#08x, want %#08x", endLength, TLV_END_LENGTH)
	}

	return &tlvData, nil
}

// verify the integrity and correctness of the TLV message
func ValidateTLVMessage(t *testing.T, data []byte, expectedIP net.IP, expectedPort uint16) error {
	tlvData, err := ParseTLVMessage(data)
	if err != nil {
		return fmt.Errorf("failed to parse TLV message: %v", err)
	}

	if !tlvData.IP.Equal(expectedIP) {
		return fmt.Errorf("unexpected TLV IP: got %v, want %v", tlvData.IP, expectedIP)
	}

	if tlvData.Port != expectedPort {
		return fmt.Errorf("unexpected TLV port: got %d, want %d", tlvData.Port, expectedPort)
	}

	t.Logf("TLV message validation successful: IP=%v, Port=%d", tlvData.IP, tlvData.Port)
	return nil
}
