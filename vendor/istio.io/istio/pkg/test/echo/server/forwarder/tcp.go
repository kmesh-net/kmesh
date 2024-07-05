// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package forwarder

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	proxyproto "github.com/pires/go-proxyproto"

	"istio.io/istio/pkg/hbone"
	"istio.io/istio/pkg/test/echo"
	"istio.io/istio/pkg/test/echo/common"
	"istio.io/istio/pkg/test/echo/proto"
)

var _ protocol = &tcpProtocol{}

type tcpProtocol struct {
	e *executor
}

func newTCPProtocol(e *executor) protocol {
	return &tcpProtocol{e: e}
}

func (c *tcpProtocol) ForwardEcho(ctx context.Context, cfg *Config) (*proto.ForwardEchoResponse, error) {
	return doForward(ctx, cfg, c.e, c.makeRequest)
}

func (c *tcpProtocol) makeRequest(ctx context.Context, cfg *Config, requestID int) (string, error) {
	conn, err := newTCPConnection(cfg)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()

	msgBuilder := strings.Builder{}
	// If we have been asked to do TCP comms with a PROXY protocol header,
	// determine which version, and send the header.
	// https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
	//
	// PROXY protocol is only for L4 TCP traffic, and the magic string/bytes MUST
	// be written at the BEGINNING of the TCP connection if communicating with a PROXY-protocol enabled server.
	if cfg.proxyProtocolVersion != 0 {
		fwLog.Infof("TCP forwarder using PROXY protocol version %d", cfg.proxyProtocolVersion)
		header := proxyproto.HeaderProxyFromAddrs(byte(cfg.proxyProtocolVersion), conn.LocalAddr(), conn.RemoteAddr())
		// After the connection is created, write the proxy headers first
		if _, err := header.WriteTo(conn); err != nil {
			fwLog.Warnf("TCP Proxy protocol header write failed: %v", err)
			return msgBuilder.String(), err
		}
	}

	echo.ForwarderURLField.WriteForRequest(&msgBuilder, requestID, cfg.Request.Url)

	if cfg.Request.Message != "" {
		echo.ForwarderMessageField.WriteForRequest(&msgBuilder, requestID, cfg.Request.Message)
	}

	// Apply per-request timeout to calculate deadline for reads/writes.
	ctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	// Apply the deadline to the connection.
	deadline, _ := ctx.Deadline()
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return msgBuilder.String(), err
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return msgBuilder.String(), err
	}

	// For server first protocol, we expect the server to send us the magic string first
	if cfg.Request.ServerFirst {
		readBytes, err := bufio.NewReader(conn).ReadBytes('\n')
		if err != nil {
			fwLog.Warnf("server first TCP read failed: %v", err)
			return "", err
		}
		if string(readBytes) != common.ServerFirstMagicString {
			return "", fmt.Errorf("did not receive magic string. Want %q, got %q", common.ServerFirstMagicString, string(readBytes))
		}
	}

	// Make sure the client writes something to the buffer
	message := "HelloWorld"
	if cfg.Request.Message != "" {
		message = cfg.Request.Message
	}

	if _, err := conn.Write([]byte(message + "\n")); err != nil {
		fwLog.Warnf("TCP write failed: %v", err)
		return msgBuilder.String(), err
	}
	var resBuffer bytes.Buffer
	buf := make([]byte, 1024+len(message))
	for {
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			fwLog.Warnf("TCP read failed (already read %d bytes): %v", len(resBuffer.String()), err)
			return msgBuilder.String(), err
		}
		resBuffer.Write(buf[:n])
		// the message is sent last - when we get the whole message we can stop reading
		if err == io.EOF || strings.Contains(resBuffer.String(), message) {
			break
		}
	}

	// format the output for forwarder response
	for _, line := range strings.Split(resBuffer.String(), "\n") {
		if line != "" {
			echo.WriteBodyLine(&msgBuilder, requestID, line)
		}
	}

	msg := msgBuilder.String()
	expected := fmt.Sprintf("%s=%d", string(echo.StatusCodeField), http.StatusOK)
	if cfg.Request.ExpectedResponse != nil {
		expected = cfg.Request.ExpectedResponse.GetValue()
	}
	if !strings.Contains(msg, expected) {
		return msg, fmt.Errorf("expect to recv message with %s, got %s. Return EOF", expected, msg)
	}
	return msg, nil
}

func (c *tcpProtocol) Close() error {
	return nil
}

func newTCPConnection(cfg *Config) (net.Conn, error) {
	address := cfg.Request.Url[len(cfg.scheme+"://"):]

	if cfg.secure {
		return hbone.TLSDialWithDialer(newDialer(cfg), "tcp", address, cfg.tlsConfig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), common.ConnectionTimeout)
	defer cancel()

	return newDialer(cfg).DialContext(ctx, "tcp", address)
}
