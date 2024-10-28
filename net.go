// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tongsuogo

import (
	"errors"
	"fmt"
	"net"
)

var ErrNilParam = errors.New("nil parameter")

type listener struct {
	net.Listener
	ctx *Ctx
}

func (l *listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("failed to accept: %w", err)
	}

	server, err := Server(conn, l.ctx)
	if err != nil {
		conn.Close()

		return nil, err
	}

	return server, nil
}

// NewListener wraps an existing net.Listener such that all accepted
// connections are wrapped as OpenSSL server connections using the provided
// context ctx.
func NewListener(inner net.Listener, ctx *Ctx) net.Listener {
	return &listener{
		Listener: inner,
		ctx:      ctx,
	}
}

// Listen is a wrapper around net.Listen that wraps incoming connections with
// an OpenSSL server connection using the provided context ctx.
func Listen(network, laddr string, ctx *Ctx) (net.Listener, error) {
	if ctx == nil {
		return nil, fmt.Errorf("no ssl context provided: %w", ErrNilParam)
	}

	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}

	return NewListener(l, ctx), nil
}

type DialFlags int

const (
	InsecureSkipHostVerification DialFlags = 1 << iota
	DisableSNI
)

// Dial will connect to network/address and then wrap the corresponding
// underlying connection with an OpenSSL client connection using context ctx.
// If flags includes InsecureSkipHostVerification, the server certificate's
// hostname will not be checked to match the hostname in addr. Otherwise, flags
// should be 0.
//
// Dial probably won't work for you unless you set a verify location or add
// some certs to the certificate store of the client context you're using.
// This library is not nice enough to use the system certificate store by
// default for you yet.
func Dial(network, addr string, ctx *Ctx, flags DialFlags, host string) (*Conn, error) {
	return DialSession(network, addr, ctx, flags, nil, host)
}

// DialSession will connect to network/address and then wrap the corresponding
// underlying connection with an OpenSSL client connection using context ctx.
// If flags includes InsecureSkipHostVerification, the server certificate's
// hostname will not be checked to match the hostname in addr. Otherwise, flags
// should be 0.
//
// Dial probably won't work for you unless you set a verify location or add
// some certs to the certificate store of the client context you're using.
// This library is not nice enough to use the system certificate store by
// default for you yet.
//
// If session is not nil it will be used to resume the tls state. The session
// can be retrieved from the GetSession method on the Conn.
func DialSession(network, addr string, ctx *Ctx, flags DialFlags,
	session []byte, host string,
) (*Conn, error) {
	var err error
	if host == "" {
		host, _, err = net.SplitHostPort(addr)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to split host and port: %w", err)
	}

	if ctx == nil {
		var err error

		ctx, err = NewCtx()
		if err != nil {
			return nil, err
		}
	}

	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	client, err := Client(conn, ctx)
	if err != nil {
		conn.Close()

		return nil, err
	}

	if session != nil {
		err := client.setSession(session)
		if err != nil {
			conn.Close()

			return nil, err
		}
	}

	if flags&DisableSNI == 0 {
		err = client.SetTLSExtHostName(host)
		if err != nil {
			client.Close()

			return nil, fmt.Errorf("failed to set TLS host name: %w", err)
		}
	}

	err = client.Handshake()
	if err != nil {
		client.Close()

		return nil, fmt.Errorf("failed to handshake: %w", err)
	}

	if flags&InsecureSkipHostVerification == 0 {
		err = client.VerifyHostname(host)
		if err != nil {
			client.Close()

			return nil, fmt.Errorf("failed to verify host name: %w", err)
		}
	}

	return client, nil
}
