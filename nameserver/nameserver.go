package nameserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Result struct {
	Msg      *dns.Msg
	Err      error
	NsName   string
	Duration time.Duration
}

type NameServer interface {
	Name() string
	Query(ctx context.Context, q *dns.Msg) Result
}

// UDP/IP Nameserver

type UDPServer struct {
	name   string
	addr   string // ip:port or ip
	client *dns.Client
}

func NewUDP(name, addr string) *UDPServer {
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(addr, "53")
	}
	return &UDPServer{
		name:   name,
		addr:   addr,
		client: &dns.Client{Net: "udp", Timeout: 3 * time.Second},
	}
}

func (u *UDPServer) Name() string { return u.name }

func (u *UDPServer) Query(ctx context.Context, q *dns.Msg) Result {
	start := time.Now()
	resp, _, err := u.client.ExchangeContext(ctx, q, u.addr)
	return Result{Msg: resp, Err: err, NsName: u.name, Duration: time.Since(start)}
}

// DoH Nameserver

type DoHServer struct {
	name      string
	endpoint  string
	host      string
	client    *http.Client
	bootstrap []net.IP // optional resolved IPs for endpoint host
}

func NewDoH(name, endpoint string, bootstrapIPs []net.IP) (*DoHServer, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: host},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Prefer bootstrap IPs if provided
			if len(bootstrapIPs) > 0 {
				ip := bootstrapIPs[time.Now().UnixNano()%int64(len(bootstrapIPs))]
				port := u.Port()
				if port == "" { port = "443" }
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			}
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, addr)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	return &DoHServer{name: name, endpoint: endpoint, host: host, client: client, bootstrap: bootstrapIPs}, nil
}

func (d *DoHServer) Name() string { return d.name }

func (d *DoHServer) Query(ctx context.Context, q *dns.Msg) Result {
	start := time.Now()
	wire, err := q.Pack()
	if err != nil { return Result{Err: err, NsName: d.name} }
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.endpoint, bytes.NewReader(wire))
	if err != nil { return Result{Err: err, NsName: d.name} }
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil { return Result{Err: err, NsName: d.name} }
	defer resp.Body.Close()
	if resp.StatusCode != 200 { return Result{Err: errors.New("doh status " + resp.Status), NsName: d.name} }
	body, err := io.ReadAll(resp.Body)
	if err != nil { return Result{Err: err, NsName: d.name} }
	msg := new(dns.Msg)
	if err := msg.Unpack(body); err != nil { return Result{Err: err, NsName: d.name} }
	return Result{Msg: msg, Err: nil, NsName: d.name, Duration: time.Since(start)}
}