package bootstrap

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
)

// ResolveHost resolves A/AAAA for host using provided bootstrap DNS servers (IP:53)
func ResolveHost(ctx context.Context, host string, servers []string) []net.IP {
	var ips []net.IP
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(host), dns.TypeA)
	ips = append(ips, queryOnce(ctx, q, servers)...)
	q6 := new(dns.Msg)
	q6.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
	ips = append(ips, queryOnce(ctx, q6, servers)...)
	return ips
}

func queryOnce(ctx context.Context, q *dns.Msg, servers []string) []net.IP {
	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	answers := []net.IP{}
	for _, s := range servers {
		addr := s
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, "53")
		}
		resp, _, err := c.ExchangeContext(ctx, q, addr)
		if err != nil || resp == nil {
			continue
		}
		for _, rr := range resp.Answer {
			switch r := rr.(type) {
			case *dns.A:
				answers = append(answers, r.A)
			case *dns.AAAA:
				answers = append(answers, r.AAAA)
			}
		}
	}
	return answers
}
