package policy

import (
	"net"
	"strings"

	"github.com/miekg/dns"
	"geo-dns/geo"
)

// Rule represents a policy rule like "GEOIP:CN,CN" or "MATCH,HK".
type Rule struct {
	Kind   string
	Arg    string
	Target string
}

func Parse(lines []string) []Rule {
	var rules []Rule
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" { continue }
		parts := strings.Split(l, ",")
		if len(parts) == 2 {
			// Either GEOIP:CODE,GROUP or MATCH,GROUP
			kind := parts[0]
			if strings.HasPrefix(kind, "GEOIP:") {
				arg := strings.TrimPrefix(kind, "GEOIP:")
				rules = append(rules, Rule{Kind: "GEOIP", Arg: arg, Target: parts[1]})
			} else if kind == "MATCH" {
				rules = append(rules, Rule{Kind: "MATCH", Target: parts[1]})
			}
		}
	}
	return rules
}

// DecideGroup determines which group should be used based on the first response's IPs and rules.
func DecideGroup(db *geo.Database, resp *dns.Msg, rules []Rule) string {
	if resp == nil { return "" }
	var ips []net.IP
	for _, rr := range resp.Answer {
		switch r := rr.(type) {
		case *dns.A:
			ips = append(ips, r.A)
		case *dns.AAAA:
			ips = append(ips, r.AAAA)
		}
	}
	for _, rule := range rules {
		switch rule.Kind {
		case "GEOIP":
			for _, ip := range ips {
				if db.Contains(rule.Arg, ip) {
					return rule.Target
				}
			}
		case "MATCH":
			return rule.Target
		}
	}
	return ""
}