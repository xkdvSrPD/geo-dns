package policy

import (
	"github.com/miekg/dns"
	"net"
	"strings"

	"geo-dns/geo"
)

// Rule represents a policy rule like "GEOIP:CN,CN" or "GEOIP:!CN,HK" or "MATCH,HK".
type Rule struct {
	Kind   string
	Arg    string
	Target string
}

func Parse(lines []string) []Rule {
	var rules []Rule
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
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

// CheckRuleMatch checks if a response matches a specific rule and whether group validation is required.
// Returns: (matches, requiresGroupValidation)
func CheckRuleMatch(db *geo.Database, resp *dns.Msg, rule Rule) (bool, bool) {
	if resp == nil {
		return false, false
	}
	var ips []net.IP
	for _, rr := range resp.Answer {
		switch r := rr.(type) {
		case *dns.A:
			ips = append(ips, r.A)
		case *dns.AAAA:
			ips = append(ips, r.AAAA)
		}
	}
	if len(ips) == 0 {
		return false, false
	}

	switch rule.Kind {
	case "GEOIP":
		neg := strings.HasPrefix(rule.Arg, "!")
		code := strings.TrimPrefix(rule.Arg, "!")
		if !neg {
			// Positive GEOIP: match if any IP is inside the code set; no group validation needed
			for _, ip := range ips {
				if db.Contains(code, ip) {
					return true, false
				}
			}
			return false, false
		}
		// Negative GEOIP: match if any IP is outside the code set; requires group validation
		for _, ip := range ips {
			if !db.Contains(code, ip) {
				return true, true
			}
		}
		return false, false
	case "MATCH":
		// MATCH always "matches" but requires group validation by caller
		return true, true
	}
	return false, false
}

// DecideGroup determines which group should be used based on the first response's IPs and rules.
// This is kept for backward compatibility but the new logic should use CheckRuleMatch
func DecideGroup(db *geo.Database, resp *dns.Msg, rules []Rule) string {
	if resp == nil {
		return ""
	}
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
			neg := strings.HasPrefix(rule.Arg, "!")
			code := strings.TrimPrefix(rule.Arg, "!")
			if !neg {
				for _, ip := range ips {
					if db.Contains(code, ip) {
						return rule.Target
					}
				}
			} else {
				for _, ip := range ips {
					if !db.Contains(code, ip) {
						return rule.Target
					}
				}
			}
		case "MATCH":
			return rule.Target
		}
	}
	return ""
}
