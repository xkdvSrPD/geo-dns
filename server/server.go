package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net"
	"strings"
	"time"

	"geo-dns/cache"
	"geo-dns/geo"
	"geo-dns/policy"
	"github.com/miekg/dns"
)

type ctxKey string

const (
	traceKey  ctxKey = "traceid"
	clientKey ctxKey = "clientip"
)

type Coordinator struct {
	ListenAddr      string
	Cache           *cache.Cache
	Rules           []policy.Rule
	GroupMap        map[string][]string // group name -> nameserver names
	NSIndex         map[string]int      // nameserver name -> index
	NS              []NSAdapter
	GeoDB           *geo.Database
	ECSByNS         map[string]string // ns name -> ecs CIDR
	ECSOverrideByNS map[string]bool   // ns name -> override existing client ECS
	DebugEnabled    bool
	GroupOrder      []string // preserve config order
	IPv6Enabled     bool     // control AAAA handling
}

type NSAdapter interface {
	Name() string
	Query(ctx context.Context, q *dns.Msg) NSResult
}

type NSResult struct {
	Msg      *dns.Msg
	Err      error
	NsName   string
	Duration time.Duration
}

func (c *Coordinator) Start() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", c.handle)
	srv := &dns.Server{Addr: c.ListenAddr, Net: "udp", Handler: mux}
	log.Printf("listening on %s", c.ListenAddr)
	return srv.ListenAndServe()
}

func genTraceID() string {
	buf := make([]byte, 3)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func (c *Coordinator) handle(w dns.ResponseWriter, r *dns.Msg) {
	baseCtx := context.Background()
	ctx, cancel := context.WithTimeout(baseCtx, 5*time.Second)
	defer cancel()
	clientIP := ""
	if ra := w.RemoteAddr(); ra != nil {
		host, _, err := net.SplitHostPort(ra.String())
		if err == nil {
			clientIP = host
		} else {
			clientIP = ra.String()
		}
	}
	ctx = context.WithValue(ctx, clientKey, clientIP)
	question := r.Copy()
	qname := ""
	if len(question.Question) > 0 {
		qname = question.Question[0].Name
	}
	// Cache lookup only if enabled
	if c.Cache != nil {
		cached, cachedTrace := c.Cache.GetWithTrace(question)
		if cached != nil {
			ips := extractIPs(cached, c.IPv6Enabled)
			log.Printf("level=debug trace=%s event=cache_hit client_ip=%s qname=%s ips=%s", cachedTrace, clientIP, qname, strings.Join(ips, ","))
			out := cached.Copy()
			out.Id = r.Id
			out.Question = r.Question
			log.Printf("level=info trace=%s event=return client_ip=%s qname=%s group=cache ips=%s ns=cache", cachedTrace, clientIP, qname, strings.Join(ips, ","))
			_ = w.WriteMsg(out)
			return
		}
	}
	// Miss: generate new trace id for this effective query
	traceID := genTraceID()
	ctx = context.WithValue(ctx, traceKey, traceID)
	// Fresh resolve concurrently
	resp, group, nsUsed := c.resolveConcurrently(ctx, question, clientIP)
	if resp != nil {
		if c.Cache != nil {
			c.Cache.SetWithTrace(question, resp, traceID)
		}
		ips := extractIPs(resp, c.IPv6Enabled)
		out := resp.Copy()
		out.Id = r.Id
		out.Question = r.Question
		log.Printf("level=info trace=%s event=return client_ip=%s qname=%s group=%s ips=%s ns=%s", traceID, clientIP, qname, group, strings.Join(ips, ","), nsUsed)
		_ = w.WriteMsg(out)
		return
	}
	// Respond SERVFAIL if none
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	log.Printf("level=error trace=%s event=servfail client_ip=%s qname=%s ns=none", traceID, clientIP, qname)
	_ = w.WriteMsg(m)
}

func (c *Coordinator) refresh(ctx context.Context, q *dns.Msg) {
	// Background refresh simply resolves and updates cache
	resp, _, _ := c.resolveConcurrently(ctx, q, "")
	if resp != nil && c.Cache != nil {
		c.Cache.Set(q, resp)
	}
}

func (c *Coordinator) resolveConcurrently(ctx context.Context, q *dns.Msg, clientIP string) (*dns.Msg, string, string) {
	traceID, _ := ctx.Value(traceKey).(string)
	if traceID == "" {
		traceID = genTraceID()
	}
	qname := ""
	if len(q.Question) > 0 {
		qname = strings.ToLower(strings.TrimSuffix(q.Question[0].Name, "."))
	}
	// ECS handling per ns
	setECS := func(nsName string, m *dns.Msg) {
		cidr, ok := c.ECSByNS[nsName]
		if !ok || cidr == "" || m == nil {
			return
		}
		// Find or create OPT RR
		var opt *dns.OPT
		for _, e := range m.Extra {
			if e.Header().Rrtype == dns.TypeOPT {
				if o, ok := e.(*dns.OPT); ok {
					opt = o
					break
				}
			}
		}
		if opt == nil {
			opt = new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			m.Extra = append(m.Extra, opt)
		}
		// Build ECS option
		sub := ecsEDNS0SUBNET(cidr)
		if sub == nil {
			return
		}
		// Check existing ECS option
		override := c.ECSOverrideByNS != nil && c.ECSOverrideByNS[nsName]
		replaced := false
		for i, o := range opt.Option {
			if o.Option() == dns.EDNS0SUBNET {
				if override {
					opt.Option[i] = sub
					replaced = true
				} else {
					replaced = true // keep existing
				}
				break
			}
		}
		if !replaced {
			opt.Option = append(opt.Option, sub)
		}
		if c.DebugEnabled {
			action := "added"
			if replaced {
				if override {
					action = "overridden"
				} else {
					action = "preserved"
				}
			}
			log.Printf("level=debug trace=%s event=ecs_%s client_ip=%s ns=%s cidr=%s", traceID, action, clientIP, nsName, cidr)
		}
	}

	// Launch queries
	resCh := make(chan NSResult, len(c.NS))
	for _, ns := range c.NS {
		nsName := ns.Name()
		msg := q.Copy()
		setECS(nsName, msg)

		go func(a NSAdapter, m *dns.Msg) {

			r := a.Query(ctx, m)

			if c.DebugEnabled {
				if r.Err != nil {
					log.Printf("level=debug trace=%s event=upstream_response client_ip=%s ns=%s qname=%s duration=%s error=%v",
						traceID, clientIP, nsName, qname, r.Duration, r.Err)
				} else if r.Msg != nil {
					ips := extractIPs(r.Msg, c.IPv6Enabled)
					log.Printf("level=debug trace=%s event=upstream_response client_ip=%s ns=%s qname=%s duration=%s ips=%s",
						traceID, clientIP, nsName, qname, r.Duration, strings.Join(ips, ","))
				} else {
					log.Printf("level=debug trace=%s event=upstream_response client_ip=%s ns=%s qname=%s duration=%s msg=nil",
						traceID, clientIP, nsName, qname, r.Duration)
				}
			}

			resCh <- r
		}(ns, msg)
	}
	deadline := time.After(4 * time.Second)
	// Reverse map ns->group
	nsToGroup := map[string]string{}
	for g, names := range c.GroupMap {
		for _, n := range names {
			nsToGroup[n] = g
		}
	}
	// Collect the first response per group
	totalGroups := len(c.GroupOrder)
	groupFirst := map[string]NSResult{}
	received := 0

	for received < len(c.NS) {
		select {
		case <-deadline:
			// If not all groups responded, treat as error (per requirement #2)
			if c.DebugEnabled {
				log.Printf("level=error trace=%s event=policy_unavailable client_ip=%s qname=%s reason=missing_group_results have=%d need=%d", traceID, clientIP, qname, len(groupFirst), totalGroups)
			}
			return nil, "", ""
		case r := <-resCh:
			received++
			if r.Err != nil || r.Msg == nil {
				continue
			}
			grp := nsToGroup[r.NsName]
			if grp == "" {
				continue
			}
			// Filter answers by IPv6 toggle for matching and returning
			msg := filterByIPv6(r.Msg, c.IPv6Enabled)
			if _, ok := groupFirst[grp]; !ok {
				groupFirst[grp] = NSResult{Msg: msg, Err: r.Err, NsName: r.NsName, Duration: r.Duration}
				if len(groupFirst) == totalGroups {
					goto MATCH_PHASE
				}
			} else {
				// Already have a faster result for this group; log discard
				if c.DebugEnabled {
					ips2 := extractIPs(msg, c.IPv6Enabled)
					log.Printf("level=debug trace=%s event=discard client_ip=%s ns=%s qname=%s ips=%s reason=slow_in_group group=%s", traceID, clientIP, r.NsName, qname, strings.Join(ips2, ","), grp)
				}
			}
		}
	}

MATCH_PHASE:
	// All groups have their first response; perform policy matching in group order
	for _, grp := range c.GroupOrder {
		gr, ok := groupFirst[grp]
		if !ok || gr.Msg == nil {
			continue
		}
		for _, rule := range c.Rules {
			match, _ := policy.CheckRuleMatch(c.GeoDB, gr.Msg, rule)
			if !match {
				continue
			}
			// Enforce two-group condition for MATCH (already satisfied but keep explicit)
			if rule.Kind == "MATCH" {
				if totalGroups < 2 {
					if c.DebugEnabled {
						log.Printf("level=debug trace=%s event=policy_wait client_ip=%s ns=%s qname=%s rule=%s groups=%d", traceID, clientIP, gr.NsName, qname, rule.Kind, totalGroups)
					}
					continue
				}
			}
			// When a rule matches, select target group's earliest result
			target := rule.Target
			tRes, ok := groupFirst[target]
			if !ok || tRes.Msg == nil {
				if c.DebugEnabled {
					log.Printf("level=debug trace=%s event=policy_mismatch client_ip=%s ns=%s qname=%s rule=%s reason=target_group_missing target=%s", traceID, clientIP, gr.NsName, qname, rule.Kind, target)
				}
				continue
			}
			policyStr := ""
			if rule.Kind == "GEOIP" {
				policyStr = "GEOIP:" + rule.Arg + "," + rule.Target
			} else if rule.Kind == "MATCH" {
				policyStr = "MATCH," + rule.Target
			} else {
				policyStr = rule.Kind + "," + rule.Target
			}
			ips := extractIPs(tRes.Msg, c.IPv6Enabled)
			log.Printf("level=info trace=%s event=policy_match client_ip=%s ns=%s qname=%s policy=%s group=%s target_group=%s ips=%s", traceID, clientIP, tRes.NsName, qname, policyStr, grp, target, strings.Join(ips, ","))
			// Drain remaining late responses for logging without delaying return
			if c.DebugEnabled {
				remaining := len(c.NS) - received
				go func(rem int, trace, cip, name string) {
					for i := 0; i < rem; i++ {
						select {
						case r2 := <-resCh:
							if r2.Msg == nil {
								continue
							}
							ips2 := extractIPs(r2.Msg, c.IPv6Enabled)
							log.Printf("level=debug trace=%s event=discard client_ip=%s ns=%s qname=%s ips=%s reason=late_response", trace, cip, r2.NsName, name, strings.Join(ips2, ","))
						case <-time.After(500 * time.Millisecond):
							return
						}
					}
				}(remaining, traceID, clientIP, qname)
			}
			return tRes.Msg, target, tRes.NsName
		}
		// No rule matched for this group's result
		if c.DebugEnabled {
			ips := extractIPs(gr.Msg, c.IPv6Enabled)
			log.Printf("level=debug trace=%s event=policy_group_no_match client_ip=%s ns=%s qname=%s group=%s ips=%s", traceID, clientIP, gr.NsName, qname, grp, strings.Join(ips, ","))
		}
	}
	// No group produced a match: treat as config error
	log.Printf("level=error trace=%s event=policy_no_match client_ip=%s qname=%s reason=config_error", traceID, clientIP, qname)
	return nil, "", ""

}

func extractIPs(m *dns.Msg, ipv6Enabled bool) []string {
	var ips []string
	for _, a := range m.Answer {
		switch rr := a.(type) {
		case *dns.A:
			ips = append(ips, rr.A.String())
		case *dns.AAAA:
			if ipv6Enabled {
				ips = append(ips, rr.AAAA.String())
			}
		}
	}
	return ips
}

func filterByIPv6(m *dns.Msg, ipv6Enabled bool) *dns.Msg {
	if m == nil {
		return nil
	}
	out := m.Copy()
	ans := []dns.RR{}
	for _, a := range out.Answer {
		switch rr := a.(type) {
		case *dns.A:
			ans = append(ans, rr)
		case *dns.AAAA:
			if ipv6Enabled {
				ans = append(ans, rr)
			}
		default:
			// keep other RRs as-is
			ans = append(ans, a)
		}
	}
	out.Answer = ans
	return out
}

func ecsEDNS0SUBNET(cidr string) *dns.EDNS0_SUBNET {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil || ip == nil || ipnet == nil {
		return nil
	}
	family := uint16(1)
	if ip.To4() == nil {
		family = 2
	}
	ones, _ := ipnet.Mask.Size()
	return &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: family, SourceNetmask: uint8(ones), SourceScope: 0, Address: ip.Mask(ipnet.Mask)}
}
