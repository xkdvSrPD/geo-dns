package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"geo-dns/cache"
	"geo-dns/geo"
	"geo-dns/policy"
)

type ctxKey string

const (
	traceKey  ctxKey = "traceid"
	clientKey ctxKey = "clientip"
)

type Coordinator struct {
	ListenAddr string
	Cache     *cache.Cache
	Rules     []policy.Rule
	GroupMap  map[string][]string // group name -> nameserver names
	NSIndex   map[string]int      // nameserver name -> index
	NS        []NSAdapter
	GeoDB     *geo.Database
	 ECSByNS   map[string]string   // ns name -> ecs CIDR
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
		if err == nil { clientIP = host } else { clientIP = ra.String() }
	}
	ctx = context.WithValue(ctx, clientKey, clientIP)
	question := r.Copy()
	qname := ""
	if len(question.Question) > 0 { qname = question.Question[0].Name }
	// Cache lookup: if hit, return directly without refresh or policy matching, reuse stored traceid
	cached, cachedTrace := c.Cache.GetWithTrace(question)
	if cached != nil {
		ips := extractIPs(cached)
		log.Printf("level=debug trace=%s event=cache_hit client_ip=%s qname=%s ips=%s", cachedTrace, clientIP, qname, strings.Join(ips, ","))
		out := cached.Copy()
		out.Id = r.Id
		out.Question = r.Question
		log.Printf("level=info trace=%s event=return client_ip=%s qname=%s group=cache ips=%s ns=cache", cachedTrace, clientIP, qname, strings.Join(ips, ","))
		_ = w.WriteMsg(out)
		return
	}
	// Miss: generate new trace id for this effective query
	traceID := genTraceID()
	ctx = context.WithValue(ctx, traceKey, traceID)
	// Fresh resolve concurrently
	resp, group, nsUsed := c.resolveConcurrently(ctx, question)
	if resp != nil {
		c.Cache.SetWithTrace(question, resp, traceID)
		ips := extractIPs(resp)
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
	log.Printf("level=info trace=%s event=servfail client_ip=%s qname=%s ns=none", traceID, clientIP, qname)
	_ = w.WriteMsg(m)
}

func (c *Coordinator) refresh(ctx context.Context, q *dns.Msg) {
	// Background refresh simply resolves and updates cache
	resp, _, _ := c.resolveConcurrently(ctx, q)
	if resp != nil {
		c.Cache.Set(q, resp)
	}
}

func (c *Coordinator) resolveConcurrently(ctx context.Context, q *dns.Msg) (*dns.Msg, string, string) {
	resCh := make(chan NSResult, len(c.NS))
	for _, ns := range c.NS {
		go func(adapter NSAdapter) {
			// clone query and inject ECS if configured for this NS
			q2 := q.Copy()
			if cidr, ok := c.ECSByNS[adapter.Name()]; ok && cidr != "" {
				if opt := ecsOPT(cidr); opt != nil {
					q2.Extra = append(q2.Extra, opt)
				}
			}
			res := adapter.Query(ctx, q2)
			resCh <- NSResult{Msg: res.Msg, Err: res.Err, NsName: adapter.Name(), Duration: res.Duration}
		}(ns)
	}
	deadline := time.After(4 * time.Second)
	var firstResp *dns.Msg
	var firstRespNs string
	var chosenGroup string
	var groupFirstResp *dns.Msg
	var groupFirstNs string
	groupMembers := map[string]struct{}{}
	traceID, _ := ctx.Value(traceKey).(string)
	clientIP, _ := ctx.Value(clientKey).(string)
	qname := ""
	if len(q.Question) > 0 { qname = q.Question[0].Name }
	for received := 0; received < len(c.NS); received++ {
		select {
		case <-deadline:
			if groupFirstResp != nil { return groupFirstResp, chosenGroup, groupFirstNs }
			return firstResp, chosenGroup, firstRespNs
		case r := <-resCh:
			// Log each upstream call
			if r.Err != nil {
				log.Printf("level=debug trace=%s event=upstream client_ip=%s ns=%s qname=%s duration=%s err=%v", traceID, clientIP, r.NsName, qname, r.Duration, r.Err)
				continue
			}
			if r.Msg == nil {
				log.Printf("level=debug trace=%s event=upstream client_ip=%s ns=%s qname=%s duration=%s err=nil empty_msg", traceID, clientIP, r.NsName, qname, r.Duration)
				continue
			}
			ips := extractIPs(r.Msg)
			log.Printf("level=debug trace=%s event=upstream client_ip=%s ns=%s qname=%s duration=%s ips=%s", traceID, clientIP, r.NsName, qname, r.Duration, strings.Join(ips, ","))
			if firstResp == nil { firstResp = r.Msg; firstRespNs = r.NsName }
			// If we don't have a chosen group yet, decide now based on policy
			if chosenGroup == "" {
				chosenGroup = policy.DecideGroup(c.GeoDB, r.Msg, c.Rules)
				// Build member set for chosen group
				groupMembers = map[string]struct{}{}
				for _, name := range c.GroupMap[chosenGroup] { groupMembers[name] = struct{}{} }
			}
			// If this response comes from chosen group, and we don't have groupFirstResp yet, use it
			if _, ok := groupMembers[r.NsName]; ok && groupFirstResp == nil {
				groupFirstResp = r.Msg
				groupFirstNs = r.NsName
			}
		}
	}
	if groupFirstResp != nil { return groupFirstResp, chosenGroup, groupFirstNs }
	return firstResp, chosenGroup, firstRespNs
}

func extractIPs(resp *dns.Msg) []string {
	var ips []string
	if resp == nil { return ips }
	for _, rr := range resp.Answer {
		switch r := rr.(type) {
		case *dns.A:
			ips = append(ips, r.A.String())
		case *dns.AAAA:
			ips = append(ips, r.AAAA.String())
		}
	}
	return ips
}

func ecsOPT(cidr string) *dns.OPT {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil || ip == nil || ipnet == nil { return nil }
	family := uint16(1)
	if ip.To4() == nil { family = 2 }
	ones, _ := ipnet.Mask.Size()
	sub := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: family, SourceNetmask: uint8(ones), SourceScope: 0, Address: ip.Mask(ipnet.Mask)}
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.Option = append(opt.Option, sub)
	return opt
}