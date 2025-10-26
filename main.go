package main

import (
	"context"
	"github.com/miekg/dns"
	"log"
	"net"
	"net/url"
	"os"
	"time"

	"geo-dns/bootstrap"
	"geo-dns/cache"
	"geo-dns/config"
	"geo-dns/geo"
	"geo-dns/nameserver"
	"geo-dns/policy"
	"geo-dns/server"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	cfg, err := config.Load("config.yaml")
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	// Load GeoIP DAT
	geoDB := geo.NewDatabase()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := geoDB.LoadFromURL(ctx, cfg.GeoxURL); err != nil {
		log.Printf("warn: failed to load geox: %v", err)
	}
	// Build nameservers
	var nsAdapters []server.NSAdapter
	bootstrapIPsByHost := map[string][]net.IP{}
	// Pre-resolve DoH hosts via bootstrap IP DNS servers
	for _, ns := range cfg.Nameservers {
		if ns.Type == "doh" {
			u, err := url.Parse(ns.Server)
			if err == nil {
				host := u.Hostname()
				ips := bootstrap.ResolveHost(ctx, host, cfg.BootstrapNameservers)
				bootstrapIPsByHost[host] = ips
			}
		}
	}
	for _, ns := range cfg.Nameservers {
		switch ns.Type {
		case "ip":
			nsAdapters = append(nsAdapters, &udpAdapter{impl: nameserver.NewUDP(ns.Name, ns.Server)})
		case "doh":
			u, err := url.Parse(ns.Server)
			if err != nil {
				log.Printf("skip doh ns %s: %v", ns.Name, err)
				continue
			}
			ips := bootstrapIPsByHost[u.Hostname()]
			doh, err := nameserver.NewDoH(ns.Name, ns.Server, ips)
			if err != nil {
				log.Printf("skip doh ns %s: %v", ns.Name, err)
				continue
			}
			nsAdapters = append(nsAdapters, &dohAdapter{impl: doh})
		default:
			log.Printf("unknown ns type %s for %s", ns.Type, ns.Name)
		}
	}
	// Build group map: group -> nameserver names
	groupMap := map[string][]string{}
	var groupOrder []string
	for _, g := range cfg.NameserverGroup {
		groupMap[g.Name] = append([]string{}, g.Nameservers...)
		groupOrder = append(groupOrder, g.Name)
	}
	// Build ECS map: nsName -> CIDR from ns-level or group-level
	ecsByNS := map[string]string{}
	for _, ns := range cfg.Nameservers {
		if ns.ECS != "" {
			ecsByNS[ns.Name] = ns.ECS
		}
	}
	for _, g := range cfg.NameserverGroup {
		if g.ECS == "" {
			continue
		}
		for _, name := range g.Nameservers {
			if _, ok := ecsByNS[name]; !ok {
				ecsByNS[name] = g.ECS
			}
		}
	}
	// Build ECS override map: nsName -> override flag
	ecsOverrideByNS := map[string]bool{}
	for _, ns := range cfg.Nameservers {
		if ns.ECSOverride {
			ecsOverrideByNS[ns.Name] = true
		}
	}
	for _, g := range cfg.NameserverGroup {
		if g.ECSOverride {
			for _, name := range g.Nameservers {
				if _, ok := ecsOverrideByNS[name]; !ok {
					ecsOverrideByNS[name] = true
				}
			}
		}
	}
	// Parse policy rules
	rules := policy.Parse(cfg.NameserverPolicy)
	// Cache toggle
	cacheEnabled := true
	if cfg.Cache != nil {
		cacheEnabled = cfg.Cache.Enable
	}
	var cacheInst *cache.Cache
	if cacheEnabled {
		cacheInst = cache.New()
	} else {
		log.Printf("level=info event=cache_disabled reason=config cache.enable=false")
		cacheInst = nil
	}
	// Log level toggle for discard debug
	debugEnabled := false
	if cfg.Log != nil && cfg.Log.Level == "debug" {
		debugEnabled = true
	}
	// IPv6 toggle
	ipv6Enabled := true
	if cfg.IPv6 != nil {
		ipv6Enabled = *cfg.IPv6
	}
	coord := &server.Coordinator{
		ListenAddr:      cfg.Listen,
		Cache:           cacheInst,
		Rules:           rules,
		GroupMap:        groupMap,
		NS:              nsAdapters,
		GeoDB:           geoDB,
		ECSByNS:         ecsByNS,
		ECSOverrideByNS: ecsOverrideByNS,
		DebugEnabled:    debugEnabled,
		GroupOrder:      groupOrder,
		IPv6Enabled:     ipv6Enabled,
	}
	if err := coord.Start(); err != nil {
		log.Printf("server error: %v", err)
		os.Exit(1)
	}
}

type udpAdapter struct{ impl *nameserver.UDPServer }

func (a *udpAdapter) Name() string { return a.impl.Name() }
func (a *udpAdapter) Query(ctx context.Context, q *dns.Msg) server.NSResult {
	r := a.impl.Query(ctx, q)
	return server.NSResult{Msg: r.Msg, Err: r.Err, NsName: r.NsName, Duration: r.Duration}
}

type dohAdapter struct{ impl *nameserver.DoHServer }

func (a *dohAdapter) Name() string { return a.impl.Name() }
func (a *dohAdapter) Query(ctx context.Context, q *dns.Msg) server.NSResult {
	r := a.impl.Query(ctx, q)
	return server.NSResult{Msg: r.Msg, Err: r.Err, NsName: r.NsName, Duration: r.Duration}
}
