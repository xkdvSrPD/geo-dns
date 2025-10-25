package main

import (
	"context"
	"log"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/miekg/dns"
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
			if err != nil { log.Printf("skip doh ns %s: %v", ns.Name, err); continue }
			ips := bootstrapIPsByHost[u.Hostname()]
			doh, err := nameserver.NewDoH(ns.Name, ns.Server, ips)
			if err != nil { log.Printf("skip doh ns %s: %v", ns.Name, err); continue }
			nsAdapters = append(nsAdapters, &dohAdapter{impl: doh})
		default:
			log.Printf("unknown ns type %s for %s", ns.Type, ns.Name)
		}
	}
	// Build group map: group -> nameserver names
	groupMap := map[string][]string{}
	for _, g := range cfg.NameserverGroup {
		groupMap[g.Name] = append([]string{}, g.Nameservers...)
	}
	// Build ECS map: nsName -> CIDR from ns-level or group-level
	ecsByNS := map[string]string{}
	for _, ns := range cfg.Nameservers {
		if ns.ECS != "" { ecsByNS[ns.Name] = ns.ECS }
	}
	for _, g := range cfg.NameserverGroup {
		if g.ECS == "" { continue }
		for _, name := range g.Nameservers {
			if _, ok := ecsByNS[name]; !ok { ecsByNS[name] = g.ECS }
		}
	}
	// Parse policy rules
	rules := policy.Parse(cfg.NameserverPolicy)
	coord := &server.Coordinator{
		ListenAddr: cfg.Listen,
		Cache:      cache.New(),
		Rules:      rules,
		GroupMap:   groupMap,
		NS:         nsAdapters,
		GeoDB:      geoDB,
		ECSByNS:    ecsByNS,
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