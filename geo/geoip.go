package geo

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/golang/protobuf/proto"
)

// Minimal protobuf structures compatible with v2fly geoip.dat
// message CIDR { bytes ip = 1; uint32 prefix = 2; }
// message GeoIP { string country_code = 1; repeated CIDR cidr = 2; }
// message GeoIPList { repeated GeoIP entry = 1; }

type CIDR struct {
	Ip     []byte `protobuf:"bytes,1,opt,name=ip,proto3"`
	Prefix uint32 `protobuf:"varint,2,opt,name=prefix,proto3"`
}

type GeoIP struct {
	CountryCode string  `protobuf:"bytes,1,opt,name=country_code,json=countryCode,proto3"`
	Cidr        []*CIDR `protobuf:"bytes,2,rep,name=cidr,proto3"`
}

type GeoIPList struct {
	Entry []*GeoIP `protobuf:"bytes,1,rep,name=entry,proto3"`
}

func (m *CIDR) Reset()         { *m = CIDR{} }
func (m *CIDR) String() string { return proto.CompactTextString(m) }
func (*CIDR) ProtoMessage()    {}

func (m *GeoIP) Reset()         { *m = GeoIP{} }
func (m *GeoIP) String() string { return proto.CompactTextString(m) }
func (*GeoIP) ProtoMessage()    {}

func (m *GeoIPList) Reset()         { *m = GeoIPList{} }
func (m *GeoIPList) String() string { return proto.CompactTextString(m) }
func (*GeoIPList) ProtoMessage()    {}

// Database holds IP networks by code (e.g., "CN", "PRIVATE").
type Database struct {
	sets map[string][]*net.IPNet
}

func NewDatabase() *Database { return &Database{sets: make(map[string][]*net.IPNet)} }

func (db *Database) LoadFromURL(ctx context.Context, url string) error {
	if url == "" {
		return errors.New("empty geox url")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("failed to fetch geox dat, status " + resp.Status)
	}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var list GeoIPList
	if err := proto.Unmarshal(buf, &list); err != nil {
		return err
	}
	for _, entry := range list.Entry {
		var nets []*net.IPNet
		for _, c := range entry.Cidr {
			ip := net.IP(c.Ip)
			mask := net.CIDRMask(int(c.Prefix), len(ip)*8)
			netw := &net.IPNet{IP: ip, Mask: mask}
			nets = append(nets, netw)
		}
		db.sets[entry.CountryCode] = nets
	}
	return nil
}

func (db *Database) Contains(code string, ip net.IP) bool {
	nets := db.sets[code]
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
