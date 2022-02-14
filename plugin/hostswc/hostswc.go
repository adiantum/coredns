package hostswc

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

// parseIP calls discards any v6 zone info, before calling net.ParseIP.
func parseIP(addr string) net.IP {
	if i := strings.Index(addr, "%"); i >= 0 {
		// discard ipv6 zone
		addr = addr[0:i]
	}

	return net.ParseIP(addr)
}

type options struct {
	// automatically generate IP to Hostname PTR entries
	// for host entries we parse
	autoReverse bool

	// The TTL of the record we generate
	ttl uint32

	// The time between two reload of the configuration
	reload time.Duration
}

func newOptions() *options {
	return &options{
		autoReverse: true,
		ttl:         3600,
		reload:      time.Duration(5 * time.Second),
	}
}

// Map contains the IPv4/IPv6 and reverse mapping.
type Map struct {
	// Key for the list of literal IP addresses must be a FQDN lowercased host name.
	name4 map[string][]net.IP
	name6 map[string][]net.IP

	// Key for the list of host names must be a literal IP address
	// including IPv6 address without zone identifier.
	// We don't support old-classful IP address notation.
	addr map[string][]string
}

func newMap() *Map {
	return &Map{
		name4: make(map[string][]net.IP),
		name6: make(map[string][]net.IP),
		addr:  make(map[string][]string),
	}
}

// Len returns the total number of addresses in the hostmap, this includes V4/V6 and any reverse addresses.
func (h *Map) Len() int {
	l := 0
	for _, v4 := range h.name4 {
		l += len(v4)
	}
	for _, v6 := range h.name6 {
		l += len(v6)
	}
	for _, a := range h.addr {
		l += len(a)
	}
	return l
}

type HostsWC struct {
	Origins []string
	inline  *Map
	options *options

	Next plugin.Handler
	Fall fall.F
}

// ServeDNS implements the plugin.Handle interface.
func (h HostsWC) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.Name()

	answers := []dns.RR{}

	zone := plugin.Zones(h.Origins).Matches(qname)
	if zone == "" {
		// PTR zones don't need to be specified in Origins.
		if state.QType() != dns.TypePTR {
			// if this doesn't match we need to fall through regardless of h.Fallthrough
			return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, r)
		}
	}

	switch state.QType() {
	case dns.TypePTR:
		names := h.LookupStaticAddr(dnsutil.ExtractAddressFromReverse(qname))
		if len(names) == 0 {
			// If this doesn't match we need to fall through regardless of h.Fallthrough
			return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, r)
		}
		answers = h.ptr(qname, h.options.ttl, names)
	case dns.TypeA:
		ips := h.LookupStaticHostV4(qname)
		answers = a(qname, h.options.ttl, ips)
	case dns.TypeAAAA:
		ips := h.LookupStaticHostV6(qname)
		answers = aaaa(qname, h.options.ttl, ips)
	}

	// Only on NXDOMAIN we will fallthrough.
	if len(answers) == 0 && !h.otherRecordsExist(qname) {
		if h.Fall.Through(qname) {
			return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, r)
		}

		// We want to send an NXDOMAIN, but because of /etc/hosts' setup we don't have a SOA, so we make it SERVFAIL
		// to at least give an answer back to signals we're having problems resolving this.
		return dns.RcodeServerFailure, nil
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = answers

	w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

// Name implements the plugin.Handle interface.
func (h HostsWC) Name() string { return "hostswc" }

func (h *HostsWC) initInline(inline []string) {
	if len(inline) == 0 {
		return
	}

	h.inline = h.parse(strings.NewReader(strings.Join(inline, "\n")))
}

// Parse reads the hostsfile and populates the byName and addr maps.
func (h HostsWC) parse(r io.Reader) *Map {
	hmap := newMap()

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Bytes()
		if i := bytes.Index(line, []byte{'#'}); i >= 0 {
			// Discard comments.
			line = line[0:i]
		}
		f := bytes.Fields(line)
		if len(f) < 2 {
			continue
		}
		addr := parseIP(string(f[0]))
		if addr == nil {
			continue
		}

		family := 0
		if addr.To4() != nil {
			family = 1
		} else {
			family = 2
		}

		for i := 1; i < len(f); i++ {
			name := plugin.Name(string(f[i])).Normalize()
			if plugin.Zones(h.Origins).Matches(name) == "" {
				// name is not in Origins
				continue
			}
			switch family {
			case 1:
				hmap.name4[name] = append(hmap.name4[name], addr)
			case 2:
				hmap.name6[name] = append(hmap.name6[name], addr)
			default:
				continue
			}
			if !h.options.autoReverse {
				continue
			}
			hmap.addr[addr.String()] = append(hmap.addr[addr.String()], name)
		}
	}

	return hmap
}

func (h HostsWC) lookupStaticHostWithWildCards(m map[string][]net.IP, name string) ([]net.IP, bool) {
	var ips []net.IP

	wildcards := make([]string, 0)

	for k := range m {
		if k[:2] == "*." {
			wildcards = append(wildcards, k)
		}
	}

	for _, w := range wildcards {
		if strings.HasSuffix(name, w[2:]) {
			ips = append(ips, m[w]...)
		}
	}

	if ip, ok := m[name]; ok {
		ips = append(ips, ip...)
	}

	if len(ips) == 0 {
		return nil, false
	}

	return ips, true
}

// lookupStaticHost looks up the IP addresses for the given host from the hosts file.
func (h HostsWC) lookupStaticHost(m map[string][]net.IP, host string) []net.IP {
	if len(m) == 0 {
		return nil
	}

	ips, ok := h.lookupStaticHostWithWildCards(m, host)
	if !ok {
		return nil
	}
	ipsCp := make([]net.IP, len(ips))
	copy(ipsCp, ips)
	return ipsCp
}

// LookupStaticHostV4 looks up the IPv4 addresses for the given host from the hosts file.
func (h HostsWC) LookupStaticHostV4(host string) []net.IP {
	host = strings.ToLower(host)
	ip := h.lookupStaticHost(h.inline.name4, host)
	return ip
}

// LookupStaticHostV6 looks up the IPv6 addresses for the given host from the hosts file.
func (h HostsWC) LookupStaticHostV6(host string) []net.IP {
	host = strings.ToLower(host)
	ip := h.lookupStaticHost(h.inline.name6, host)
	return ip
}

// LookupStaticAddr looks up the hosts for the given address from the hosts file.
func (h HostsWC) LookupStaticAddr(addr string) []string {
	addr = parseIP(addr).String()
	if addr == "" {
		return nil
	}

	hosts := h.inline.addr[addr]

	if len(hosts) == 0 {
		return nil
	}

	hostsCp := make([]string, len(hosts))
	copy(hostsCp, hosts)
	return hostsCp
}

func (h HostsWC) otherRecordsExist(qname string) bool {
	if len(h.LookupStaticHostV4(qname)) > 0 {
		return true
	}
	if len(h.LookupStaticHostV6(qname)) > 0 {
		return true
	}
	return false
}

// a takes a slice of net.IPs and returns a slice of A RRs.
func a(zone string, ttl uint32, ips []net.IP) []dns.RR {
	answers := make([]dns.RR, len(ips))
	for i, ip := range ips {
		r := new(dns.A)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
		r.A = ip
		answers[i] = r
	}
	return answers
}

// aaaa takes a slice of net.IPs and returns a slice of AAAA RRs.
func aaaa(zone string, ttl uint32, ips []net.IP) []dns.RR {
	answers := make([]dns.RR, len(ips))
	for i, ip := range ips {
		r := new(dns.AAAA)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
		r.AAAA = ip
		answers[i] = r
	}
	return answers
}

// ptr takes a slice of host names and filters out the ones that aren't in Origins, if specified, and returns a slice of PTR RRs.
func (h *HostsWC) ptr(zone string, ttl uint32, names []string) []dns.RR {
	answers := make([]dns.RR, len(names))
	for i, n := range names {
		r := new(dns.PTR)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl}
		r.Ptr = dns.Fqdn(n)
		answers[i] = r
	}
	return answers
}
