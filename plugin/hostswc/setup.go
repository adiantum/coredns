package hostswc

import (
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

//var log = clog.NewWithPlugin("hostswc")

func init() { plugin.Register("hostswc", setup) }

func setup(c *caddy.Controller) error {
	h, err := hostsParse(c)
	if err != nil {
		return plugin.Error("hostswc", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		h.Next = next
		return h
	})

	return nil
}

func hostsParse(c *caddy.Controller) (HostsWC, error) {
	h := &HostsWC{
		inline:  newMap(),
		options: newOptions(),
	}

	inline := []string{}
	i := 0
	for c.Next() {
		if i > 0 {
			return *h, plugin.ErrOnce
		}
		i++

		args := c.RemainingArgs()

		h.Origins = plugin.OriginsFromArgsOrServerBlock(args, c.ServerBlockKeys)

		for c.NextBlock() {
			switch c.Val() {
			case "fallthrough":
				h.Fall.SetZonesFromArgs(c.RemainingArgs())
			case "no_reverse":
				h.options.autoReverse = false
			case "ttl":
				remaining := c.RemainingArgs()
				if len(remaining) < 1 {
					return *h, c.Errf("ttl needs a time in second")
				}
				ttl, err := strconv.Atoi(remaining[0])
				if err != nil {
					return *h, c.Errf("ttl needs a number of second")
				}
				if ttl <= 0 || ttl > 65535 {
					return *h, c.Errf("ttl provided is invalid")
				}
				h.options.ttl = uint32(ttl)
			case "reload":
				remaining := c.RemainingArgs()
				if len(remaining) != 1 {
					return *h, c.Errf("reload needs a duration (zero seconds to disable)")
				}
				reload, err := time.ParseDuration(remaining[0])
				if err != nil {
					return *h, c.Errf("invalid duration for reload '%s'", remaining[0])
				}
				if reload < 0 {
					return *h, c.Errf("invalid negative duration for reload '%s'", remaining[0])
				}
				h.options.reload = reload
			default:
				if len(h.Fall.Zones) == 0 {
					line := strings.Join(append([]string{c.Val()}, c.RemainingArgs()...), " ")
					inline = append(inline, line)
					continue
				}
				return *h, c.Errf("unknown property '%s'", c.Val())
			}
		}
	}

	h.initInline(inline)

	return *h, nil
}
