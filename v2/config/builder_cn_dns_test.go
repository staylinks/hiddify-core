// builder_cn_dns_test.go
// 锁定 region=cn 下国内站 DNS 与路由行为。
// TUN/FakeDNS：客户端 DNS 不得再被 geosite-cn / .cn 强制到 dns-direct（失败即死、无法回退 FakeDNS）；
// 路由直连规则必须保留。systemProxy：保留原 DNS 分流。
package config

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestTunCnSkipsRegionalDirectDnsRules(t *testing.T) {
	hopt := DefaultHiddifyOptions()
	hopt.Region = "cn"
	hopt.EnableTun = true

	options := option.Options{}
	staticIPs := map[string][]string{}
	if err := setDns(&options, hopt, &staticIPs); err != nil {
		t.Fatalf("setDns() error = %v", err)
	}
	if err := setRoutingOptions(&options, hopt); err != nil {
		t.Fatalf("setRoutingOptions() error = %v", err)
	}
	if options.DNS == nil || options.Route == nil {
		t.Fatal("DNS/Route must be set")
	}

	for _, rule := range options.DNS.Rules {
		d := rule.DefaultOptions
		if testContains(d.DomainSuffix, ".cn") && d.RouteOptions.Server == DNSMultiDirectTag {
			t.Fatal("TUN+cn must not force DomainSuffix=.cn DNS to dns-direct; FakeDNS should cover client queries")
		}
		if testContains(d.RuleSet, "geosite-cn") && d.RouteOptions.Server == DNSMultiDirectTag {
			t.Fatal("TUN+cn must not force geosite-cn DNS to dns-direct; FakeDNS should cover client queries")
		}
	}

	if !hasFakeDnsCatchAllRule(options.DNS.Rules) {
		t.Fatal("TUN+cn must keep FakeDNS catch-all for A/AAAA")
	}

	hasSuffixDirect := false
	hasGeositeDirect := false
	for _, rule := range options.Route.Rules {
		d := rule.DefaultOptions
		if testContains(d.DomainSuffix, ".cn") && d.RouteOptions.Outbound == OutboundDirectTag {
			hasSuffixDirect = true
		}
		if testContains(d.RuleSet, "geosite-cn") && d.RouteOptions.Outbound == OutboundDirectTag {
			hasGeositeDirect = true
		}
	}
	if !hasSuffixDirect {
		t.Fatal("TUN+cn must keep DomainSuffix=.cn → direct route")
	}
	if !hasGeositeDirect {
		t.Fatal("TUN+cn must keep geosite-cn → direct route")
	}
}

func TestSystemProxyCnKeepsRegionalDirectDnsRules(t *testing.T) {
	hopt := DefaultHiddifyOptions()
	hopt.Region = "cn"
	hopt.EnableTun = false
	hopt.SetSystemProxy = true
	hopt.EnableFakeDNS = false

	options := option.Options{}
	staticIPs := map[string][]string{}
	if err := setDns(&options, hopt, &staticIPs); err != nil {
		t.Fatalf("setDns() error = %v", err)
	}
	if err := setRoutingOptions(&options, hopt); err != nil {
		t.Fatalf("setRoutingOptions() error = %v", err)
	}

	hasSuffixDns := false
	hasGeositeDns := false
	for _, rule := range options.DNS.Rules {
		d := rule.DefaultOptions
		if testContains(d.DomainSuffix, ".cn") && d.RouteOptions.Server == DNSMultiDirectTag {
			hasSuffixDns = true
		}
		if testContains(d.RuleSet, "geosite-cn") && d.RouteOptions.Server == DNSMultiDirectTag {
			hasGeositeDns = true
		}
	}
	if !hasSuffixDns {
		t.Fatal("systemProxy+cn must keep DomainSuffix=.cn → dns-direct")
	}
	if !hasGeositeDns {
		t.Fatal("systemProxy+cn must keep geosite-cn → dns-direct")
	}
}
