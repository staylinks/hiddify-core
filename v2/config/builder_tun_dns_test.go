// builder_tun_dns_test.go
// 锁定 TUN 模式下的 DNS 接管行为。
// 目标：VPN/TUN 模式必须默认具备 fake DNS，避免浏览器先在系统层把 Google 类域名解析成被污染 IP，
// 使后续的域名规则失效；而 system proxy 模式不应被这条默认行为影响。
package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestTunModeInjectsFakeDnsByDefault(t *testing.T) {
	hopt := DefaultHiddifyOptions()
	hopt.EnableTun = true
	hopt.EnableFakeDNS = false

	options := optionOptionsForTest()
	staticIPs := map[string][]string{}
	if err := setDns(&options, hopt, &staticIPs); err != nil {
		t.Fatalf("setDns() error = %v", err)
	}
	if err := setRoutingOptions(&options, hopt); err != nil {
		t.Fatalf("setRoutingOptions() error = %v", err)
	}
	if options.DNS == nil {
		t.Fatal("options.DNS is nil")
	}

	if !hasDnsServerTag(options.DNS.Servers, DNSFakeTag) {
		t.Fatalf("TUN mode must inject fake DNS server [%s]", DNSFakeTag)
	}
	if !hasFakeDnsCatchAllRule(options.DNS.Rules) {
		t.Fatal("TUN mode must inject catch-all fake DNS rule for A/AAAA queries")
	}
}

func TestSystemProxyModeDoesNotInjectFakeDnsByDefault(t *testing.T) {
	hopt := DefaultHiddifyOptions()
	hopt.EnableTun = false
	hopt.SetSystemProxy = true
	hopt.EnableFakeDNS = false

	options := optionOptionsForTest()
	staticIPs := map[string][]string{}
	if err := setDns(&options, hopt, &staticIPs); err != nil {
		t.Fatalf("setDns() error = %v", err)
	}
	if err := setRoutingOptions(&options, hopt); err != nil {
		t.Fatalf("setRoutingOptions() error = %v", err)
	}
	if options.DNS == nil {
		t.Fatal("options.DNS is nil")
	}

	if hasDnsServerTag(options.DNS.Servers, DNSFakeTag) {
		t.Fatalf("system proxy mode must not inject fake DNS server [%s] by default", DNSFakeTag)
	}
	if hasFakeDnsCatchAllRule(options.DNS.Rules) {
		t.Fatal("system proxy mode must not inject catch-all fake DNS rule by default")
	}
}

func optionOptionsForTest() option.Options {
	return option.Options{}
}

func hasDnsServerTag(servers []option.DNSServerOptions, want string) bool {
	for _, server := range servers {
		if server.Tag == want {
			return true
		}
	}
	return false
}

func hasFakeDnsCatchAllRule(rules []option.DNSRule) bool {
	for _, rule := range rules {
		defaultRule := rule.DefaultOptions
		if defaultRule.RouteOptions.Server == DNSFakeTag &&
			defaultRule.DNSRuleAction.Action == C.RuleActionTypeRoute &&
			len(defaultRule.QueryType) == 2 {
			return true
		}
	}
	return false
}
