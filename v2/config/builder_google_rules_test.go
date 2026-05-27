// builder_google_rules_test.go
// 验证 Google 相关域名在地区分流前优先走远程 DNS 和代理。
// 目的：即使用户手动选择 cn 分流，Google 域名也不能因 DNS 污染命中 geoip-cn 后直连。
// 规则顺序是核心行为：Google 优先规则必须排在 region direct 规则之前。
package config

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestGoogleRulesPrecedeRegionalDirectRules(t *testing.T) {
	hopt := DefaultHiddifyOptions()
	hopt.Region = "cn"

	options := option.Options{}
	staticIPs := map[string][]string{}
	if err := setDns(&options, hopt, &staticIPs); err != nil {
		t.Fatalf("setDns() error = %v", err)
	}
	if err := setRoutingOptions(&options, hopt); err != nil {
		t.Fatalf("setRoutingOptions() error = %v", err)
	}
	if options.Route == nil {
		t.Fatal("options.Route is nil")
	}

	googleRouteIndex := -1
	regionRouteIndex := -1
	for i, rule := range options.Route.Rules {
		defaultRule := rule.DefaultOptions
		if testContains(defaultRule.DomainSuffix, "google.com") &&
			defaultRule.RouteOptions.Outbound == OutboundMainDetour {
			googleRouteIndex = i
		}
		if testContains(defaultRule.RuleSet, "geoip-cn") &&
			testContains(defaultRule.RuleSet, "geosite-cn") &&
			defaultRule.RouteOptions.Outbound == OutboundDirectTag {
			regionRouteIndex = i
		}
	}

	if googleRouteIndex == -1 {
		t.Fatal("missing Google route rule to proxy detour")
	}
	if regionRouteIndex == -1 {
		t.Fatal("missing cn regional direct route rule")
	}
	if googleRouteIndex >= regionRouteIndex {
		t.Fatalf("Google route rule index %d must precede regional direct route index %d", googleRouteIndex, regionRouteIndex)
	}
}

func TestGoogleDnsRulesPrecedeRegionalDirectDnsRules(t *testing.T) {
	hopt := DefaultHiddifyOptions()
	hopt.Region = "cn"

	options := option.Options{}
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

	googleDnsIndex := -1
	regionDnsIndex := -1
	for i, rule := range options.DNS.Rules {
		defaultRule := rule.DefaultOptions
		if testContains(defaultRule.DomainSuffix, "google.com") &&
			defaultRule.RouteOptions.Server == DNSMultiRemoteTag {
			googleDnsIndex = i
		}
		if testContains(defaultRule.RuleSet, "geosite-cn") &&
			defaultRule.RouteOptions.Server == DNSMultiDirectTag {
			regionDnsIndex = i
		}
	}

	if googleDnsIndex == -1 {
		t.Fatal("missing Google DNS rule to remote DNS")
	}
	if regionDnsIndex == -1 {
		t.Fatal("missing cn regional direct DNS rule")
	}
	if googleDnsIndex >= regionDnsIndex {
		t.Fatalf("Google DNS rule index %d must precede regional direct DNS index %d", googleDnsIndex, regionDnsIndex)
	}
}

func testContains[T comparable](items []T, want T) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
