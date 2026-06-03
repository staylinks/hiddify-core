// builder_google_rules_test.go
// 验证 Google 相关域名的路由与 DNS 行为。
// 核心行为：
//   - routeRules 中 Google 代理规则必须排在 geoip/geosite-cn 直连规则之前。
//   - TUN 模式下，Google DNS 由 FakeDNS 兜底（不再走 dns-remote），
//     避免 dns-remote 因代理未就绪而阻塞，同时彻底绕开 DNS 污染。
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

// TestGoogleDnsTunModeUsesFakeDNS 验证 TUN 模式下 Google 域名走 FakeDNS 而不是 dns-remote。
// 原因：dns-remote 通过代理出口发 DNS 请求，代理启动初期未就绪会造成
// google.com DNS 失败，进而导致 Google 类地址在 VPN 模式下完全不通。
// FakeDNS 是本地服务，永远可用，且通过 FakeIP → 域名还原，路由规则可正确命中
// googleProxyRouteRule，由代理出口侧解析真实 IP。
func TestGoogleDnsTunModeUsesFakeDNS(t *testing.T) {
	hopt := DefaultHiddifyOptions()
	hopt.Region = "cn"
	hopt.EnableTun = true // TUN/VPN 模式

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

	// TUN 模式下不应存在 Google dns-remote 规则（移除后 FakeDNS 兜底）
	for _, rule := range options.DNS.Rules {
		d := rule.DefaultOptions
		if testContains(d.DomainSuffix, "google.com") && d.RouteOptions.Server == DNSMultiRemoteTag {
			t.Fatal("TUN mode must not have Google-specific dns-remote rule: causes chicken-and-egg with proxy startup")
		}
	}

	// FakeDNS server 必须存在
	if !hasDnsServerTag(options.DNS.Servers, DNSFakeTag) {
		t.Fatalf("TUN mode must have FakeDNS server [%s]", DNSFakeTag)
	}

	// FakeDNS catch-all 规则（A/AAAA）必须存在，且 google.com 的 A/AAAA 查询会被它兜底
	if !hasFakeDnsCatchAllRule(options.DNS.Rules) {
		t.Fatal("TUN mode must have FakeDNS catch-all rule for A/AAAA queries")
	}
}

// TestGoogleDnsSystemProxyModeNoSpecialRule 验证 systemProxy 模式下 Google DNS 走兜底 dns-remote（正常路径）。
func TestGoogleDnsSystemProxyModeNoSpecialRule(t *testing.T) {
	hopt := DefaultHiddifyOptions()
	hopt.Region = "cn"
	hopt.EnableTun = false
	hopt.SetSystemProxy = true

	options := option.Options{}
	staticIPs := map[string][]string{}
	if err := setDns(&options, hopt, &staticIPs); err != nil {
		t.Fatalf("setDns() error = %v", err)
	}
	if err := setRoutingOptions(&options, hopt); err != nil {
		t.Fatalf("setRoutingOptions() error = %v", err)
	}

	// systemProxy 模式下没有 FakeDNS，Google DNS 走 Final=dns-remote（兜底），正常
	if hasDnsServerTag(options.DNS.Servers, DNSFakeTag) {
		t.Fatal("systemProxy mode must not have FakeDNS server")
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
