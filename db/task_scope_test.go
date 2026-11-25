package db

import (
	"database/sql/driver"
	"fmt"
	"strings"
	"testing"
)

// TestStripHostPort covers the ip:port / [ipv6]:port stripping used by the
// ip/cidr scope path so a target like "10.0.188.136:3000" no longer 404s.
func TestStripHostPort(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.0.188.136:3000", "10.0.188.136"},          // the reported IP case
		{"10.0.188.136", "10.0.188.136"},               // bare IPv4 unchanged
		{"[2001:db8::1]:8080", "2001:db8::1"},          // bracketed IPv6 + port
		{"2001:db8::1", "2001:db8::1"},                 // bare IPv6 unchanged (has colons)
		{" 1.2.3.4:80 ", "1.2.3.4"},                    // trims surrounding space
		{"example.com:443", "example.com"},             // domain + port → bare host
		{"api.example.com:8080", "api.example.com"},    // subdomain + port
		{"example.com", "example.com"},                 // bare domain unchanged
	}
	for _, c := range cases {
		if got := stripHostPort(c.in); got != c.want {
			t.Errorf("stripHostPort(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBuildCoverageGraphHandlesReallocation(t *testing.T) {
	// Return 40 subdomains + services + endpoints so g.Nodes reallocates
	// repeatedly, verifying map[string]struct{} membership & edge linking.
	var assetRows [][]driver.Value
	for i := int64(1); i <= 40; i++ {
		sub := fmt.Sprintf("sub-%d.example.test", i)
		assetRows = append(assetRows,
			[]driver.Value{
				i, "subdomain", int64(7), sub, "example.test", "", "", int64(0), "", "", "", int64(0), i%2 == 0,
			},
			[]driver.Value{
				100 + i, "service", int64(7), sub, "example.test", "", "https://" + sub, int64(443), "http", "", "", int64(200), false,
			},
		)
	}
	st := &stubSQLState{
		queryHandler: func(_ int, _ bool, query string, _ []any) ([]string, [][]driver.Value, error) {
			switch {
			case strings.Contains(query, "FROM assets a JOIN target"):
				return []string{"id", "type", "company_id", "domain", "root_domain", "ip", "url", "port", "service_type", "app_name", "page_title", "status_code", "tested"}, assetRows, nil
			case strings.Contains(query, "SELECT DISTINCT ON (domain)"):
				return []string{"domain", "id", "company_id"}, [][]driver.Value{{"example.test", int64(500), int64(7)}}, nil
			case strings.Contains(query, "FROM companies"):
				return []string{"id", "name"}, [][]driver.Value{{int64(7), "Example Corp"}}, nil
			default:
				return []string{"col"}, nil, nil
			}
		},
	}
	d := st.openDB()
	defer d.Close()

	graph, err := d.Assets().BuildCoverageGraph(1, 0)
	if err != nil {
		t.Fatalf("BuildCoverageGraph: %v", err)
	}
	// 80 in-scope assets + 1 connector root_domain + 1 company = 82 nodes.
	if len(graph.Nodes) != 82 {
		t.Fatalf("nodes=%d want 82", len(graph.Nodes))
	}
	// 40 subdomain->root + 40 service->subdomain + 1 root->company = 81 edges.
	if len(graph.Edges) != 81 {
		t.Fatalf("edges=%d want 81", len(graph.Edges))
	}
}
