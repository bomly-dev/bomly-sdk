// Package plugin is the managed-plugin runtime: it serves one component as a
// Bomly plugin binary over the HashiCorp go-plugin gRPC transport, and hands
// the host the matching Client for the other end of that connection.
//
// Managed plugins are native Go binaries that Bomly launches as separate
// subprocesses. A plugin implements exactly one externally supported role:
//
//   - detector: reads project evidence and returns dependency graphs
//   - matcher: enriches PURL-keyed package records with vulnerability, license,
//     lifecycle, or other package metadata
//   - auditor: evaluates graph and registry data and emits findings or risk
//     scores
//   - analyzer: runs code analysis (e.g. reachability) over the matched graph
//     and annotates registry vulnerability entries
//
// A plugin binary packages its component as a plugin.Module and serves it
// from main:
//
//	func main() {
//		runtime.ServeModule(myModule)
//	}
//
// ServeModule builds the managed plugin.HostContext (a stderr logger, an HTTP
// client provider from the BOMLY_HTTP_* environment via httpkit, and config
// decoding from the file named by BOMLY_PLUGIN_CONFIG_FILE) and adapts the
// component to the wire protocol. ServeDetector, ServeMatcher, ServeAuditor,
// and ServeAnalyzer serve a hand-written ServedDetector, ServedMatcher,
// ServedAuditor, or ServedAnalyzer directly; they use the same request and
// response types as the in-process contract in the plugin package.
//
// The wire contract, bomly.plugin.v1, is JSON over gRPC and strictly
// additive: every payload type lives in the plugin and model packages,
// where the omitempty coverage tests guard it. Nothing in this package is a
// payload.
//
// On the host side, HandshakeConfig and ClientPluginMap configure a go-plugin
// client, and the dispensed value implements Client.
package runtime
