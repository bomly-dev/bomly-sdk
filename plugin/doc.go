// Package plugin is the contract a Bomly component implements: the Detector,
// Matcher, Auditor, and Analyzer interfaces with their descriptors, request
// and response types, the Base* defaults that insulate an implementation from
// interface growth, and Module, which packages one component with its
// constructor so the same value runs embedded in the host or served as a
// managed plugin.
//
// A component reaches host services only through HostContext -- a logger, an
// HTTP client provider, runtime information, DecodeConfig for its own
// configuration block, and OnCleanup for releasing what it acquired -- and is
// otherwise a pure function of its request. It does not know which execution
// mode it is in: the embedded host and the managed transport (the runtime
// package) both satisfy HostContext, and both give it the same lifetime. Its
// constructor's context lasts as long as the component, and the cleanups it
// registers run in reverse order when that lifetime ends; ComponentScope is
// the implementation a host uses.
//
// A descriptor may declare the pipeline inputs its component needs in
// Requires (see Requirement), so a host can explain an impossible plan before
// running it; Ready and Applicable still decide at run time. A managed
// plugin's manifest may disclose the access it expects (see Access), which a
// host shows the user as an unverified claim before the plugin is enabled.
//
// A matcher or analyzer receives a copy of the host's graph and registry
// (MatchRequest.Clone, AnalyzeRequest.Clone), and the host keeps what it
// returns only when the call succeeds: changing the request in place and then
// failing leaves the host's state as it was, in both execution modes.
//
// A plugin binary packages its component as a Module and serves it from main
// through the runtime package:
//
//	func main() {
//		runtime.ServeModule(myModule)
//	}
//
// Descriptors are validated at every entry point (ValidateDetectorDescriptor
// and its siblings, ValidateModule), and a descriptor's ConfigSchema is
// derived from the component's own config struct with ConfigSchemaFor. The
// request and response types here, together with the model package they
// carry, are the JSON payloads of the bomly.plugin.v1 protocol; their tags
// are the wire schema and only grow additively.
package plugin
