// Package plugin is the contract a Bomly component implements: the Detector,
// Matcher, Auditor, and Analyzer interfaces with their descriptors, request
// and response types, the Base* defaults that insulate an implementation from
// interface growth, and Module, which packages one component with its
// constructor so the same value runs embedded in the host or served as a
// managed plugin.
//
// A component reaches host services only through HostContext -- a logger, an
// HTTP client provider, runtime information, and DecodeConfig for its own
// configuration block -- and is otherwise a pure function of its request. It
// does not know which execution mode it is in: the embedded host and the
// managed transport (the runtime package) both satisfy HostContext.
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
