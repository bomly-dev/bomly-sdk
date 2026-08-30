package sdk

// DependencySource describes how a dependency occurrence is resolved.
type DependencySource string

const (
	DependencySourceRegistry  DependencySource = "registry"
	DependencySourceProject   DependencySource = "project"
	DependencySourceWorkspace DependencySource = "workspace"
	DependencySourceFile      DependencySource = "file"
	DependencySourceGit       DependencySource = "git"
	DependencySourceURL       DependencySource = "url"
)

// RegistryMatchEligible reports whether this dependency may be sent to
// external package matchers. Ownership and structure are the node kind
// under the union — module and manifest nodes cannot reach this method —
// so only the source classification decides. Project, workspace, file,
// Git, and arbitrary URL records are normally excluded. Swift
// source-control packages remain eligible because their repository URL is
// the canonical SwiftURL package identity used by vulnerability sources.
// An omitted source stays eligible for protocol-v1 and legacy detector
// compatibility. Graph insertion folds eligibility toward eligible: when
// records of one identity disagree, the eligible witness's source
// survives.
func (d *DependencyNode) RegistryMatchEligible() bool {
	if d == nil {
		return false
	}
	if d.Ecosystem == EcosystemSwift && d.Source == DependencySourceGit {
		return true
	}
	switch d.Source {
	case DependencySourceProject, DependencySourceWorkspace, DependencySourceFile, DependencySourceGit, DependencySourceURL:
		return false
	case DependencySourceRegistry, "":
		return true
	default:
		// Custom plugin source values predate this classification. Preserve
		// matching until the plugin explicitly adopts a non-registry source.
		return true
	}
}
