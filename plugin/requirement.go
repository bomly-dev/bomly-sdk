package plugin

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
)

// Requirement names one class of pipeline input, or one host capability, a
// component needs before it can do useful work: a source tree to read, a
// dependency graph to walk, vulnerability records to annotate. A descriptor
// declares them in Requires so a host can explain an impossible plan --
// "this analyzer needs a source tree and the target is an SBOM" -- before
// running anything, and so generated documentation can say what a
// component needs.
//
// A requirement names data, never a provider. A matcher may require
// vulnerability records; it may not require "plugin X", because which
// component produces the records is the host's selection and fallback
// policy, and a named dependency would turn the fixed pipeline into a
// service scheduler. The vocabulary has no way to spell a provider.
//
// Declarations are advisory to the plan and never replace the runtime
// checks: a host that finds every requirement satisfied still calls Ready
// and Applicable, which remain authoritative. A descriptor that declares
// nothing is legacy -- its requirements are unspecified, not empty -- and a
// host treats it exactly as it treated every component before Requires
// existed.
//
// Tokens are versioned ("<name>-v<N>") and the vocabulary is open: a token
// this SDK does not know still validates if it is well formed, survives the
// wire, and must be treated as unsatisfied by a host that does not know it,
// since a host cannot vouch for an input it has never heard of. A new
// meaning gets a new token or a new version, never a changed meaning for an
// existing one.
type Requirement string

const (
	// RequirementSourceTree: the target is a source tree the component can
	// read -- a filesystem checkout or a Git repository -- rather than an
	// SBOM document or a container image. Reachability analyzers and
	// lockfile detectors need it.
	RequirementSourceTree Requirement = "source-tree-v1"
	// RequirementDependencyGraph: the request carries a dependency graph
	// with at least one dependency node, produced by an earlier stage.
	RequirementDependencyGraph Requirement = "dependency-graph-v1"
	// RequirementVulnerabilityRecords: the registry carries vulnerability
	// records, which a vulnerability matcher earlier in the pipeline
	// supplies. Analyzers that annotate reachability need it.
	RequirementVulnerabilityRecords Requirement = "vulnerability-records-v1"
)

// knownRequirements is this SDK's vocabulary, in a fixed order.
var knownRequirements = []Requirement{
	RequirementDependencyGraph,
	RequirementSourceTree,
	RequirementVulnerabilityRecords,
}

// KnownRequirements returns every requirement this SDK defines, sorted.
func KnownRequirements() []Requirement {
	return slices.Clone(knownRequirements)
}

// Known reports whether r is in this SDK's vocabulary. A host must treat a
// requirement that is not known as unsatisfied.
func (r Requirement) Known() bool {
	return slices.Contains(knownRequirements, r)
}

// MaxRequirements bounds how many requirements one descriptor may declare,
// and MaxRequirementLength how long one token may be. Both are resource
// bounds on untrusted descriptor input, not vocabulary.
const (
	MaxRequirements      = 16
	MaxRequirementLength = 64
)

// requirementGrammar is the token shape: lower-case words joined by
// hyphens, ending in a version.
var requirementGrammar = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*-v[1-9][0-9]*$`)

// Requirements is a descriptor's declared prerequisite list. Its JSON codec
// writes and reads it deduplicated and sorted, so two descriptors that
// declare the same set encode the same way and a host never sees order as
// meaning; it never drops an entry, so a token the host does not know
// reaches the host's conservative handling instead of disappearing.
type Requirements []Requirement

// Normalized returns the requirements deduplicated and sorted; nil when
// empty, so an empty declaration and an absent one encode alike.
func (r Requirements) Normalized() Requirements {
	if len(r) == 0 {
		return nil
	}
	out := slices.Clone(r)
	slices.Sort(out)
	return slices.Compact(out)
}

// MarshalJSON writes the normalized list.
func (r Requirements) MarshalJSON() ([]byte, error) {
	return json.Marshal([]Requirement(r.Normalized()))
}

// maxRequirementsBytes bounds an encoded declaration before it is parsed:
// a generous multiple of the largest list Validate accepts, so the limit
// rejects only input no valid descriptor could be.
const maxRequirementsBytes = 4 << 10

// UnmarshalJSON reads a list and normalizes it. The input is bounded before
// it is parsed, and the decoded list is held to MaxRequirements before it is
// deduplicated, so a repeated token cannot pass the bound by collapsing.
func (r *Requirements) UnmarshalJSON(data []byte) error {
	if len(data) > maxRequirementsBytes {
		return fmt.Errorf("requirements exceed %d bytes", maxRequirementsBytes)
	}
	var decoded []Requirement
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if len(decoded) > MaxRequirements {
		return fmt.Errorf("declares %d requirements, more than %d", len(decoded), MaxRequirements)
	}
	*r = Requirements(decoded).Normalized()
	return nil
}

// Validate checks the declaration's shape: at most MaxRequirements tokens,
// each well formed and at most MaxRequirementLength bytes. It does not
// require a token to be known -- the vocabulary is open -- so a descriptor
// written against a newer SDK still validates on an older host.
func (r Requirements) Validate() error {
	if len(r) > MaxRequirements {
		return fmt.Errorf("declares %d requirements, more than %d", len(r), MaxRequirements)
	}
	for _, requirement := range r {
		if len(requirement) > MaxRequirementLength {
			return fmt.Errorf("requirement %.32q... exceeds %d bytes", requirement, MaxRequirementLength)
		}
		if !requirementGrammar.MatchString(string(requirement)) {
			return fmt.Errorf("requirement %q is not a versioned token such as %q", requirement, RequirementSourceTree)
		}
	}
	return nil
}

// Unsatisfied returns the requirements in r that available does not
// contain, normalized. available is what the host can vouch for at the
// point it plans the component -- the requirements it knows and finds met
// -- so a token the host does not know is never in it and always comes
// back unsatisfied. A nil result means every declared requirement is met;
// it says nothing about a legacy descriptor that declared none.
func (r Requirements) Unsatisfied(available []Requirement) Requirements {
	var missing Requirements
	for _, requirement := range r.Normalized() {
		if !slices.Contains(available, requirement) {
			missing = append(missing, requirement)
		}
	}
	return missing
}
