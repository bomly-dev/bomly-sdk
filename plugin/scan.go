package plugin

import (
	"encoding/json"
	"strings"

	"github.com/bomly-dev/bomly-sdk/model"
)

// ExecutionTargetKind identifies the top-level source selected by the user for one scan execution.
type ExecutionTargetKind string

const (
	// ExecutionTargetFilesystem points at a local filesystem path. The path may be a
	// directory or a single file depending on the selected scan target.
	ExecutionTargetFilesystem ExecutionTargetKind = "filesystem"
	// ExecutionTargetWorkingDirectory is kept as an alias for the existing local-path model.
	ExecutionTargetWorkingDirectory ExecutionTargetKind = ExecutionTargetFilesystem
	ExecutionTargetGitRepository    ExecutionTargetKind = "git-repository"
	ExecutionTargetContainerImage   ExecutionTargetKind = "container-image"
)

// ExecutionTarget names what one scan execution reads: a filesystem path,
// a repository at a ref, or a container image. Gate: CommitSHA passes
// NormalizeCommitSHA in the JSON codec on both directions, so a ref name or
// a padded hash a producer wrote in its place is cleared at the wire rather
// than carried as a commit; the other fields are trimmed.
type ExecutionTarget struct {
	Kind          ExecutionTargetKind `json:"kind,omitempty"`
	Location      string              `json:"location,omitempty"`
	RepositoryURL string              `json:"repositoryUrl,omitempty"`
	Ref           string              `json:"ref,omitempty"`
	// CommitSHA is the commit the scan actually ran against, resolved from
	// Ref by the host: Ref is what was asked for, CommitSHA is what was
	// found. Gate: NormalizeCommitSHA, applied by the producer. Optional;
	// empty when the target is not a revision of a repository.
	CommitSHA string `json:"commitSha,omitempty"`
}

// Normalized returns the target held to its gate.
func (t ExecutionTarget) Normalized() ExecutionTarget {
	return ExecutionTarget{
		Kind:          ExecutionTargetKind(strings.TrimSpace(string(t.Kind))),
		Location:      strings.TrimSpace(t.Location),
		RepositoryURL: strings.TrimSpace(t.RepositoryURL),
		Ref:           strings.TrimSpace(t.Ref),
		CommitSHA:     NormalizeCommitSHA(t.CommitSHA),
	}
}

// executionTargetWire is the codec's shape: the same fields without the
// methods, so the gate runs once on each direction without recursing.
type executionTargetWire ExecutionTarget

// MarshalJSON writes the gated form.
func (t ExecutionTarget) MarshalJSON() ([]byte, error) {
	return json.Marshal(executionTargetWire(t.Normalized()))
}

// UnmarshalJSON reads through the gate, so a managed component's payload
// cannot put a non-commit on CommitSHA.
func (t *ExecutionTarget) UnmarshalJSON(data []byte) error {
	var wire executionTargetWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*t = ExecutionTarget(wire).Normalized()
	return nil
}

// NormalizeCommitSHA returns value as a lowercase hexadecimal commit
// identifier of 7 to 64 digits -- an abbreviated or full SHA-1, or a
// SHA-256 -- or "" when value is not one. A producer applies it before
// recording ExecutionTarget.CommitSHA so a ref name or a path can never be
// mistaken for a commit.
func NormalizeCommitSHA(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) < 7 || len(value) > 64 {
		return ""
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	return value
}

// Subproject identifies one package-manager root discovered beneath the execution target.
type Subproject struct {
	ExecutionTarget         ExecutionTarget        `json:"executionTarget"`
	RelativePath            string                 `json:"relativePath,omitempty"`
	PrimaryDetector         string                 `json:"primaryDetector,omitempty"`
	DetectedPackageManagers []model.PackageManager `json:"detectedPackageManagers,omitempty"`
	PlannedDetectors        []string               `json:"plannedDetectors,omitempty"`
	Ecosystem               model.Ecosystem        `json:"ecosystem,omitempty"`
}

// PrimaryPackageManager returns the first entry in DetectedPackageManagers, or
// PackageManagerUnknown if the list is empty.
func (s Subproject) PrimaryPackageManager() model.PackageManager {
	if len(s.DetectedPackageManagers) == 0 || s.ExecutionTarget.Kind == ExecutionTargetContainerImage {
		return model.PackageManagerUnknown
	}
	return s.DetectedPackageManagers[0]
}

// PackageQuery identifies a specific package target.
type PackageQuery struct {
	Name string `json:"name,omitempty"`
	ID   string `json:"id,omitempty"`
}
