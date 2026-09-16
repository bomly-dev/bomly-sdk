package detectorkit

import (
	"strings"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// RemediationAdvice builds manager-specific, read-only guidance for a strategy.
// Concrete detectors own this function and the wording it returns.
type RemediationAdvice func(
	action model.RemediationAction,
	name, version, manifestPath string,
) string

// BuildRemediationHints assembles occurrence-scoped hints from a detector's
// graph. It handles only common graph traversal; the calling detector owns its
// advertised actions and manager-specific advice.
func BuildRemediationHints(
	request plugin.RemediationHintRequest,
	manager model.PackageManager,
	actions []model.RemediationAction,
	advice RemediationAdvice,
) plugin.RemediationHintResponse {
	if request.Detection.Graphs == nil || request.Registry == nil || len(actions) == 0 {
		return plugin.RemediationHintResponse{}
	}
	advertised := make(map[model.RemediationAction]struct{}, len(actions))
	for _, action := range actions {
		advertised[action] = struct{}{}
	}

	response := plugin.RemediationHintResponse{}
	for _, entry := range request.Detection.Graphs.Entries {
		if entry.Graph == nil {
			continue
		}
		for _, dependency := range entry.Graph.DependencyNodes() {
			if dependency == nil {
				continue
			}
			packageRef := dependency.PackageRef
			if packageRef == "" {
				packageRef = dependency.NodeID()
			}
			pkg, ok := request.Registry.Get(packageRef)
			if !ok || pkg == nil || pkg.Remediation == nil ||
				pkg.Remediation.Status != model.PackageRemediationComplete ||
				strings.TrimSpace(pkg.Remediation.RecommendedVersion) == "" {
				continue
			}
			dependencyManager := dependency.PackageManager
			if dependencyManager == model.PackageManagerUnknown {
				dependencyManager = request.Detection.SubprojectInfo.PrimaryPackageManager()
			}
			if dependencyManager != manager {
				continue
			}
			hint := plugin.RemediationHint{
				DependencyRef: dependency.NodeID(),
				ManifestPath:  entry.Manifest.Path,
			}
			for _, action := range remediationActionOrder {
				if _, ok := advertised[action]; !ok {
					continue
				}
				strategy := plugin.RemediationStrategyHint{
					Action: action,
				}
				if advice != nil {
					strategy.Advice = advice(
						action,
						dependency.DisplayName(),
						pkg.Remediation.RecommendedVersion,
						entry.Manifest.Path,
					)
				}
				hint.Strategies = append(hint.Strategies, strategy)
			}
			if len(hint.Strategies) > 0 {
				response.Hints = append(response.Hints, hint)
			}
		}
	}
	return response
}

var remediationActionOrder = []model.RemediationAction{
	model.RemediationActionDirectBump,
	model.RemediationActionTransitiveOverride,
	model.RemediationActionLockfileRefresh,
}
