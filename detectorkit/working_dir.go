package detectorkit

import (
	"strings"

	"github.com/bomly-dev/bomly-sdk/plugin"
)

// RequestWorkingDir returns the directory a detector should operate in for the
// given request, preferring the explicit project path and falling back to the
// subproject execution target location.
func RequestWorkingDir(req plugin.DetectionRequest) string {
	if wd := strings.TrimSpace(req.ProjectPath); wd != "" {
		return wd
	}
	return strings.TrimSpace(req.ExecutionTarget.Location)
}
