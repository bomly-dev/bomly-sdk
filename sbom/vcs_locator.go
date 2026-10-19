package sbom

import "strings"

// vcsLocator renders a repository origin in the version-control locator
// grammar: "git+<url>", with "@<revision>" appended when a revision is
// recorded. The grammar is SPDX 2.3's (section 7.7, Package download
// location: "<vcs_tool>+<transport>://<host_name>[/<path_to_repository>]
// [@<revision>][#<sub_path>]") and the package-URL specification's for the
// vcs_url qualifier, which spells it the same way. It has no query component
// and no room for anything but the revision after "@", which is why the
// origin invariant strips both before a URL gets here.
//
// Both encoders write this one string for a pinned origin, so a consumer
// reading the SPDX and the CycloneDX export of one scan finds the same
// locator in each (bomly-cli issue #508). An empty repository yields "".
func vcsLocator(repository, revision string) string {
	repository = strings.TrimSpace(repository)
	if repository == "" {
		return ""
	}
	locator := "git+" + repository
	if revision = strings.TrimSpace(revision); revision != "" {
		locator += "@" + revision
	}
	return locator
}

// pinnedVCSReference is the URL a CycloneDX vcs reference carries for a
// repository origin: the locator above when a revision is recorded, and the
// plain repository URL when none is.
//
// CycloneDX defines the vcs reference type only as "Version Control System"
// (bom-1.6.schema.json, externalReference.type meta:enum) and types the url
// as an IRI reference, so it neither offers a revision slot nor forbids one
// in the URL. Where the format is silent the choice is Bomly's, and it is
// made for the reader: a pinned origin is written in the locator grammar
// because that is the one form consumers already parse a revision from, and
// an unpinned one stays the location a reader can open, since the grammar
// adds nothing to it.
func pinnedVCSReference(repository, revision string) string {
	if strings.TrimSpace(revision) == "" {
		return strings.TrimSpace(repository)
	}
	return vcsLocator(repository, revision)
}
