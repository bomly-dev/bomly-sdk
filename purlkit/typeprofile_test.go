package purlkit

import (
	"errors"
	"testing"
)

func TestValidateTypeProfiles(t *testing.T) {
	valid := []string{
		// Profile-satisfying purls for table rows.
		"pkg:maven/org.apache.commons/commons-text@1.10.0",
		"pkg:golang/github.com/google/uuid@v1.6.0",
		"pkg:apk/alpine/curl@7.83.0-r0?arch=x86",
		"pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie",
		"pkg:npm/%40scope/name@1.0.0",
		"pkg:cargo/serde@1.0.0",
		"pkg:pypi/django@4.2",
		"pkg:swid/Acme/example.com/Enterprise%2BServer@1.0.0?tag_id=75b8c285-fa7b-485b-b199-4745e3004d0d",
		// The open vocabulary: unknown types validate on syntax alone.
		"pkg:pokemon/pikachu@25",
		"pkg:groceries/oat-milk@2L?store=local",
		// Library-enforced rows still pass through Validate.
		"pkg:swift/github.com%2Fapple/swift-numerics@1.0.0",
	}
	for _, value := range valid {
		if err := ValidateString(value); err != nil {
			t.Errorf("ValidateString(%q) = %v, want valid", value, err)
		}
	}

	invalid := []string{
		// Profile rules the library does not enforce.
		"pkg:maven/commons-text@1.10.0", // namespace (group ID) required
		"pkg:golang/text@v0.3.5",        // namespace required
		"pkg:apk/curl@7.83.0-r0",        // vendor namespace required
		"pkg:cargo/rust-lang/serde@1.0", // namespace prohibited
		"pkg:pypi/python/django@4.2",    // namespace prohibited
		"pkg:swid/example.com/Server@1", // tag_id qualifier required
		// Library-enforced rules surface through the same entry point.
		"pkg:swift/swift-numerics@1.0.0", // library: namespace required
		"pkg:julia/Example@1.0.0",        // library: uuid qualifier required
		"not a purl",
		"",
	}
	for _, value := range invalid {
		err := ValidateString(value)
		if err == nil {
			t.Errorf("ValidateString(%q) = nil, want rejection", value)
			continue
		}
		if !errors.Is(err, ErrInvalidPURL) {
			t.Errorf("ValidateString(%q) error %v does not match ErrInvalidPURL", value, err)
		}
	}
}

func TestValidateMatchesParseVocabulary(t *testing.T) {
	// Every profile row must name a type the parser accepts — a typo'd row
	// would silently never fire.
	for purlType := range typeProfiles {
		value := "pkg:" + purlType + "/ns/name@1.0"
		if _, err := Parse(value); err != nil {
			t.Errorf("profile row %q is not a parseable type: %v", purlType, err)
		}
	}
}

func TestWithoutVersion(t *testing.T) {
	cases := map[string]string{
		"pkg:npm/left-pad@1.3.0":                       "pkg:npm/left-pad",
		"pkg:npm/left-pad":                             "pkg:npm/left-pad",
		"pkg:apk/alpine/curl@7.83.0-r0?arch=x86":       "pkg:apk/alpine/curl?arch=x86",
		"pkg:golang/example.com/mod@v1.0.0#internal/x": "pkg:golang/example.com/mod#internal/x",
		"not a purl":                                   "",
		"":                                             "",
	}
	for input, want := range cases {
		if got := WithoutVersion(input); got != want {
			t.Errorf("WithoutVersion(%q) = %q, want %q", input, got, want)
		}
	}
	// The reason this key exists: an architecture pair must not collapse.
	amd := WithoutVersion("pkg:apk/alpine/musl@1.2.5?arch=x86_64")
	arm := WithoutVersion("pkg:apk/alpine/musl@1.2.5?arch=aarch64")
	if amd == arm {
		t.Fatal("WithoutVersion dropped the identity qualifiers")
	}
}
