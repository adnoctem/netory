package bundle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseManifest decodes a manifest from its bytes.
//
// The format is chosen by the filename, which is one of ManifestNames and so
// is not attacker-chosen in any interesting way: the archive either carries
// signpost.json or it carries signpost.yaml, and loadManifest has already
// established there is exactly one.
//
// Both decoders are strict about unknown fields. A manifest with a mistyped
// key - `content-type` for `content_type`, say - is a bundle that would publish
// successfully and then serve the wrong Content-Type, which is precisely the
// silent failure this service cannot afford.
func ParseManifest(name string, data []byte) (*Manifest, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("bundle: %s is empty", name)
	}

	var manifest Manifest

	switch strings.ToLower(path.Ext(name)) {
	case ".json":
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()

		if err := decoder.Decode(&manifest); err != nil {
			return nil, fmt.Errorf("bundle: %s is not valid JSON: %w", name, err)
		}

		if decoder.More() {
			return nil, fmt.Errorf("bundle: %s contains more than one JSON document", name)
		}
	case ".yaml", ".yml":
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)

		if err := decoder.Decode(&manifest); err != nil {
			return nil, fmt.Errorf("bundle: %s is not valid YAML: %w", name, err)
		}

		// A second document would be ambiguous about which one is the
		// manifest.
		var extra Manifest
		if err := decoder.Decode(&extra); err == nil {
			return nil, fmt.Errorf("bundle: %s contains more than one YAML document", name)
		}
	default:
		return nil, fmt.Errorf("bundle: %s has an unrecognised manifest extension", name)
	}

	return &manifest, nil
}
