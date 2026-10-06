package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// MaxDocumentBytes bounds a rule document.
const MaxDocumentBytes = 1 << 20 // 1 MiB

// Parse reads a rule document from YAML or JSON.
//
// Which one is decided by the content rather than by a filename, for the same
// reason signpost sniffs an archive format: the name is a hint supplied
// alongside the bytes and a mismatch between the two is a confusion worth not
// having.
//
// Unknown fields are rejected by both decoders. A wrong key in a rule
// document is the one class of mistake that must never be silently ignored: a
// document whose allow list is spelled `allow_list:` would load with no allow
// list at all, which denies everything and presents as a broken service rather
// than a broken file, and a misspelled `comment:` on a deny rule would quietly
// drop the explanation an auditor reads.
func Parse(data []byte) (Document, error) {
	if len(data) == 0 {
		return Document{}, errors.New("rules: the document is empty")
	}

	if len(data) > MaxDocumentBytes {
		return Document{}, fmt.Errorf(
			"rules: the document is %d bytes, the limit is %d", len(data), MaxDocumentBytes)
	}

	if looksLikeJSON(data) {
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()

		var doc Document
		if err := decoder.Decode(&doc); err != nil {
			return Document{}, fmt.Errorf("rules: decode JSON: %w", err)
		}

		if decoder.More() {
			return Document{}, errors.New("rules: the document holds more than one JSON value")
		}

		return doc, nil
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	var doc Document
	if err := decoder.Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("rules: decode YAML: %w", err)
	}

	return doc, nil
}

// looksLikeJSON reports whether a document is JSON rather than YAML.
//
// JSON is a subset of YAML, so the YAML decoder would read either - but its
// error messages for a malformed JSON document are confusing, and
// DisallowUnknownFields and KnownFields report different things. Sniffing the
// first non-space byte picks the decoder whose errors will make sense.
func looksLikeJSON(data []byte) bool {
	trimmed := bytes.TrimLeft(data, " \t\r\n")

	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

// Encode renders a document as YAML, for `rules list --yaml` and for storing
// it in Valkey.
func Encode(doc Document) ([]byte, error) {
	var buffer bytes.Buffer

	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)

	if err := encoder.Encode(doc); err != nil {
		return nil, fmt.Errorf("rules: encode: %w", err)
	}

	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("rules: encode: %w", err)
	}

	return buffer.Bytes(), nil
}

// EncodeJSON renders a document as JSON, which is what is stored in Valkey.
//
// JSON rather than the YAML an operator wrote: the stored form is read by
// every replica on every reload, and a round trip through a canonical encoding
// means a reload cannot be affected by the formatting of the file somebody
// happened to load it from.
func EncodeJSON(doc Document) ([]byte, error) {
	encoded, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("rules: encode: %w", err)
	}

	return encoded, nil
}
