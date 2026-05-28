package schema

import (
	"bytes"
	"encoding/json"
)

// DecodeStrict unmarshals body into v with unknown-field rejection. The
// schema (doc/schema-draft.yaml) declares request bodies with
// additionalProperties:false; lenient stdlib json.Unmarshal would
// silently ignore typos and unsupported keys, defeating the
// schema-tightening contract (audit finding L-1). Callers that
// receive an empty body should branch around this — the helper does
// not invent defaults.
func DecodeStrict(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
