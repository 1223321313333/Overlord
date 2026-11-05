package wire

import (
	"bytes"
	"fmt"

	"github.com/vmihailenco/msgpack/v5"
)

const maxDecodeDepth = 32

func DecodeEnvelope(data []byte) (map[string]interface{}, error) {
	//garble:controlflow block_splits=10 junk_jumps=10 flatten_passes=2
	depth := 0
	dec := msgpack.NewDecoder(bytes.NewReader(data))
	dec.SetMapDecoder(func(d *msgpack.Decoder) (interface{}, error) {
		depth++
		if depth > maxDecodeDepth {
			return nil, fmt.Errorf("wire: msgpack nesting depth exceeds %d", maxDecodeDepth)
		}
		defer func() { depth-- }()
		return d.DecodeMap()
	})
	env := make(map[string]interface{})
	if err := dec.Decode(&env); err != nil {
		return nil, err
	}
	msgType, _ := env["type"].(string)
	if msgType == "" {
		return nil, fmt.Errorf("wire: missing or non-string type field")
	}
	return env, nil
}
