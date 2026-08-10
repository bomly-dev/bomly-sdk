package sdk

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// ConfigSchemaFor derives a JSON Schema (draft 2020-12 subset) for a
// component's configuration block from a prototype struct. Declare your
// configuration once as a typed Go struct, decode it at runtime with
// DecodePluginConfigFromEnv, and advertise its shape in the descriptor:
//
//	type Config struct {
//		Endpoint string `json:"endpoint" doc:"API endpoint override" default:"https://api.example.com"`
//		Timeout  int    `json:"timeoutSeconds" doc:"Request timeout in seconds" default:"30"`
//		Strict   bool   `json:"strict" doc:"Fail on partial results"`
//	}
//
//	descriptor.ConfigSchema = sdk.MustConfigSchemaFor(Config{})
//
// Recognized struct tags: `json` (property name and omission), `doc`
// (property description), and `default` (default value, converted to the
// field's type). Nested structs, pointers, slices, and string-keyed maps are
// supported. Unexported fields and fields tagged `json:"-"` are skipped.
func ConfigSchemaFor(prototype any) (json.RawMessage, error) {
	if prototype == nil {
		return nil, fmt.Errorf("config schema prototype is nil")
	}
	t := reflect.TypeOf(prototype)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("config schema prototype must be a struct, got %s", t.Kind())
	}
	schema, err := schemaForType(t, map[reflect.Type]bool{})
	if err != nil {
		return nil, err
	}
	schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	data, err := json.Marshal(schema)
	if err != nil {
		return nil, fmt.Errorf("marshal config schema: %w", err)
	}
	return data, nil
}

// MustConfigSchemaFor is ConfigSchemaFor that panics on error. Use it for
// static descriptor initialization where the prototype is a compile-time
// constant shape.
func MustConfigSchemaFor(prototype any) json.RawMessage {
	schema, err := ConfigSchemaFor(prototype)
	if err != nil {
		panic(err)
	}
	return schema
}

func schemaForType(t reflect.Type, seen map[reflect.Type]bool) (map[string]any, error) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Bool:
		return map[string]any{"type": "boolean"}, nil
	case reflect.String:
		return map[string]any{"type": "string"}, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}, nil
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}, nil
	case reflect.Slice, reflect.Array:
		items, err := schemaForType(t.Elem(), seen)
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "array", "items": items}, nil
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return nil, fmt.Errorf("config schema maps must be string-keyed, got %s", t.Key().Kind())
		}
		values, err := schemaForType(t.Elem(), seen)
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "object", "additionalProperties": values}, nil
	case reflect.Interface:
		return map[string]any{}, nil
	case reflect.Struct:
		if seen[t] {
			return nil, fmt.Errorf("config schema does not support recursive type %s", t)
		}
		seen[t] = true
		defer delete(seen, t)
		properties := map[string]any{}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if !field.IsExported() {
				continue
			}
			name, omit := jsonFieldName(field)
			if omit {
				continue
			}
			if field.Anonymous && name == "" {
				embedded, err := schemaForType(field.Type, seen)
				if err != nil {
					return nil, err
				}
				if embeddedProps, ok := embedded["properties"].(map[string]any); ok {
					for key, value := range embeddedProps {
						properties[key] = value
					}
				}
				continue
			}
			property, err := schemaForType(field.Type, seen)
			if err != nil {
				return nil, fmt.Errorf("field %s: %w", field.Name, err)
			}
			if doc := strings.TrimSpace(field.Tag.Get("doc")); doc != "" {
				property["description"] = doc
			}
			if raw, ok := field.Tag.Lookup("default"); ok {
				value, err := defaultValueForType(field.Type, raw)
				if err != nil {
					return nil, fmt.Errorf("field %s: %w", field.Name, err)
				}
				property["default"] = value
			}
			properties[name] = property
		}
		return map[string]any{"type": "object", "properties": properties, "additionalProperties": false}, nil
	default:
		return nil, fmt.Errorf("config schema does not support %s fields", t.Kind())
	}
}

func jsonFieldName(field reflect.StructField) (name string, omit bool) {
	tag := field.Tag.Get("json")
	if tag == "-" {
		return "", true
	}
	parts := strings.Split(tag, ",")
	if parts[0] != "" {
		return parts[0], false
	}
	if field.Anonymous {
		return "", false
	}
	return field.Name, false
}

func defaultValueForType(t reflect.Type, raw string) (any, error) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Bool:
		return strconv.ParseBool(raw)
	case reflect.String:
		return raw, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.ParseInt(raw, 10, 64)
	case reflect.Float32, reflect.Float64:
		return strconv.ParseFloat(raw, 64)
	default:
		var value any
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			return nil, fmt.Errorf("default %q is not valid for %s: %w", raw, t.Kind(), err)
		}
		return value, nil
	}
}
