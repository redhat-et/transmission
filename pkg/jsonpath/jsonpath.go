package jsonpath

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var fieldRegEx = regexp.MustCompile(`^(\w+)(\[(\d+)\])?$`)

func parseField(field string) (name string, index int, hasIndex bool, err error) {
	matches := fieldRegEx.FindStringSubmatch(field)
	if matches == nil {
		return "", 0, false, fmt.Errorf("field %s has invalid format", field)
	}

	name = matches[1]
	if matches[3] != "" {
		hasIndex = true
		index, err = strconv.Atoi(matches[3])
		if err != nil {
			return "", 0, false, fmt.Errorf("field %s has invalid index: %w", field, err)
		}
	}
	return
}

func JsonSet(obj map[string]any, jsonPath string, value any) error {
	fields := strings.Split(jsonPath, ".")

	m := obj
	for _, field := range fields[:len(fields)-1] {
		name, index, _, err := parseField(field)
		if err != nil {
			return fmt.Errorf("jsonPath %s has invalid field %s: %w", jsonPath, name, err)
		}
		if val, ok := m[name]; ok {
			switch valT := val.(type) {
			case map[string]any:
				m = valT
			case []any:
				m = valT[index].(map[string]any)
			default:
				return fmt.Errorf("cannot set value because %s is not a map[string]interface{}", jsonPath)
			}
		} else {
			newVal := make(map[string]any)
			m[field] = newVal
			m = newVal
		}
	}
	m[fields[len(fields)-1]] = value
	return nil
}

func JsonGet(obj map[string]any, jsonPath string) (any, error) {
	fields := strings.Split(jsonPath, ".")

	m := obj
	for _, field := range fields[:len(fields)-1] {
		name, index, _, err := parseField(field)
		if err != nil {
			return nil, fmt.Errorf("jsonPath %s has invalid field %s: %w", jsonPath, name, err)
		}

		if val, ok := m[name]; ok {
			switch valT := val.(type) {
			case map[string]any:
				m = valT
			case []any:
				m = valT[index].(map[string]any)
			default:
				return nil, fmt.Errorf("cannot get value because %s is not a map[string]interface{}", jsonPath)
			}
		} else {
			return nil, fmt.Errorf("cannot get value because %s is not a map[string]interface{}", jsonPath)
		}
	}
	return m[fields[len(fields)-1]], nil
}

func JsonGetString(obj map[string]any, jsonPath string) (string, error) {
	val, err := JsonGet(obj, jsonPath)
	if err != nil {
		return "", err
	}
	if val == nil {
		return "", nil
	}
	if s, ok := val.(string); ok {
		return s, nil
	}
	return "", fmt.Errorf("cannot get value because %s is not a string", jsonPath)
}
