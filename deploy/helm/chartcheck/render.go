// Package chartcheck renders the IVAR Helm chart with the template engine
// Helm uses (text/template with the sprig functions and Helm's own include,
// required, toYaml and fromJson), so CI can check every manifest without a
// cluster or the helm binary.
package chartcheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"gopkg.in/yaml.v3"
)

// Manifest is one rendered Kubernetes object.
type Manifest struct {
	Source string
	Object map[string]any
}

func (m Manifest) Kind() string { s, _ := m.Object["kind"].(string); return s }

func (m Manifest) Name() string {
	md, _ := m.Object["metadata"].(map[string]any)
	s, _ := md["name"].(string)
	return s
}

// Render renders chartDir with its values.yaml merged with overrides.
func Render(chartDir string, overrides map[string]any) ([]Manifest, error) {
	var chart map[string]any
	if err := readYAML(filepath.Join(chartDir, "Chart.yaml"), &chart); err != nil {
		return nil, err
	}
	var values map[string]any
	if err := readYAML(filepath.Join(chartDir, "values.yaml"), &values); err != nil {
		return nil, err
	}
	merge(values, overrides)
	top := map[string]any{
		"Values":  values,
		"Release": map[string]any{"Name": "ivar", "Namespace": "ivar", "Service": "Helm"},
		"Chart":   map[string]any{"Name": chart["name"], "Version": chart["version"], "AppVersion": chart["appVersion"]},
	}
	t := template.New("chart").Option("missingkey=zero")
	funcs := sprig.TxtFuncMap()
	funcs["include"] = func(name string, data any) (string, error) {
		var b bytes.Buffer
		err := t.ExecuteTemplate(&b, name, data)
		return b.String(), err
	}
	funcs["required"] = func(msg string, v any) (any, error) {
		if v == nil || v == "" {
			return nil, fmt.Errorf("required: %s", msg)
		}
		return v, nil
	}
	funcs["toYaml"] = func(v any) string {
		b, _ := yaml.Marshal(v)
		return strings.TrimSuffix(string(b), "\n")
	}
	funcs["fromJson"] = func(s string) map[string]any {
		m := map[string]any{}
		_ = json.Unmarshal([]byte(s), &m)
		return m
	}
	t.Funcs(funcs)
	files, _ := filepath.Glob(filepath.Join(chartDir, "templates", "*"))
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if _, err := t.New(filepath.Base(f)).Parse(string(b)); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
	}
	var out []Manifest
	for _, f := range files {
		name := filepath.Base(f)
		if strings.HasPrefix(name, "_") || !strings.HasSuffix(name, ".yaml") {
			continue
		}
		var b bytes.Buffer
		if err := t.ExecuteTemplate(&b, name, top); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		dec := yaml.NewDecoder(strings.NewReader(strings.ReplaceAll(b.String(), "<no value>", "")))
		for {
			var obj map[string]any
			err := dec.Decode(&obj)
			if err != nil {
				if err.Error() == "EOF" {
					break
				}
				return nil, fmt.Errorf("%s: rendered YAML does not parse: %w\n%s", name, err, b.String())
			}
			if len(obj) > 0 {
				out = append(out, Manifest{Source: name, Object: obj})
			}
		}
	}
	return out, nil
}

func readYAML(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, v)
}

func merge(dst, src map[string]any) {
	for k, v := range src {
		if sm, ok := v.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				merge(dm, sm)
				continue
			}
		}
		dst[k] = v
	}
}
