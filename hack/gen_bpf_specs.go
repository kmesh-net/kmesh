/*
 * Copyright The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"
)

type entry struct {
	OutputDir string // e.g. kernelnative/normal or kernelnative/enhanced or dualengine or general
	GoPkg     string // go package name passed in --go-package
	Symbol    string // the symbol token (KmeshCgroupSock etc)
}

type pkgInfo struct {
	Alias      string
	ImportPath string
	OutputDir  string
	Entries    []entry
}

type symbolGen struct {
	BaseName       string // e.g. KmeshSockops
	NormalPkgAlias string // alias that provides normal symbol (may be "")
	NormalSymbol   string // e.g. KmeshSockops
	CompatPkgAlias string // alias that provides compat symbol (may be "")
	CompatSymbol   string // e.g. KmeshSockopsCompat
}

func main() {
	root, err := repoRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed detect repo root: %v\n", err)
		os.Exit(2)
	}

	files := collectGoFiles(root)

	// regexes
	genRe := regexp.MustCompile(`//\s*go:generate\s+(?:.*\b)bpf2go\b(.*)`)
	outDirRe := regexp.MustCompile(`--output-dir\s+([^\s]+)`)
	goPkgRe := regexp.MustCompile(`--go-package\s+([^\s]+)`)
	symbolRe := regexp.MustCompile(`\b([A-Za-z0-9_]+)\s+[^\s]+\.(?:c|C)\b`)

	var entries []entry
	for _, f := range files {
		b, _ := os.ReadFile(f)
		for _, line := range strings.Split(string(b), "\n") {
			m := genRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			rest := m[1]
			out := ""
			if mm := outDirRe.FindStringSubmatch(rest); mm != nil {
				out = mm[1]
			}
			pkg := ""
			if mm := goPkgRe.FindStringSubmatch(rest); mm != nil {
				pkg = mm[1]
			}
			if mm := symbolRe.FindStringSubmatch(rest); mm != nil {
				sym := mm[1]
				entries = append(entries, entry{OutputDir: out, GoPkg: pkg, Symbol: sym})
			}
		}
	}

	if len(entries) == 0 {
		fmt.Println("no bpf2go generate lines found, nothing to do")
		return
	}

	byDir := map[string][]entry{}
	for _, e := range entries {
		dir := strings.Trim(e.OutputDir, `"'`)
		byDir[dir] = append(byDir[dir], e)
	}

	keys := make([]string, 0, len(byDir))
	for k := range byDir {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	modulePrefix := detectModulePath(root)
	if modulePrefix == "" {
		modulePrefix = "kmesh.net/kmesh"
	}

	sanitizeRe := regexp.MustCompile(`[^A-Za-z0-9_]`)
	sanitize := func(s string) string {
		out := sanitizeRe.ReplaceAllString(s, "_")
		out = strings.Trim(out, "_")
		if out == "" {
			out = "pkg"
		}
		if out[0] >= '0' && out[0] <= '9' {
			out = "pkg_" + out
		}
		return out
	}

	baseBpf2go := filepath.ToSlash(filepath.Join(root, "bpf", "kmesh", "bpf2go"))

	var pkgsDefault []pkgInfo
	var pkgsEnhanced []pkgInfo

	for _, k := range keys {
		list := byDir[k]
		pattern := strings.Trim(k, `"'`)

		var realDirs []string
		if strings.ContainsAny(pattern, "*?[]") {
			globFull := filepath.ToSlash(filepath.Join(baseBpf2go, pattern))
			matches, _ := filepath.Glob(globFull)
			for _, m := range matches {
				if fi, err := os.Stat(m); err == nil && fi.IsDir() {
					rel, err := filepath.Rel(baseBpf2go, m)
					if err == nil {
						realDirs = append(realDirs, filepath.ToSlash(rel))
					}
				}
			}
			if len(realDirs) == 0 {
				realDirs = append(realDirs, pattern)
			}
		} else {
			realDirs = append(realDirs, pattern)
		}

		for _, real := range realDirs {
			if strings.Contains(real, "$ENHANCED_KERNEL") {
				rdDefault := strings.ReplaceAll(real, "$ENHANCED_KERNEL", "normal")
				aliasDef := sanitize(rdDefault)
				importDef := filepath.ToSlash(filepath.Join(modulePrefix, "bpf", "kmesh", "bpf2go", rdDefault))
				pkgsDefault = append(pkgsDefault, pkgInfo{Alias: aliasDef, ImportPath: importDef, OutputDir: rdDefault, Entries: list})

				rdEnh := strings.ReplaceAll(real, "$ENHANCED_KERNEL", "enhanced")
				aliasEnh := sanitize(rdEnh)
				importEnh := filepath.ToSlash(filepath.Join(modulePrefix, "bpf", "kmesh", "bpf2go", rdEnh))
				pkgsEnhanced = append(pkgsEnhanced, pkgInfo{Alias: aliasEnh, ImportPath: importEnh, OutputDir: rdEnh, Entries: list})
			} else {
				alias := sanitize(real)
				importPath := filepath.ToSlash(filepath.Join(modulePrefix, "bpf", "kmesh", "bpf2go", real))
				pi := pkgInfo{Alias: alias, ImportPath: importPath, OutputDir: real, Entries: list}
				pkgsDefault = append(pkgsDefault, pi)
				if !strings.HasPrefix(real, "dualengine") {
					pkgsEnhanced = append(pkgsEnhanced, pi)
				}
			}
		}
	}

	sort.Slice(pkgsDefault, func(i, j int) bool { return pkgsDefault[i].ImportPath < pkgsDefault[j].ImportPath })
	sort.Slice(pkgsEnhanced, func(i, j int) bool { return pkgsEnhanced[i].ImportPath < pkgsEnhanced[j].ImportPath })

	// build per-bucket symbol gens
	knDefault := filterPkgsByPrefix(pkgsDefault, "kernelnative")
	deDefault := filterPkgsByPrefix(pkgsDefault, "dualengine")
	genDefault := filterPkgsByPrefix(pkgsDefault, "general")

	knEnhanced := filterPkgsByPrefix(pkgsEnhanced, "kernelnative")

	symsKnDefault := buildSymbolGen(knDefault)
	symsDeDefault := buildSymbolGen(deDefault)
	symsGenDefault := buildSymbolGen(genDefault)

	symsKnEnhanced := buildSymbolGen(knEnhanced)

	// prepare output dir
	outDir := filepath.Join(root, "pkg", "bpf", "restart")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir target dir: %v\n", err)
		os.Exit(2)
	}

	// template
	tplText := `/*
 * Copyright The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Code generated by hack/gen_bpf_specs.go; DO NOT EDIT.

package restart

import (
	"fmt"

	"github.com/cilium/ebpf"

	"kmesh.net/kmesh/daemon/options"
	helper "kmesh.net/kmesh/pkg/utils"
{{- range .Pkgs }}
	{{ .Alias }} "{{ .ImportPath }}"
{{- end }}
)

// Auto-generated: keeps in sync with //go:generate bpf2go lines.
func LoadCompileTimeSpecs(config *options.BpfConfig) (map[string]map[string]*ebpf.MapSpec, error) {
	specs := make(map[string]map[string]*ebpf.MapSpec)

	if config.KernelNativeEnabled() {
{{- range .SymsKn }}
{{- if and .NormalPkgAlias .CompatPkgAlias }}
	// Symbol {{ .BaseName }} has both normal and compat variants.
	if helper.KernelVersionLowerThan5_13() {
		if coll, err := {{ .CompatPkgAlias }}.Load{{ .CompatSymbol }}(); err != nil {
			return nil, fmt.Errorf("load Compat {{ .CompatSymbol }} spec: %w", err)
		} else {
			specs["{{ .BaseName }}Compat"] = coll.Maps
		}
	} else {
		if coll, err := {{ .NormalPkgAlias }}.Load{{ .NormalSymbol }}(); err != nil {
			return nil, fmt.Errorf("load {{ .NormalSymbol }} spec: %w", err)
		} else {
			specs["{{ .BaseName }}"] = coll.Maps
		}
	}
{{- else if .NormalPkgAlias }}
	// Symbol {{ .BaseName }} only normal
	if coll, err := {{ .NormalPkgAlias }}.Load{{ .NormalSymbol }}(); err != nil {
		return nil, fmt.Errorf("load {{ .NormalSymbol }} spec: %w", err)
	} else {
		specs["{{ .BaseName }}"] = coll.Maps
	}
{{- else if .CompatPkgAlias }}
	// Symbol {{ .BaseName }} only compat
	if coll, err := {{ .CompatPkgAlias }}.Load{{ .CompatSymbol }}(); err != nil {
		return nil, fmt.Errorf("load Compat {{ .CompatSymbol }} spec: %w", err)
	} else {
		specs["{{ .BaseName }}Compat"] = coll.Maps
	}
{{- end }}

{{- end }}
	} else if config.DualEngineEnabled() {
{{- range .SymsDe }}
{{- if and .NormalPkgAlias .CompatPkgAlias }}
	// Symbol {{ .BaseName }} has both normal and compat variants (dualengine).
	if helper.KernelVersionLowerThan5_13() {
		if coll, err := {{ .CompatPkgAlias }}.Load{{ .CompatSymbol }}(); err != nil {
			return nil, fmt.Errorf("load Compat {{ .CompatSymbol }} spec: %w", err)
		} else {
			specs["{{ .BaseName }}Compat"] = coll.Maps
		}
	} else {
		if coll, err := {{ .NormalPkgAlias }}.Load{{ .NormalSymbol }}(); err != nil {
			return nil, fmt.Errorf("load {{ .NormalSymbol }} spec: %w", err)
		} else {
			specs["{{ .BaseName }}"] = coll.Maps
		}
	}
{{- else if .NormalPkgAlias }}
	// Symbol {{ .BaseName }} only normal (dualengine)
	if coll, err := {{ .NormalPkgAlias }}.Load{{ .NormalSymbol }}(); err != nil {
		return nil, fmt.Errorf("load {{ .NormalSymbol }} spec: %w", err)
	} else {
		specs["{{ .BaseName }}"] = coll.Maps
	}
{{- else if .CompatPkgAlias }}
	// Symbol {{ .BaseName }} only compat (dualengine)
	if coll, err := {{ .CompatPkgAlias }}.Load{{ .CompatSymbol }}(); err != nil {
		return nil, fmt.Errorf("load Compat {{ .CompatSymbol }} spec: %w", err)
	} else {
		specs["{{ .BaseName }}Compat"] = coll.Maps
	}
{{- end }}
{{- end }}
	}

{{- range .SymsGen }}
{{- if and .NormalPkgAlias .CompatPkgAlias }}
	// General Symbol {{ .BaseName }} has normal+compat (choose by kernel)
	if helper.KernelVersionLowerThan5_13() {
		if coll, err := {{ .CompatPkgAlias }}.Load{{ .CompatSymbol }}(); err != nil {
			return nil, fmt.Errorf("load Compat {{ .CompatSymbol }} spec: %w", err)
		} else {
			specs["{{ .BaseName }}Compat"] = coll.Maps
		}
	} else {
		if coll, err := {{ .NormalPkgAlias }}.Load{{ .NormalSymbol }}(); err != nil {
			return nil, fmt.Errorf("load {{ .NormalSymbol }} spec: %w", err)
		} else {
			specs["{{ .BaseName }}"] = coll.Maps
		}
	}
{{- else if .NormalPkgAlias }}
	if coll, err := {{ .NormalPkgAlias }}.Load{{ .NormalSymbol }}(); err != nil {
		return nil, fmt.Errorf("load General {{ .NormalSymbol }} spec: %w", err)
	} else {
		specs["{{ .BaseName }}"] = coll.Maps
	}
{{- else if .CompatPkgAlias }}
	if coll, err := {{ .CompatPkgAlias }}.Load{{ .CompatSymbol }}(); err != nil {
		return nil, fmt.Errorf("load General Compat {{ .CompatSymbol }} spec: %w", err)
	} else {
		specs["{{ .BaseName }}Compat"] = coll.Maps
	}
{{- end }}
{{- end }}

	return specs, nil
}
`

	funcMap := template.FuncMap{}
	tpl, err := template.New("out").Funcs(funcMap).Parse(tplText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse tpl: %v\n", err)
		os.Exit(2)
	}

	// render default (non-enhanced) file
	if err := renderVariant(tpl, pkgsDefault, symsKnDefault, symsDeDefault, symsGenDefault, filepath.Join(outDir, "new_version_mapspec_loader.go"), "!enhanced"); err != nil {
		fmt.Fprintf(os.Stderr, "write default: %v\n", err)
		os.Exit(2)
	}

	// render enhanced file
	if err := renderVariant(tpl, pkgsEnhanced, symsKnEnhanced, []symbolGen{}, symsGenDefault, filepath.Join(outDir, "new_version_mapspec_loader_enhanced.go"), "enhanced"); err != nil {
		fmt.Fprintf(os.Stderr, "write enhanced: %v\n", err)
		os.Exit(2)
	}
}

func collectGoFiles(root string) []string {
	files := []string{}
	_ = filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			if fi.Name() == "vendor" || strings.HasPrefix(path, filepath.Join(root, ".git")) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			files = append(files, path)
		}
		return nil
	})
	return files
}

func detectModulePath(root string) string {
	modf := filepath.Join(root, "go.mod")
	b, err := os.ReadFile(modf)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return dir, nil
}

func filterPkgsByPrefix(pkgs []pkgInfo, prefix string) []pkgInfo {
	out := []pkgInfo{}
	for _, p := range pkgs {
		trim := strings.TrimPrefix(strings.TrimSpace(p.OutputDir), "/")
		if strings.HasPrefix(trim, prefix) {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ImportPath < out[j].ImportPath })
	return out
}

func buildSymbolGen(pkgs []pkgInfo) []symbolGen {
	m := map[string]*symbolGen{}
	for _, p := range pkgs {
		for _, e := range p.Entries {
			sym := e.Symbol
			base := sym
			isCompat := false
			if strings.HasSuffix(sym, "Compat") {
				base = strings.TrimSuffix(sym, "Compat")
				isCompat = true
			}
			if _, ok := m[base]; !ok {
				m[base] = &symbolGen{BaseName: base}
			}
			sg := m[base]
			if isCompat {
				sg.CompatPkgAlias = p.Alias
				sg.CompatSymbol = sym
			} else {
				sg.NormalPkgAlias = p.Alias
				sg.NormalSymbol = sym
			}
		}
	}
	out := make([]symbolGen, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BaseName < out[j].BaseName })
	return out
}

func renderVariant(tpl *template.Template, pkgs []pkgInfo, symsKn, symsDe, symsGen []symbolGen, outPath, buildTag string) error {
	// combine pkgs into template data (unique by import path)
	uniq := map[string]pkgInfo{}
	for _, p := range pkgs {
		uniq[p.ImportPath] = p
	}
	list := make([]pkgInfo, 0, len(uniq))
	for _, v := range uniq {
		list = append(list, v)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ImportPath < list[j].ImportPath })

	buf := &bytes.Buffer{}
	err := tpl.Execute(buf, map[string]interface{}{
		"Pkgs":    list,
		"SymsKn":  symsKn,
		"SymsDe":  symsDe,
		"SymsGen": symsGen,
	})
	if err != nil {
		return fmt.Errorf("execute tpl: %w", err)
	}

	var out []byte
	if buildTag != "" {
		header := fmt.Sprintf("//go:build %s\n// +build %s\n\n", buildTag, buildTag)
		out = append([]byte(header), buf.Bytes()...)
	} else {
		out = buf.Bytes()
	}

	src, err := format.Source(out)
	if err != nil {
		return fmt.Errorf("gofmt failed: %w\nraw output:\n%s\n", err, string(out))
	}
	if err := os.WriteFile(outPath, src, 0644); err != nil {
		return fmt.Errorf("write out: %w", err)
	}
	return nil
}
