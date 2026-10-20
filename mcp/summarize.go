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

package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

var (
	// internal RAM boundary (daemon to MCP server)
	maxDumpBytes int64 = 16 << 20 // 16 MiB

	// maxResultBytes caps tool output size (MCP server to client)
	maxResultBytes = 50 * 1024 // 50KB

	maxSummaryItems = 50
)

var errDumpTooLarge = errors.New("daemon response too large to buffer safely")

var identityKeys = []string{
	"name", "namespace", "uid", "ip", "address", "addresses",
	"hostname", "hostnames", "status", "state", "clusterName",
}

// readAllLimited reads at most limit bytes and errors if the body exceeds it.
func readAllLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w (limit %d bytes)", errDumpTooLarge, limit)
	}
	return data, nil
}

// collectCategories extracts arrays of objects from dump json
func collectCategories(v any) map[string][]map[string]any {
	cats := map[string][]map[string]any{}
	root, ok := v.(map[string]any)
	if !ok {
		return cats
	}

	var walk func(prefix string, m map[string]any, depth int)
	walk = func(prefix string, m map[string]any, depth int) {
		for k, val := range m {
			switch t := val.(type) {
			case []any:
				items := make([]map[string]any, 0, len(t))
				for _, e := range t {
					if eo, ok := e.(map[string]any); ok {
						items = append(items, eo)
					}
				}
				if len(items) > 0 {
					key := k
					if prefix != "" {
						key = prefix + "." + k
					}
					cats[key] = items
				}
			case map[string]any:
				if depth == 0 {
					walk(k, t, depth+1)
				}
			}
		}
	}
	walk("", root, 0)
	return cats
}

// summarizeItem extracts key identity fields from a dump item
func summarizeItem(item map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range identityKeys {
		v, ok := item[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case string:
			if t != "" {
				out[k] = t
			}
		case float64, bool:
			out[k] = t
		case []any:
			strs := make([]string, 0, len(t))
			for _, e := range t {
				if s, ok := e.(string); ok {
					strs = append(strs, s)
				}
			}
			if len(strs) > 0 && len(strs) <= 4 {
				out[k] = strings.Join(strs, ",")
			}
		}
		if len(out) >= 4 {
			break
		}
	}
	if len(out) == 0 {
		keys := make([]string, 0, len(item))
		for k := range item {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out["fields"] = strings.Join(keys, ",")
	}
	return out
}

func itemMatches(item map[string]any, filter string) bool {
	b, err := json.Marshal(item)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(b)), strings.ToLower(filter))
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

type summaryOutput struct {
	Summary    bool                        `json:"summary"`
	Counts     map[string]int              `json:"counts"`
	Categories map[string][]map[string]any `json:"categories"`
	Omitted    map[string]int              `json:"omitted,omitempty"`
	Hint       string                      `json:"hint"`
}

func summarize(cats map[string][]map[string]any) (string, error) {
	out := summaryOutput{
		Summary:    true,
		Counts:     map[string]int{},
		Categories: map[string][]map[string]any{},
		Hint:       "This is a summary. Call again with the 'filter' argument (e.g. a resource name, IP or UID) to fetch full details of matching items.",
	}
	for _, cat := range sortedKeys(cats) {
		items := cats[cat]
		out.Counts[cat] = len(items)
		shown := items
		if len(items) > maxSummaryItems {
			shown = items[:maxSummaryItems]
			if out.Omitted == nil {
				out.Omitted = map[string]int{}
			}
			out.Omitted[cat] = len(items) - maxSummaryItems
		}
		compact := make([]map[string]any, 0, len(shown))
		for _, it := range shown {
			compact = append(compact, summarizeItem(it))
		}
		out.Categories[cat] = compact
	}
	b, err := json.MarshalIndent(out, "", "  ")
	return string(b), err
}

type filteredOutput struct {
	Filter     string                       `json:"filter"`
	MatchCount int                          `json:"matchCount"`
	Truncated  bool                         `json:"truncated"`
	Matches    map[string][]json.RawMessage `json:"matches"`
	Hint       string                       `json:"hint,omitempty"`
}

// filtered returns items matching the filter substring
func filtered(cats map[string][]map[string]any, filter string) (string, error) {
	out := filteredOutput{
		Filter:  filter,
		Matches: map[string][]json.RawMessage{},
	}
	size := 0
	for _, cat := range sortedKeys(cats) {
		for _, it := range cats[cat] {
			if !itemMatches(it, filter) {
				continue
			}
			b, err := json.Marshal(it)
			if err != nil {
				continue
			}
			out.MatchCount++
			if size+len(b) > maxResultBytes {
				out.Truncated = true
				continue
			}
			size += len(b)
			out.Matches[cat] = append(out.Matches[cat], b)
		}
	}
	if out.Truncated {
		out.Hint = "Some matches omitted to fit the context window. Use a more specific filter to narrow results."
	}
	if out.MatchCount == 0 {
		out.Hint = "No matches. Call without 'filter' to see the summary of available resources."
	}
	b, err := json.MarshalIndent(out, "", "  ")
	return string(b), err
}

// formatDump formats dump payload with optional summary or filter
func formatDump(raw []byte, filter string, summary bool) (string, error) {
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err == nil {
		if cats := collectCategories(decoded); len(cats) > 0 {
			if filter != "" {
				return filtered(cats, filter)
			}
			if summary {
				return summarize(cats)
			}
		}
	}

	if len(raw) > maxResultBytes {
		return string(raw[:maxResultBytes]) +
			"\n... [WARNING: TRUNCATED to fit the context window. Use summary or filter to drill down]", nil
	}
	return string(raw), nil
}
