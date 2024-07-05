// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package builder

import (
	"fmt"
	"strings"

	"istio.io/istio/pkg/maps"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/util/sets"
	"istio.io/istio/tools/istio-iptables/pkg/config"
	"istio.io/istio/tools/istio-iptables/pkg/constants"
	"istio.io/istio/tools/istio-iptables/pkg/log"
)

// Rule represents iptables rule - chain, table and options
type Rule struct {
	chain  string
	table  string
	params []string
}

// Rules represents iptables for V4 and V6
type Rules struct {
	rulesv4 []*Rule
	rulesv6 []*Rule
}

// IptablesRuleBuilder is an implementation for IptablesRuleBuilder interface
type IptablesRuleBuilder struct {
	rules Rules
	cfg   *config.Config
}

// NewIptablesBuilders creates a new IptablesRuleBuilder
func NewIptablesRuleBuilder(cfg *config.Config) *IptablesRuleBuilder {
	if cfg == nil {
		cfg = &config.Config{}
	}
	return &IptablesRuleBuilder{
		rules: Rules{
			rulesv4: []*Rule{},
			rulesv6: []*Rule{},
		},
		cfg: cfg,
	}
}

func (rb *IptablesRuleBuilder) InsertRule(command log.Command, chain string, table string, position int, params ...string) *IptablesRuleBuilder {
	rb.InsertRuleV4(command, chain, table, position, params...)
	rb.InsertRuleV6(command, chain, table, position, params...)
	return rb
}

// nolint lll
func (rb *IptablesRuleBuilder) insertInternal(ipt *[]*Rule, command log.Command, chain string, table string, position int, params ...string) *IptablesRuleBuilder {
	rules := params
	*ipt = append(*ipt, &Rule{
		chain:  chain,
		table:  table,
		params: append([]string{"-I", chain, fmt.Sprint(position)}, rules...),
	})
	idx := indexOf("-j", params)
	// We have identified the type of command this is and logging is enabled. Insert a rule to log this chain was hit.
	// Since this is insert we do this *after* the real chain, which will result in it bumping it forward
	if rb.cfg.TraceLogging && idx >= 0 && command != log.UndefinedCommand {
		match := params[:idx]
		// 1337 group is just a random constant to be matched on the log reader side
		// Size of 20 allows reading the IPv4 IP header.
		match = append(match, "-j", "NFLOG", "--nflog-prefix", fmt.Sprintf(`%q`, command.Identifier), "--nflog-group", "1337", "--nflog-size", "20")
		*ipt = append(*ipt, &Rule{
			chain:  chain,
			table:  table,
			params: append([]string{"-I", chain, fmt.Sprint(position)}, match...),
		})
	}
	return rb
}

func (rb *IptablesRuleBuilder) InsertRuleV4(command log.Command, chain string, table string, position int, params ...string) *IptablesRuleBuilder {
	return rb.insertInternal(&rb.rules.rulesv4, command, chain, table, position, params...)
}

func (rb *IptablesRuleBuilder) InsertRuleV6(command log.Command, chain string, table string, position int, params ...string) *IptablesRuleBuilder {
	if !rb.cfg.EnableIPv6 {
		return rb
	}
	return rb.insertInternal(&rb.rules.rulesv6, command, chain, table, position, params...)
}

func indexOf(element string, data []string) int {
	for k, v := range data {
		if element == v {
			return k
		}
	}
	return -1 // not found.
}

func (rb *IptablesRuleBuilder) appendInternal(ipt *[]*Rule, command log.Command, chain string, table string, params ...string) *IptablesRuleBuilder {
	idx := indexOf("-j", params)
	// We have identified the type of command this is and logging is enabled. Appending a rule to log this chain will be hit
	if rb.cfg.TraceLogging && idx >= 0 && command != log.UndefinedCommand {
		match := params[:idx]
		// 1337 group is just a random constant to be matched on the log reader side
		// Size of 20 allows reading the IPv4 IP header.
		match = append(match, "-j", "NFLOG", "--nflog-prefix", fmt.Sprintf(`%q`, command.Identifier), "--nflog-group", "1337", "--nflog-size", "20")
		*ipt = append(*ipt, &Rule{
			chain:  chain,
			table:  table,
			params: append([]string{"-A", chain}, match...),
		})
	}
	rules := params
	*ipt = append(*ipt, &Rule{
		chain:  chain,
		table:  table,
		params: append([]string{"-A", chain}, rules...),
	})
	return rb
}

func (rb *IptablesRuleBuilder) AppendRuleV4(command log.Command, chain string, table string, params ...string) *IptablesRuleBuilder {
	return rb.appendInternal(&rb.rules.rulesv4, command, chain, table, params...)
}

func (rb *IptablesRuleBuilder) AppendRule(command log.Command, chain string, table string, params ...string) *IptablesRuleBuilder {
	rb.AppendRuleV4(command, chain, table, params...)
	rb.AppendRuleV6(command, chain, table, params...)
	return rb
}

func (rb *IptablesRuleBuilder) AppendRuleV6(command log.Command, chain string, table string, params ...string) *IptablesRuleBuilder {
	if !rb.cfg.EnableIPv6 {
		return rb
	}
	return rb.appendInternal(&rb.rules.rulesv6, command, chain, table, params...)
}

func (rb *IptablesRuleBuilder) buildRules(rules []*Rule) [][]string {
	output := make([][]string, 0)
	chainTableLookupSet := sets.New[string]()
	for _, r := range rules {
		chainTable := fmt.Sprintf("%s:%s", r.chain, r.table)
		// Create new chain if key: `chainTable` isn't present in map
		if !chainTableLookupSet.Contains(chainTable) {
			// Ignore chain creation for built-in chains for iptables
			if _, present := constants.BuiltInChainsMap[r.chain]; !present {
				cmd := []string{"-t", r.table, "-N", r.chain}
				output = append(output, cmd)
				chainTableLookupSet.Insert(chainTable)
			}
		}
	}
	for _, r := range rules {
		cmd := append([]string{"-t", r.table}, r.params...)
		output = append(output, cmd)
	}
	return output
}

func (rb *IptablesRuleBuilder) BuildV4() [][]string {
	return rb.buildRules(rb.rules.rulesv4)
}

func (rb *IptablesRuleBuilder) BuildV6() [][]string {
	return rb.buildRules(rb.rules.rulesv6)
}

func (rb *IptablesRuleBuilder) constructIptablesRestoreContents(tableRulesMap map[string][]string) string {
	var b strings.Builder
	for _, table := range slices.Sort(maps.Keys(tableRulesMap)) {
		rules := tableRulesMap[table]
		if len(rules) > 0 {
			_, _ = fmt.Fprintln(&b, "*", table)
			for _, r := range rules {
				_, _ = fmt.Fprintln(&b, r)
			}
			_, _ = fmt.Fprintln(&b, "COMMIT")
		}
	}
	return b.String()
}

func (rb *IptablesRuleBuilder) buildRestore(rules []*Rule) string {
	tableRulesMap := map[string][]string{
		constants.FILTER: {},
		constants.NAT:    {},
		constants.MANGLE: {},
	}

	chainTableLookupMap := sets.New[string]()
	for _, r := range rules {
		chainTable := fmt.Sprintf("%s:%s", r.chain, r.table)
		// Create new chain if key: `chainTable` isn't present in map
		if !chainTableLookupMap.Contains(chainTable) {
			// Ignore chain creation for built-in chains for iptables
			if _, present := constants.BuiltInChainsMap[r.chain]; !present {
				tableRulesMap[r.table] = append(tableRulesMap[r.table], fmt.Sprintf("-N %s", r.chain))
				chainTableLookupMap.Insert(chainTable)
			}
		}
	}

	for _, r := range rules {
		tableRulesMap[r.table] = append(tableRulesMap[r.table], strings.Join(r.params, " "))
	}
	return rb.constructIptablesRestoreContents(tableRulesMap)
}

func (rb *IptablesRuleBuilder) BuildV4Restore() string {
	return rb.buildRestore(rb.rules.rulesv4)
}

func (rb *IptablesRuleBuilder) BuildV6Restore() string {
	return rb.buildRestore(rb.rules.rulesv6)
}

// AppendVersionedRule is a wrapper around AppendRule that substitutes an ipv4/ipv6 specific value
// in place in the params. This allows appending a dual-stack rule that has an IP value in it.
func (rb *IptablesRuleBuilder) AppendVersionedRule(ipv4 string, ipv6 string, command log.Command, chain string, table string, params ...string) {
	rb.AppendRuleV4(command, chain, table, replaceVersionSpecific(ipv4, params...)...)
	rb.AppendRuleV6(command, chain, table, replaceVersionSpecific(ipv6, params...)...)
}

func replaceVersionSpecific(contents string, inputs ...string) []string {
	res := make([]string, 0, len(inputs))
	for _, i := range inputs {
		if i == constants.IPVersionSpecific {
			res = append(res, contents)
		} else {
			res = append(res, i)
		}
	}
	return res
}
