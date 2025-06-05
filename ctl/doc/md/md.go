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

package md

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

const markdownExtension = ".md"

func printOptions(buf *bytes.Buffer, cmd *cobra.Command) error {
	flags := cmd.NonInheritedFlags()
	flags.SetOutput(buf)
	if flags.HasAvailableFlags() {
		buf.WriteString("### Options\n\n```bash\n")
		flags.PrintDefaults()
		buf.WriteString("```\n\n")
	}

	parentFlags := cmd.InheritedFlags()
	parentFlags.SetOutput(buf)
	if parentFlags.HasAvailableFlags() {
		buf.WriteString("### Options inherited from parent commands\n\n```bash\n")
		parentFlags.PrintDefaults()
		buf.WriteString("```\n\n")
	}
	return nil
}

// This functions were copied and adapted from github.com/spf13/cobra/main/doc/md_docs.go.
func GenMarkdownTree(cmd *cobra.Command, dir string) {
	patches := gomonkey.NewPatches()
	defer patches.Reset()
	patches.ApplyFunc(doc.GenMarkdownCustom, func(cmd *cobra.Command, w io.Writer, linkHandler func(string) string) error {
		cmd.InitDefaultHelpCmd()
		cmd.InitDefaultHelpFlag()

		buf := new(bytes.Buffer)
		name := cmd.CommandPath()

		buf.WriteString("## " + name + "\n\n")
		buf.WriteString(cmd.Short + "\n\n")
		if len(cmd.Long) > 0 {
			buf.WriteString("### Synopsis\n\n")
			buf.WriteString(cmd.Long + "\n\n")
		}

		if cmd.Runnable() {
			buf.WriteString(fmt.Sprintf("```bash\n%s\n```\n\n", cmd.UseLine()))
		}

		if len(cmd.Example) > 0 {
			buf.WriteString("### Examples\n\n")
			buf.WriteString(fmt.Sprintf("```bash\n%s\n```\n\n", cmd.Example))
		}

		if err := printOptions(buf, cmd); err != nil {
			return err
		}
		if hasSeeAlso(cmd) {
			buf.WriteString("### SEE ALSO\n\n")
			if cmd.HasParent() {
				parent := cmd.Parent()
				pname := parent.CommandPath()
				link := pname + markdownExtension
				link = strings.ReplaceAll(link, " ", "_")
				buf.WriteString(fmt.Sprintf("* [%s](%s) - %s\n", pname, linkHandler(link), parent.Short))
				cmd.VisitParents(func(c *cobra.Command) {
					if c.DisableAutoGenTag {
						cmd.DisableAutoGenTag = c.DisableAutoGenTag
					}
				})
			}

			children := cmd.Commands()
			sort.Sort(byName(children))

			for _, child := range children {
				if !child.IsAvailableCommand() || child.IsAdditionalHelpTopicCommand() {
					continue
				}
				cname := name + " " + child.Name()
				link := cname + markdownExtension
				link = strings.ReplaceAll(link, " ", "_")
				buf.WriteString(fmt.Sprintf("* [%s](%s) - %s\n", cname, linkHandler(link), child.Short))
			}
		}
		_, err := buf.WriteTo(w)
		return err
	})

	doc.GenMarkdownTree(cmd, dir) //nolint:errcheck
}
