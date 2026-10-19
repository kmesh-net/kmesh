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
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

// validateK8sName validates DNS-1123 subdomain format
func validateK8sName(field, s string) error {
	if s == "" {
		return nil
	}
	if errs := validation.IsDNS1123Subdomain(s); len(errs) > 0 {
		return fmt.Errorf("invalid %s %q: %s", field, s, strings.Join(errs, "; "))
	}
	return nil
}
