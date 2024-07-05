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

	"github.com/hashicorp/go-multierror"

	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/util/istiomultierror"
)

var authzLog = log.RegisterScope("authorization", "Istio Authorization Policy")

type AuthzLogger struct {
	debugMsg []string
	errMsg   *multierror.Error
}

func (al *AuthzLogger) AppendDebugf(format string, args ...any) {
	al.debugMsg = append(al.debugMsg, fmt.Sprintf(format, args...))
}

func (al *AuthzLogger) AppendError(err error) {
	al.errMsg = multierror.Append(al.errMsg, err)
}

func (al *AuthzLogger) Report() {
	if al.errMsg != nil {
		al.errMsg.ErrorFormat = istiomultierror.MultiErrorFormat()
		authzLog.Errorf("Processed authorization policy: %s", al.errMsg)
	}
	if authzLog.DebugEnabled() && len(al.debugMsg) != 0 {
		out := strings.Join(al.debugMsg, "\n\t* ")
		authzLog.Debugf("Processed authorization policy with details:\n\t* %v", out)
	} else {
		authzLog.Debugf("Processed authorization policy")
	}
}
