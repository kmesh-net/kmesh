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

package prow

import (
	"fmt"
	"net/url"
	"strings"

	"istio.io/istio/pkg/env"
)

var (
	runningInCI   = env.Register("CI", false, "If true, indicates we are running in CI").Get()
	artifactsBase = env.Register("PROW_ARTIFACTS_BASE", "https://gcsweb.istio.io/gcs/istio-prow", "the base url for prow artifacts").Get()
	// https://github.com/kubernetes/test-infra/blob/master/prow/jobs.md#job-environment-variables
	jobType    = env.Register("JOB_TYPE", "presubmit", "type of job").Get()
	jobName    = env.Register("JOB_NAME", "", "name of job").Get()
	pullNumber = env.Register("PULL_NUMBER", "", "PR of job").Get()
	repoName   = env.Register("REPO_NAME", "istio", "repo name").Get()
	repoOwner  = env.Register("REPO_OWNER", "istio", "repo owner").Get()
	buildID    = env.Register("BUILD_ID", "", "build id").Get()
	artifacts  = env.Register("ARTIFACTS", "", "artifacts base").Get()
)

func ArtifactsURL(filename string) string {
	if !runningInCI {
		return filename
	}
	name := "artifacts/" + strings.TrimPrefix(filename, artifacts+"/")
	if jobType == "presubmit" {
		return join(artifactsBase, "pr-logs/pull", fmt.Sprintf("%s_%s", repoOwner, repoName), pullNumber, jobName, buildID, name)
	}
	return join(artifactsBase, "logs", jobName, buildID, name)
}

func join(base string, elem ...string) string {
	res, _ := url.JoinPath(base, elem...)
	return res
}
