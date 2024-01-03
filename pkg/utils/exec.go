/*
 * Copyright 2023 The Kmesh Authors.
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
 *
 * Author: bitcoffee
 * Create: 2023-11-19
 */

package utils

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"

	"kmesh.net/kmesh/pkg/logger"
)

var (
	log = logger.NewLoggerField("utils")
)

func ExecuteWithRedirect(cmd string, args []string, stdout io.Writer) error {
	var err error
	if stdout == nil {
		err = fmt.Errorf("stdout can not be null in output redirect mode!")
		log.Error(err)
		return err
	}
	stderr := &bytes.Buffer{}
	err = executeCore(cmd, args, stdout, stderr)
	if len(stderr.String()) != 0 {
		err = fmt.Errorf("command error output: %s", stderr.String())
		log.Error(err)
		return err
	}
	return nil
}

func Execute(cmd string, args []string) error {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	err := executeCore(cmd, args, stdout, stderr)

	if len(stdout.String()) != 0 {
		log.Debugf("command output: %s", stdout.String())
	}

	if len(stderr.String()) != 0 {
		err = fmt.Errorf("command error output: %s", stderr.String())
		log.Error(err)
		return err
	}
	return nil
}

func executeCore(cmd string, args []string, stdout, stderr io.Writer) error {
	log.Debugf("Running command: %s", cmd)
	var err error

	cmdPath, err := exec.LookPath(cmd)
	if err != nil {
		log.Errorf("command failed to get path")
		return err
	}

	args = append([]string{cmd}, args...)
	if stdout == nil {
		stdout = &bytes.Buffer{}
	}

	command := exec.Cmd{
		Path:   cmdPath,
		Args:   args,
		Stdout: stdout,
		Stderr: stderr,
	}

	command.Run()
	return nil
}
