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

 * Author: superCharge
 * Create: 2023-02-09
 */

// Package pid: pid manager
package pid

import (
	"fmt"
	"os"
	"syscall"
)

const (
	pidFilePath = "/var/run/kmesh.pid"
)

var pf *os.File

func CreatePidFile() error {
	var err error
	pf, err = os.OpenFile(pidFilePath, os.O_RDWR|os.O_CREATE, syscall.S_IRUSR|syscall.S_IWUSR)
	if err != nil {
		return fmt.Errorf("open or create pid file failed, %v", err)
	}

	err = syscall.Flock(int(pf.Fd()), syscall.LOCK_NB|syscall.LOCK_EX)
	if err != nil {
		return fmt.Errorf("another kmesh process is already running, %v", err)
	}

	pid := fmt.Sprintf("%d", os.Getpid())
	_, err = pf.Write([]byte(pid))
	if err != nil {
		return fmt.Errorf("failed to write pid, err: %v", err)
	}
	return nil
}

func RemovePidFile() error {
	err := pf.Close()
	if err != nil {
		return fmt.Errorf("failed to close file, err: %v", err)
	}
	err = os.Remove(pidFilePath)
	if err != nil {
		return fmt.Errorf("failed to remove file, err: %v", err)
	}
	return nil
}
