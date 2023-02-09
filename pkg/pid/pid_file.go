/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
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
