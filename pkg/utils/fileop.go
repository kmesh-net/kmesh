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
	"fmt"
	"os"
	"path/filepath"
)

// create a temp file and rename to path
func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	basename := filepath.Base(path) + ".tmp.file"
	tempfile, err := os.CreateTemp(dir, basename)
	if err != nil {
		err = fmt.Errorf("failed to create tempfile %v/%v: %v", dir, basename, err)
		log.Error(err)
		return err
	}
	defer func() {
		tempfile.Close()
		os.Remove(tempfile.Name())
	}()

	if err = os.Chmod(tempfile.Name(), mode); err != nil {
		err = fmt.Errorf("failed to chmod tempfile %v: %v", tempfile.Name(), err)
		log.Error(err)
		return err
	}

	if _, err = tempfile.Write(data); err != nil {
		err = fmt.Errorf("failed to write tempfile %v: %v", tempfile.Name(), err)
		log.Error(err)
		return err
	}

	if err = tempfile.Close(); err != nil {
		err = fmt.Errorf("failed to close tempfile %v: %v", tempfile.Name(), err)
		log.Error(err)
		return err
	}

	if err = os.Rename(tempfile.Name(), path); err != nil {
		err = fmt.Errorf("failed to rename tempfile %v to %v: %v", tempfile.Name(), path, err)
		log.Error(err)
		return err
	}
	return nil
}
