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

 * Author: LemmyHuang
 * Create: 2022-03-03
 */

package command

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type httpClient struct {
	client *http.Client
	resp   *http.Response
}

var cmdClient httpClient

func StartClient() error {
	var err error

	if err = config.SetArgs(); err != nil {
		flag.Usage()
		return fmt.Errorf("set args failed, %s", err)
	}
	flag.Parse()
	if err = config.ParseConfig(); err != nil {
		return fmt.Errorf("parse config failed, %s", err)
	}

	cmdClient.client = &http.Client{
		Timeout: httpTimeout,
	}
	cmdClient.resp, err =
		cmdClient.client.Post(adminUrl+patternBpfKmeshMaps,
			contentType, strings.NewReader(string(config.ConfigResources)))
	if err != nil {
		return err
	}

	if cmdClient.resp.StatusCode != http.StatusOK {
		var content []byte
		content, err = ioutil.ReadAll(cmdClient.resp.Body)
		if err != nil {
			return fmt.Errorf("%s, %s", cmdClient.resp.Status, err)
		}
		return fmt.Errorf("%s", content)
	}

	fmt.Println(http.StatusText(http.StatusOK))
	return nil
}

func StopClient() error {
	if cmdClient.resp != nil {
		return cmdClient.resp.Body.Close()

	}
	return nil
}
