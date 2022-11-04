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
	resp *http.Response
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
		cmdClient.client.Post(adminUrl + patternBpfKmeshMaps, 
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
