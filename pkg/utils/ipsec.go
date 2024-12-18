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

package utils

import (
	"bufio"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/vishvananda/netlink"
	"istio.io/pkg/filewatcher"
)

const (
	IpSecKeyFile  = "/root/kmesh-ipsec/keys"
	offsetSpi     = 0
	offsetAead    = 1
	offsetAeadKey = 2
	offsetAeadLen = 3
)

type ipSecInfo struct {
	bootID string
	spi    int8
	nodeID uint16
}

type ipSecKey struct {
	Spi         int8
	OldSpi      int8
	AeadKeyName string
	AeadKey     []byte
	Length      int
}

type IpSecHandler struct {
	ipSecKey
	ipSecLoadLock   sync.RWMutex
	ipSecUpdateLock sync.RWMutex
	watcher         filewatcher.FileWatcher
	nodeInfos       map[string]ipSecInfo
}

func NewIpSecHandler() *IpSecHandler {
	return &IpSecHandler{
		nodeInfos: make(map[string]ipSecInfo),
	}
}

func (is *IpSecHandler) LoadIPSecKeyFromFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("load ipsec keys failed: %v", err)
	}
	defer file.Close()

	is.ipSecLoadLock.Lock()
	defer is.ipSecLoadLock.Unlock()

	// [spi] aead-algo aead-keyLine icv-len
	// only tail line effect
	err = is.loadIPSecKeyFromIO(file)
	if err != nil {
		return err
	}
	return nil
}

func (is *IpSecHandler) loadIPSecKeyFromIO(file *os.File) error {
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		keyLine := strings.Split(scanner.Text(), " ")
		if len(keyLine) != 4 {
			return fmt.Errorf("ipsec config file error, invalid format, need aead algo")
		}
		err := is.parserSpi(keyLine)
		if err != nil {
			return err
		}
		err = is.parserAeadKey(keyLine)
		if err != nil {
			return err
		}
	}
	return nil
}

func (is *IpSecHandler) parserAeadKey(keyLine []string) error {
	if !strings.HasPrefix(keyLine[offsetAead], "rfc") {
		return fmt.Errorf("ipsec config file error, invalid algo name, aead need begin with \"rfc\"")
	}
	is.AeadKeyName = keyLine[offsetAead]
	baseKeyTrim := strings.TrimPrefix(keyLine[offsetAeadKey], "0x")
	if key, err := hex.DecodeString(baseKeyTrim); err != nil {
		return fmt.Errorf("ipsec config file error, aead key decode failed, err is %v", err)
	} else {
		is.AeadKey = key
	}

	if length, err := strconv.Atoi(keyLine[offsetAeadLen]); err != nil {
		return fmt.Errorf("ipsec config file error, aead key length invalid, err is %v", err)
	} else {
		is.Length = length
	}
	return nil
}

func (is *IpSecHandler) parserSpi(key []string) error {
	spiload, err := strconv.Atoi(key[offsetSpi])
	if err != nil {
		return fmt.Errorf("ipsec config file error, invalid spi format, spi must a number, spi input is %v", key[offsetSpi])
	}

	if is.Spi != 0 {
		is.OldSpi = is.Spi
	}

	is.Spi = int8(spiload)
	/* spi only support 1 - 15 */
	if is.Spi < 1 || is.Spi > 15 {
		return fmt.Errorf("ipsec config file error, invalid spi range(1-15), spi input is %v", key[offsetSpi])
	}
	return nil
}

func (is *IpSecHandler) StartWatch(f func(is *IpSecHandler)) error {
	is.watcher = filewatcher.NewWatcher()

	if err := is.watcher.Add(IpSecKeyFile); err != nil {
		return fmt.Errorf("failed to add %s to file watcher: %v", IpSecKeyFile, err)
	}
	go func() {
		log.Infof("start watching file %s", IpSecKeyFile)

		var timerC <-chan time.Time
		for {
			select {
			case <-timerC:
				timerC = nil
				is.ipSecUpdateLock.Lock()
				if err := is.LoadIPSecKeyFromFile(IpSecKeyFile); err != nil {
					log.Errorf("failed to update ipsec, %v", err)
					is.ipSecUpdateLock.Unlock()
					continue
				}
				f(is)
				is.ipSecUpdateLock.Unlock()

			case event := <-is.watcher.Events(IpSecKeyFile):
				log.Debugf("got event %s", event.String())

				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					if timerC == nil {
						timerC = time.After(100 * time.Millisecond)
					}
				}
			case err := <-is.watcher.Errors(IpSecKeyFile):
				if err != nil {
					log.Errorf("err from errors channel of file watcher: %v", err)
					return
				}
			}
		}
	}()
	return nil
}

func (is *IpSecHandler) StopWatch() {
	if err := is.watcher.Close(); err != nil {
		log.Errorf("failed to close fsnotify watcher: %v", err)
	}
}

func (is *IpSecHandler) SetNodeInfo(IP, bootID string, spi int8) {
	var sum Sum
	sum.Write([]byte(IP))
	nodeID := sum.Sum16()

	ipSecInfo := ipSecInfo{
		bootID: bootID,
		spi:    spi,
		nodeID: nodeID,
	}
	is.nodeInfos[IP] = ipSecInfo
}

func (is *IpSecHandler) GetNodeID(IP string) uint16 {
	if ret, ok := is.nodeInfos[IP]; ok {
		return ret.nodeID
	}
	return 0
}

func (is *IpSecHandler) generateIPSecKey(srcIP, dstIP, srcBootID, dstBootID string) []byte {
	inputLen := len(is.AeadKey) + len(srcIP) + len(dstIP) + len(srcBootID) + len(dstBootID)
	input := make([]byte, 0, inputLen)
	input = append(input, is.AeadKey...)
	input = append(input, []byte(srcIP)...)
	input = append(input, []byte(dstIP)...)
	input = append(input, []byte(srcBootID)[:36]...)
	input = append(input, []byte(dstBootID)[:36]...)

	hash := sha512.Sum512(input)
	return hash[:len(is.AeadKey)]
}

func (is *IpSecHandler) CreateXfrmRule(rawSrc, rawDst string, rawDstCIDR string, out bool) error {
	is.ipSecUpdateLock.Lock()
	defer is.ipSecUpdateLock.Unlock()
	src := net.ParseIP(rawSrc)
	if src == nil {
		return fmt.Errorf("failed to parser ip in inserting xfrm rule, input: %v", rawSrc)
	}
	dst := net.ParseIP(rawDst)
	if dst == nil {
		return fmt.Errorf("failed to parser ip in inserting xfrm rule, input: %v", rawDst)
	}

	srcInfo, ok := is.nodeInfos[rawSrc]
	if !ok {
		return fmt.Errorf("failed to get src nodeinfo, src is %v", rawSrc)
	}

	dstInfo, ok := is.nodeInfos[rawDst]
	if !ok {
		return fmt.Errorf("failed to get dst nodeinfo, dst is %v", rawDst)
	}

	newKey := is.generateIPSecKey(rawSrc, rawDst, srcInfo.bootID, dstInfo.bootID)

	err := is.createStateRule(src, dst, newKey, int(dstInfo.spi))
	if err != nil {
		return err
	}

	_, srcCIDR, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		return fmt.Errorf("failed to parser CIDR in inserting xfrm rule, %v", err)
	}

	_, dstCIRD, err := net.ParseCIDR(rawDstCIDR)
	if err != nil {
		return fmt.Errorf("failed to parser CIDR in inserting xfrm rule, %v", err)
	}

	nodeID := ""
	if out {
		nodeID = fmt.Sprintf("%x", dstInfo.nodeID)
	} else {
		nodeID = fmt.Sprintf("%x", srcInfo.nodeID)
	}
	err = is.createPolicyRule(srcCIDR, dstCIRD, src, dst, nodeID, out)
	if err != nil {
		return err
	}

	return nil
}

func (is *IpSecHandler) Clean(target string) error {
	targetIP := net.ParseIP(target)
	oldPolicyList, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for _, policy := range oldPolicyList {
		for _, tmpl := range policy.Tmpls {
			if tmpl.Src.Equal(targetIP) {
				err = netlink.XfrmPolicyDel(&policy)
				if err != nil {
					return err
				}
				continue
			}
			if tmpl.Dst.Equal(targetIP) {
				err = netlink.XfrmPolicyDel(&policy)
				if err != nil {
					return err
				}
				continue
			}
		}
	}
	oldStateList, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	for _, state := range oldStateList {
		if state.Src.Equal(targetIP) {
			err = netlink.XfrmStateDel(&state)
			if err != nil {
				return err
			}
			continue
		}
		if state.Dst.Equal(targetIP) {
			err = netlink.XfrmStateDel(&state)
			if err != nil {
				return err
			}
			continue
		}
	}
	return nil
}

func (is *IpSecHandler) CleanAll() error {
	oldPolicyList, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for _, policy := range oldPolicyList {
		err = netlink.XfrmPolicyDel(&policy)
		if err != nil {
			return err
		}
	}
	oldStateList, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	for _, state := range oldStateList {
		err = netlink.XfrmStateDel(&state)
		if err != nil {
			return err
		}
	}
	return nil
}

func (is *IpSecHandler) createPolicyRule(srcCIDR, dstCIDR *net.IPNet, src, dst net.IP, nodeID string, out bool) error {
	policy := &netlink.XfrmPolicy{
		Src: srcCIDR,
		Dst: dstCIDR,
		Tmpls: []netlink.XfrmPolicyTmpl{
			{
				Src:   src,
				Dst:   dst,
				Proto: netlink.XFRM_PROTO_ESP,
				Reqid: 1,
				Mode:  netlink.XFRM_MODE_TUNNEL,
			},
		},
		Mark: &netlink.XfrmMark{},
	}

	if out {
		mark, err := strconv.ParseInt(nodeID+"0"+fmt.Sprintf("%x", int(is.Spi))+"e0", 16, 64)
		if err != nil {
			return fmt.Errorf("failed to convert mark in inserting xfrm out rule, %v", err)
		}

		policy.Mark.Value = uint32(mark)
		policy.Tmpls[0].Spi = int(is.Spi)
		policy.Dir = netlink.XFRM_DIR_OUT

		if err = is.xfrmPolicyCreateOrUpdate(policy); err != nil {
			return err
		}
	} else {
		mark, err := strconv.ParseInt(nodeID+"00d0", 16, 64)
		if err != nil {
			return fmt.Errorf("failed to convert mark in inserting xfrm in rule, %v", err)
		}

		policy.Mark.Value = uint32(mark)
		policy.Dir = netlink.XFRM_DIR_IN
		if err = is.xfrmPolicyCreateOrUpdate(policy); err != nil {
			return err
		}

		policy.Dir = netlink.XFRM_DIR_FWD
		if err = is.xfrmPolicyCreateOrUpdate(policy); err != nil {
			return err
		}
	}
	return nil
}

func (*IpSecHandler) xfrmPolicyCreateOrUpdate(policy *netlink.XfrmPolicy) error {
	err := netlink.XfrmPolicyAdd(policy)
	if err != nil && os.IsExist(err) {
		err = netlink.XfrmPolicyUpdate(policy)
	}
	if err != nil {
		return fmt.Errorf("failed to add xfrm policy to host in inserting xfrm fwd rule, %v", err)
	}
	return nil
}

func (is *IpSecHandler) createStateRule(src net.IP, dst net.IP, key []byte, spi int) error {
	state := &netlink.XfrmState{
		Src:   src,
		Dst:   dst,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Spi:   spi,
		Reqid: 1,
		Aead: &netlink.XfrmStateAlgo{
			Name:   is.AeadKeyName,
			Key:    key,
			ICVLen: is.Length,
		},
	}
	err := netlink.XfrmStateAdd(state)
	if err != nil && os.IsExist(err) {
		err = netlink.XfrmStateUpdate(state)
	}
	if err != nil {
		return fmt.Errorf("failed to add xfrm state to host in inserting xfrm out rule, %v", err)
	}
	return nil
}

func (is *IpSecHandler) CreateNewStateFromOldByLocalNidIP(nicIP []string) error {
	oldStateList, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to list all xfrm state, %v", err)
	}
	for _, ipString := range nicIP {
		ip := net.ParseIP(ipString)
		for _, state := range oldStateList {
			if !state.Dst.Equal(ip) {
				continue
			}
			if state.Spi != int(is.OldSpi) && state.Spi != int(is.Spi) {
				netlink.XfrmStateDel(&state)
				continue
			}
			if state.Spi == int(is.Spi) {
				continue
			}

			srcInfo, ok := is.nodeInfos[state.Src.String()]
			if !ok {
				return fmt.Errorf("failed to get src nodeinfo, src is %v", state.Src.String())
			}

			dstInfo, ok := is.nodeInfos[state.Dst.String()]
			if !ok {
				return fmt.Errorf("failed to get dst nodeinfo, dst is %v", state.Dst.String())
			}

			state.Aead.Key = is.generateIPSecKey(state.Src.String(), state.Dst.String(), srcInfo.bootID, dstInfo.bootID)
			state.Spi = int(is.Spi)
			if err = netlink.XfrmStateAdd(&state); err != nil {
				return fmt.Errorf("failed to add xfrm state to host in create new state from old, err is %v", err)
			}
		}
	}
	return nil
}
