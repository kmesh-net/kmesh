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

package ipsec

import (
	"bufio"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/vishvananda/netlink"
	"istio.io/istio/pkg/filewatcher"
)

const (
	IpSecKeyFile  = "./kmesh-ipsec/keys"
	offsetSpi     = 0
	offsetAead    = 1
	offsetAeadKey = 2
	offsetAeadLen = 3
)

type ipSecInfo struct {
	bootID        string
	spi           int8
	nodeID        uint32
	spiCreateTime string
}

type IpSecKey struct {
	Spi         int8   `json:"spi"`
	AeadKeyName string `json:"aeadKeyName"`
	AeadKey     []byte `json:"aeadKey"`
	Length      int    `json:"length"`
	CreateTime  string `json:"createTime"`
}

type IpSecHandler struct {
	IpSecKey
	mutex       sync.RWMutex
	watcher     filewatcher.FileWatcher
	nodeInfos   map[string]ipSecInfo
	oldIpSecKey map[string]IpSecKey
}

func NewIpSecHandler() *IpSecHandler {
	return &IpSecHandler{
		nodeInfos:   make(map[string]ipSecInfo),
		oldIpSecKey: make(map[string]IpSecKey),
	}
}

func (is *IpSecHandler) LoadIPSecKeyFromFile(filePath string) error {
	if is.IpSecKey.Spi != 0 {
		is.oldIpSecKey[is.CreateTime] = is.IpSecKey
	}

	for key := range is.oldIpSecKey {
		keyCreateTime, err := time.Parse(TimeFormatString, key)
		if err != nil {
			return fmt.Errorf("failed to parser key create time, %v", err)
		}
		if keyCreateTime.Add(1 * time.Hour).Before(time.Now()) {
			delete(is.oldIpSecKey, key)
		}
	}

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("load ipsec keys failed: %v", err)
	}
	defer file.Close()

	// [spi] aead-algo aead-keyLine icv-len
	// only tail line effect
	err = is.loadIPSecKeyFromIO(file)
	if err != nil {
		return err
	}
	return nil
}

func (is *IpSecHandler) loadIPSecKeyFromIO(file *os.File) error {
	reader := bufio.NewReader(file)
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&is.IpSecKey); err != nil {
		return fmt.Errorf("ipsec config file decoder error, %v, please use Kmesh tool generate ipsec secret key", err)
	}
	if is.Spi < 1 || is.Spi > 15 {
		return fmt.Errorf("ipsec config file error, invalid spi range(1-15), spi input is %v", is.Spi)
	}
	if !strings.HasPrefix(is.AeadKeyName, "rfc") {
		return fmt.Errorf("ipsec config file error, invalid algo name, aead need begin with \"rfc\"")
	}

	return nil
}

func (h *IpSecHandler) StartWatch(f func()) error {
	h.watcher = filewatcher.NewWatcher()
	if err := h.watcher.Add(IpSecKeyFile); err != nil {
		return fmt.Errorf("failed to add %s to file watcher: %v", IpSecKeyFile, err)
	}
	go func() {
		log.Infof("start watching file %s", IpSecKeyFile)

		var timerC <-chan time.Time
		for {
			select {
			case <-timerC:
				timerC = nil
				h.mutex.Lock()
				if err := h.LoadIPSecKeyFromFile(IpSecKeyFile); err != nil {
					log.Errorf("failed to load ipsec key, %v", err)
					h.mutex.Unlock()
					continue
				}
				f()
				h.mutex.Unlock()

			case event := <-h.watcher.Events(IpSecKeyFile):
				log.Debugf("got event %s", event.String())
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) ||
					event.Has(fsnotify.Rename) || event.Has(fsnotify.Chmod) {
					if timerC == nil {
						timerC = time.After(100 * time.Millisecond)
					}
				}
			case err := <-h.watcher.Errors(IpSecKeyFile):
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
	if is.watcher == nil {
		return
	}
	if err := is.watcher.Close(); err != nil {
		log.Errorf("failed to close fsnotify watcher: %v", err)
	}
}

func (is *IpSecHandler) SetNodeInfo(IP, bootID string, spi int8, createTime string) {
	var sum = fnv.New32()
	sum.Write([]byte(IP))
	nodeID := sum.Sum32()

	ipSecInfo := ipSecInfo{
		bootID:        bootID,
		spi:           spi,
		nodeID:        nodeID,
		spiCreateTime: createTime,
	}
	is.nodeInfos[IP] = ipSecInfo
}

func (is *IpSecHandler) GetNodeID(IP string) uint32 {
	if ret, ok := is.nodeInfos[IP]; ok {
		return ret.nodeID
	}
	return 0
}

func (is *IpSecHandler) generateIPSecKey(srcIP, dstIP, srcBootID, dstBootID string, key []byte) []byte {
	inputLen := len(is.AeadKey) + len(srcIP) + len(dstIP) + len(srcBootID) + len(dstBootID)
	input := make([]byte, 0, inputLen)
	input = append(input, key...)
	input = append(input, []byte(srcIP)...)
	input = append(input, []byte(dstIP)...)
	input = append(input, []byte(srcBootID)[:36]...)
	input = append(input, []byte(dstBootID)[:36]...)

	hash := sha512.Sum512(input)
	return hash[:len(is.AeadKey)]
}

func (is *IpSecHandler) CreateXfrmRule(rawSrc, rawDst string, rawDstCIDR string, out bool) error {
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

	var aeadKey []byte
	var targetInfo ipSecInfo
	if out {
		// update egress, maybe dst is old spi, use dstinfo spi update
		targetInfo = dstInfo
	} else {
		// update ingress, maybe src is old spi, use srcinfo spi update
		targetInfo = srcInfo
	}
	if is.Spi == targetInfo.spi && strings.Compare(is.CreateTime, targetInfo.spiCreateTime) == 0 {
		aeadKey = is.AeadKey
	} else {
		oldKey, ok := is.oldIpSecKey[targetInfo.spiCreateTime]
		if !ok {
			return fmt.Errorf("failed to get old spi, spi create time is %v, spi is %v", targetInfo.spiCreateTime, targetInfo.spi)
		}
		aeadKey = oldKey.AeadKey
	}

	newKey := is.generateIPSecKey(rawSrc, rawDst, srcInfo.bootID, dstInfo.bootID, aeadKey)

	err := is.createStateRule(src, dst, newKey, int(targetInfo.spi))
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

func (is *IpSecHandler) Clean(ip string) error {
	targetIP := net.ParseIP(ip)
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
	if err != nil {
		return err
	}
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
			log.Errorf("failed to delete xfrm policy, %v", err)
			continue
		}
	}
	oldStateList, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to list all xfrm state, %v", err)
	}
	for _, state := range oldStateList {
		err = netlink.XfrmStateDel(&state)
		if err != nil {
			log.Errorf("failed to delete xfrm state, %v", err)
			continue
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
	if os.IsExist(err) {
		// xfrm state update can not change has exist state
		// spi should grow step by step. If this spi is delete for
		// a short period of time, a small number of data packets
		// that are being sent by the spi may fail to be sent.
		// However, if the spi that is being sent is not the deleted
		// spi, there is no impact on the spi.
		netlink.XfrmStateDel(state)
		err = netlink.XfrmStateAdd(state)
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
	// TODO: may need to use map to improve performance
	for _, ipString := range nicIP {
		ip := net.ParseIP(ipString)
		for _, state := range oldStateList {
			if !state.Dst.Equal(ip) {
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

			state.Aead.Key = is.generateIPSecKey(state.Src.String(), state.Dst.String(), srcInfo.bootID, dstInfo.bootID, is.AeadKey)
			state.Spi = int(is.Spi)
			err = netlink.XfrmStateAdd(&state)
			if os.IsExist(err) {
				// xfrm state update can not change has exist state
				// spi should grow step by step. If this spi is delete for
				// a short period of time, a small number of data packets
				// that are being sent by the spi may fail to be sent.
				// However, if the spi that is being sent is not the deleted
				// spi, there is no impact on the spi.
				netlink.XfrmStateDel(&state)
				err = netlink.XfrmStateAdd(&state)
			}
			if err != nil {
				return fmt.Errorf("failed to add xfrm state to host in create new state from old, err is %v", err)
			}
		}
	}
	return nil
}
