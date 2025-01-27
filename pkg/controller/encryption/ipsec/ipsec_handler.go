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
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/vishvananda/netlink"
	"istio.io/istio/pkg/filewatcher"

	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/kube/apis/kmeshnodeinfo/v1alpha1"
)

const (
	IpSecKeyFile = "./kmesh-ipsec/ipSec"
)

type IpSecKey struct {
	Spi         int    `json:"spi"`
	AeadKeyName string `json:"aeadKeyName"`
	AeadKey     []byte `json:"aeadKey"`
	Length      int    `json:"length"`
}

type IpSecHandler struct {
	Spi             int
	mutex           sync.RWMutex
	watcher         filewatcher.FileWatcher
	historyIpSecKey map[int]IpSecKey
}

func NewIpSecHandler() *IpSecHandler {
	return &IpSecHandler{
		historyIpSecKey: make(map[int]IpSecKey),
	}
}

func (is *IpSecHandler) LoadIPSecKeyFromFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("load ipsec keys failed: %v", err)
	}
	defer file.Close()

	err = is.loadIPSecKeyFromIO(file)
	if err != nil {
		return err
	}
	return nil
}

func (is *IpSecHandler) loadIPSecKeyFromIO(file *os.File) error {
	reader := bufio.NewReader(file)
	decoder := json.NewDecoder(reader)
	var key IpSecKey
	if err := decoder.Decode(&key); err != nil {
		return fmt.Errorf("ipsec config file decoder error, %v, please use Kmesh tool generate ipsec secret key", err)
	}
	if !strings.HasPrefix(key.AeadKeyName, "rfc") {
		return fmt.Errorf("ipsec config file error, invalid algo name, aead need begin with \"rfc\"")
	}
	is.Spi = key.Spi
	is.historyIpSecKey[is.Spi] = key
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

func (is *IpSecHandler) generateIPSecKey(srcIP, dstIP, srcBootID, dstBootID string, key []byte) []byte {
	inputLen := len(key) + len(srcIP) + len(dstIP) + len(srcBootID) + len(dstBootID)
	input := make([]byte, 0, inputLen)
	input = append(input, key...)
	input = append(input, []byte(srcIP)...)
	input = append(input, []byte(dstIP)...)
	input = append(input, []byte(srcBootID)[:36]...)
	input = append(input, []byte(dstBootID)[:36]...)

	hash := sha512.Sum512(input)
	return hash[:len(key)]
}

func (is *IpSecHandler) CreateXfrmRule(localNode, remoteNode *v1alpha1.KmeshNodeInfo) error {
	ipsecKey, ok := is.historyIpSecKey[remoteNode.Spec.SPI]
	if !ok {
		// not found spi! May be i haven't record, skip
		log.Warnf("can not found the spi key, maybe spi has expire before kmesh start")
		return nil
	}
	for _, remoteNicIP := range remoteNode.Spec.Addresses {
		for _, localNicIP := range localNode.Spec.Addresses {
			if err := is.createXfrmRuleIngress(remoteNicIP, localNicIP, remoteNode.Spec.BootID, localNode.Spec.BootID,
				localNode.Spec.SPI, localNode.Spec.PodCIDRs); err != nil {
				return err
			}
			// remoteIPInfo may no exist
			if remoteNode.Spec.SPI > localNode.Spec.SPI {
				// my ipsec not update, do nothing, I will do egress again when ipsec watch file update
				// only add ingress
				continue
			}

			if err := is.createXfrmRuleEgress(localNicIP, remoteNicIP, localNode.Spec.BootID, remoteNode.Spec.BootID,
				ipsecKey, remoteNode.Spec.PodCIDRs); err != nil {
				return fmt.Errorf("create xfrm out rule failed, %v", err)
			}
		}
	}
	return nil
}

/*
 * src is remote host, dst is local host
 * create xfrm rule like:
 * ip xfrm state  add src {rawRemoteIP} dst {rawLocalNicIP} proto esp {rawLocalSpi} mode tunnel reqid 1 {aead-algo} {aead-key} {aead-key-length}
 * ip xfrm policy add src 0.0.0.0/0     dst {rawLocalCIDR}  dir in  tmpl src {rawRemoteIP} dst {rawLocalNicIP} proto esp reqid 1 mode tunnel mark 0x{remoteNodeID}00d0 mask 0xffffffff
 * ip xfrm policy add src 0.0.0.0/0     dst {rawLocalCIDR}  dir fwd tmpl src {rawRemoteIP} dst {rawLocalNicIP} proto esp reqid 1 mode tunnel mark 0x{remoteNodeID}00d0 mask 0xffffffff
 * remoteid = sum(rawRemoteIP)
 */
func (is *IpSecHandler) createXfrmRuleIngress(rawRemoteIP, rawLocalNicIP, remoteBootID, localBootID string, spi int, podCIDRs []string) error {
	src := net.ParseIP(rawRemoteIP)
	if src == nil {
		return fmt.Errorf("failed to parser ip in inserting xfrm rule, input: %v", rawRemoteIP)
	}
	dst := net.ParseIP(rawLocalNicIP)
	if dst == nil {
		return fmt.Errorf("failed to parser ip in inserting xfrm rule, input: %v", rawLocalNicIP)
	}

	// localNicIPInfo must exist, spi is local node info spi
	newKey := is.generateIPSecKey(rawRemoteIP, rawLocalNicIP, remoteBootID, localBootID, is.historyIpSecKey[spi].AeadKey)

	err := is.createStateRule(src, dst, newKey, is.historyIpSecKey[spi])
	if err != nil {
		return err
	}

	_, remoteCIDR, err := net.ParseCIDR(constants.ALL_CIDR)
	if err != nil {
		return fmt.Errorf("failed to parser podCIDR in inserting xfrm rule, %v", err)
	}

	for _, pocCIDR := range podCIDRs {
		_, localCIDR, err := net.ParseCIDR(pocCIDR)
		if err != nil {
			return fmt.Errorf("failed to parser podCIDR in inserting xfrm rule, %v", err)
		}
		if err = is.createPolicyRule(remoteCIDR, localCIDR, src, dst, 0, true); err != nil {
			return fmt.Errorf("failed to create policy rule, %v", err)
		}
	}

	return nil
}

/*
 * src is local host, dst is remote host
 * create xfrm rule like:
 * ip xfrm state  add src {localNicIP} dst {remoteNicIP} proto esp spi {remoteSpi} mode tunnel reqid 1 {aead-algo} {aead-key} {aead-key-length}
 * ip xfrm policy add src 0.0.0.0/0    dst {remoteCIDR}  dir out tmpl src {localNicIP} dst {remoteNicIP} proto esp spi {remoteSpi} reqid 1 mode tunnel mark 0x{remoteNodeID}00e0
 */
func (is *IpSecHandler) createXfrmRuleEgress(rawLocalNicIP, rawRemoteIP, localBootID, remoteBootID string, ipsecKey IpSecKey, podCIDRs []string) error {
	src := net.ParseIP(rawLocalNicIP)
	if src == nil {
		return fmt.Errorf("failed to parser ip in inserting xfrm rule, input: %v", rawLocalNicIP)
	}

	dst := net.ParseIP(rawRemoteIP)
	if dst == nil {
		return fmt.Errorf("failed to parser ip in inserting xfrm rule, input: %v", rawRemoteIP)
	}

	newKey := is.generateIPSecKey(rawLocalNicIP, rawRemoteIP, localBootID, remoteBootID, ipsecKey.AeadKey)

	err := is.createStateRule(src, dst, newKey, ipsecKey)
	if err != nil {
		return err
	}

	_, localCIDR, err := net.ParseCIDR(constants.ALL_CIDR)
	if err != nil {
		return fmt.Errorf("failed to parser podCIDR in inserting xfrm rule, %v", err)
	}

	for _, podCIDR := range podCIDRs {
		_, remoteCIDR, err := net.ParseCIDR(podCIDR)
		if err != nil {
			return fmt.Errorf("failed to parser podCIDR in inserting xfrm rule, %v", err)
		}
		if err = is.createPolicyRule(localCIDR, remoteCIDR, src, dst, ipsecKey.Spi, false); err != nil {
			return fmt.Errorf("failed to create policy rule, %v", err)
		}
	}

	return nil
}

func (is *IpSecHandler) createStateRule(src net.IP, dst net.IP, key []byte, ipsecKey IpSecKey) error {
	state := &netlink.XfrmState{
		Src:   src,
		Dst:   dst,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Spi:   ipsecKey.Spi,
		Reqid: 1,
		Aead: &netlink.XfrmStateAlgo{
			Name:   ipsecKey.AeadKeyName,
			Key:    key,
			ICVLen: ipsecKey.Length,
		},
	}
	err := netlink.XfrmStateAdd(state)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to add xfrm state to host in inserting xfrm out rule, %v", err)
	}
	return nil
}

func (is *IpSecHandler) createPolicyRule(srcCIDR, dstCIDR *net.IPNet, src, dst net.IP, spi int, out bool) error {
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
		Mark: &netlink.XfrmMark{
			Mask: 0xffffffff,
		},
	}
	if out {
		// ingress
		mark := uint32(0xd0)
		policy.Mark.Value = mark

		policy.Dir = netlink.XFRM_DIR_IN
		if err := is.xfrmPolicyCreateOrUpdate(policy); err != nil {
			return err
		}

		policy.Dir = netlink.XFRM_DIR_FWD
		if err := is.xfrmPolicyCreateOrUpdate(policy); err != nil {
			return err
		}
	} else {
		// egress, update SPI
		mark := uint32(0xe0)

		policy.Mark.Value = uint32(mark)
		policy.Tmpls[0].Spi = int(spi)
		policy.Dir = netlink.XFRM_DIR_OUT

		if err := is.xfrmPolicyCreateOrUpdate(policy); err != nil {
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

func (is *IpSecHandler) Flush() error {
	netlink.XfrmPolicyFlush()
	netlink.XfrmStateFlush(netlink.XFRM_PROTO_ESP)
	return nil
}
