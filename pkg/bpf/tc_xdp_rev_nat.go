
package bpf

// #cgo pkg-config: bpf api-v1-c
// #cgo LDFLAGS: -Wl,--allow-multiple-definition
import "C"
import (
"fmt"
"github.com/cilium/ebpf"
"github.com/cilium/ebpf/link"
"openeuler.io/mesh/bpf/slb/bpf2go"
"os"
"reflect"
)

type TcXdpRevnat struct {
	Info 		BpfInfo
	Link		link.Link
	bpf2go.TcXdpRevnatObjects
}

func NewTcXdpRevnat(cfg *Config) (TcXdpRevnat, error) {
	tcRevNat := TcXdpRevnat{}
	tcRevNat.Info.Config = *cfg


	tcRevNat.Info.BpfFsPath += "/xdp_banlance/"
	tcRevNat.Info.MapPath = tcRevNat.Info.BpfFsPath + "map/"
	if err := os.MkdirAll(tcRevNat.Info.MapPath, 0750); err != nil && !os.IsExist(err) {
		return tcRevNat, err
	}

	return tcRevNat, nil
}



func (tc *TcXdpRevnat) LoadTcRevnatObjects() (*ebpf.CollectionSpec, error) {
	var (
		err		error
		spec	*ebpf.CollectionSpec
		opts 	ebpf.CollectionOptions
	)
	opts.Maps.PinPath = tc.Info.MapPath

	if spec, err = bpf2go.LoadTcXdpRevnat(); err != nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&tc.TcXdpRevnatObjects, &opts); err != nil {
		return nil, fmt.Errorf("TcXdpRevnat: LoadAndAssign return err %s", err)
	}

	value := reflect.ValueOf(tc.TcXdpRevnatObjects.TcXdpRevnatPrograms)
	if err = pinPrograms(&value, tc.Info.BpfFsPath); err != nil {
		return nil, err
	}

	return spec, nil
}

func (tc *TcXdpRevnat) Load() error {
	if _, err := tc.LoadTcRevnatObjects(); err != nil {
		return err
	}

	return nil
}

func (tc *TcXdpRevnat) Attach() error {
/*	opts := link.RawLinkOptions {
		Program: tc.TcXdpRevnatObjects.TcXdpRevNat,
		Attach: ebpf.AttachCGroupInetEgress,
		Target: 2, //interface id ens4

	}
	rawLink, err := link.AttachRawLink(opts)
	if err != nil {
		return fmt.Errorf("LoadAndAssign return err %s", err)
	}
	tc.Link = rawLink*/

/*	rawLink, err := AttachRawLink(RawLinkOptions{
		Program: opts.Program,
		Attach:  ebpf.AttachXDP,
		Target:  opts.Interface,
		Flags:   uint32(opts.Flags),
	})*/

	return nil
}

func (tc *TcXdpRevnat) close() error {
	if err := tc.TcXdpRevnatObjects.Close(); err != nil {
		return err
	}
	return nil
}

func (tc *TcXdpRevnat) Detach() error {
	var value reflect.Value

	if err := tc.close(); err != nil {
		return err
	}

	value = reflect.ValueOf(tc.TcXdpRevnatObjects.TcXdpRevnatPrograms)
	if err := unpinPrograms(&value); err != nil {
		return err
	}
	value = reflect.ValueOf(tc.TcXdpRevnatObjects.TcXdpRevnatMaps)
	if err := unpinMaps(&value); err != nil {
		return err
	}

	if err := os.RemoveAll(tc.Info.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if tc.Link != nil {
		return tc.Link.Close()
	}
	return nil
}


