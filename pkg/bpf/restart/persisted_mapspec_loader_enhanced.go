//go:build enhanced
// +build enhanced

package restart

import (
	"fmt"

	"github.com/cilium/ebpf"

	"kmesh.net/kmesh/daemon/options"

	dualengine "kmesh.net/kmesh/bpf/kmesh/bpf2go/dualengine"
	general "kmesh.net/kmesh/bpf/kmesh/bpf2go/general"
	kernelnative "kmesh.net/kmesh/bpf/kmesh/bpf2go/kernelnative/enhanced"
)

func LoadCompileTimeSpecs(config *options.BpfConfig) (map[string]map[string]*ebpf.MapSpec, error) {
	specs := make(map[string]map[string]*ebpf.MapSpec)

	if config.KernelNativeEnabled() {
		if coll, err := kernelnative.LoadKmeshCgroupSock(); err != nil {
			return nil, fmt.Errorf("load KernelNative KmeshCgroupSock spec: %w", err)
		} else {
			specs["KmeshCgroupSock"] = coll.Maps
		}
		if coll, err := kernelnative.LoadKmeshCgroupSockCompat(); err != nil {
			return nil, fmt.Errorf("load KernelNative KmeshCgroupSockCompat spec: %w", err)
		} else {
			specs["KmeshCgroupSockCompat"] = coll.Maps
		}
		if coll, err := kernelnative.LoadKmeshSockops(); err != nil {
			return nil, fmt.Errorf("load KernelNative KmeshSockops spec: %w", err)
		} else {
			specs["KmeshSockops"] = coll.Maps
		}
		if coll, err := kernelnative.LoadKmeshSockopsCompat(); err != nil {
			return nil, fmt.Errorf("load KernelNative KmeshSockopsCompat spec: %w", err)
		} else {
			specs["KmeshSockopsCompat"] = coll.Maps
		}
	} else if config.DualEngineEnabled() {
		if coll, err := dualengine.LoadKmeshCgroupSockWorkload(); err != nil {
			return nil, fmt.Errorf("load DualEngine KmeshCgroupSockWorkload spec: %w", err)
		} else {
			specs["KmeshCgroupSockWorkload"] = coll.Maps
		}
		if coll, err := dualengine.LoadKmeshCgroupSockWorkloadCompat(); err != nil {
			return nil, fmt.Errorf("load DualEngine KmeshCgroupSockWorkloadCompat spec: %w", err)
		} else {
			specs["KmeshCgroupSockWorkloadCompat"] = coll.Maps
		}
		if coll, err := dualengine.LoadKmeshSockopsWorkload(); err != nil {
			return nil, fmt.Errorf("load DualEngine KmeshSockopsWorkload spec: %w", err)
		} else {
			specs["KmeshSockopsWorkload"] = coll.Maps
		}
		if coll, err := dualengine.LoadKmeshSockopsWorkloadCompat(); err != nil {
			return nil, fmt.Errorf("load DualEngine KmeshSockopsWorkloadCompat spec: %w", err)
		} else {
			specs["KmeshSockopsWorkloadCompat"] = coll.Maps
		}
		if coll, err := dualengine.LoadKmeshXDPAuth(); err != nil {
			return nil, fmt.Errorf("load DualEngine KmeshXDPAuth spec: %w", err)
		} else {
			specs["KmeshXDPAuth"] = coll.Maps
		}
		if coll, err := dualengine.LoadKmeshXDPAuthCompat(); err != nil {
			return nil, fmt.Errorf("load DualEngine KmeshXDPAuthCompat spec: %w", err)
		} else {
			specs["KmeshXDPAuthCompat"] = coll.Maps
		}
		if coll, err := dualengine.LoadKmeshSendmsg(); err != nil {
			return nil, fmt.Errorf("load DualEngine KmeshSendmsg spec: %w", err)
		} else {
			specs["KmeshSendmsg"] = coll.Maps
		}
		if coll, err := dualengine.LoadKmeshSendmsgCompat(); err != nil {
			return nil, fmt.Errorf("load DualEngine KmeshSendmsgCompat spec: %w", err)
		} else {
			specs["KmeshSendmsgCompat"] = coll.Maps
		}
		if coll, err := dualengine.LoadKmeshCgroupSkb(); err != nil {
			return nil, fmt.Errorf("load DualEngine KmeshCgroupSkb spec: %w", err)
		} else {
			specs["KmeshCgroupSkb"] = coll.Maps
		}
		if coll, err := dualengine.LoadKmeshCgroupSkbCompat(); err != nil {
			return nil, fmt.Errorf("load DualEngine KmeshCgroupSkbCompat spec: %w", err)
		} else {
			specs["KmeshCgroupSkbCompat"] = coll.Maps
		}
	}

	if coll, err := general.LoadKmeshTcMarkEncrypt(); err != nil {
		return nil, fmt.Errorf("load General KmeshTcMarkEncrypt spec: %w", err)
	} else {
		specs["KmeshTcMarkEncrypt"] = coll.Maps
	}
	if coll, err := general.LoadKmeshTcMarkEncryptCompat(); err != nil {
		return nil, fmt.Errorf("load General KmeshTcMarkEncryptCompat spec: %w", err)
	} else {
		specs["KmeshTcMarkEncryptCompat"] = coll.Maps
	}
	if coll, err := general.LoadKmeshTcMarkDecrypt(); err != nil {
		return nil, fmt.Errorf("load General KmeshTcMarkDecrypt spec: %w", err)
	} else {
		specs["KmeshTcMarkDecrypt"] = coll.Maps
	}
	if coll, err := general.LoadKmeshTcMarkDecryptCompat(); err != nil {
		return nil, fmt.Errorf("load General KmeshTcMarkDecryptCompat spec: %w", err)
	} else {
		specs["KmeshTcMarkDecryptCompat"] = coll.Maps
	}

	return specs, nil
}
