package restart

import (
	"fmt"
    "path/filepath"
    "os"
    "syscall"

	"encoding/json"
    "reflect"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"kmesh.net/kmesh/pkg/version"
    "kmesh.net/kmesh/daemon/options"
)

type StructDiff struct {
    Removed       bool // fields present in A but missing in B
    Added         bool // fields present in B but missing in A
    TypeChanged   bool // same-name fields whose type changed
    OffsetChanged bool // same-name fields whose offset changed
    NestedChanged bool // same-name fields of struct type whose nested layout changed
}

type MemberInfo struct {
    Name     string `json:"name"`
    TypeName string `json:"typeName"`
    Offset   uint32 `json:"offset"`
    BitfieldSize     uint32 `json:"bitfieldsize"`  // only have value when the type is bitfield
    Nested   *StructInfo `json:"nested,omitempty"`
}

type StructInfo struct {
    Name    string       `json:"name"`
    Members []MemberInfo `json:"members"`
}

type PersistedMapSpec struct {
    Name       string     `json:"name"`
    Type       string     `json:"type"`       // MapType.String()
    KeySize    uint32     `json:"keySize"`
    ValueSize  uint32     `json:"valueSize"`
    MaxEntries uint32     `json:"maxEntries"`
    Flags      uint32     `json:"flags"`
    KeyInfo    StructInfo `json:"keyInfo"`    // get from btf.Struct
    ValueInfo  StructInfo `json:"valueInfo"`
}

type PersistedSnapshot struct {
	Maps    map[string]map[string]PersistedMapSpec `json:"maps"`
}

const {
	MapSpecDir      = "/mnt/kmesh_mapspecs"
    MapSpecFilename = "mapspecs_by_pkg.json"
}

// UpdateMapHandler handles the “Update” case in NewVersionMap.
// It will migrate any BPF maps whose on‑disk pin already exists but whose
// compiled MapSpec has changed
func UpdateMapHandler(versionMap *ebpf.Map, kmBpfPath string, config *options.BpfConfig) *ebpf.Map{
    persistedSpecs, err := LoadPersistedSnapshot()
	if err != nil {
        log.Errorf("load compile map spec failed")
        return nil
    }
	specsByPkg, err := LoadCompileTimeSpecs(config)
	if err != nil {
		log.Errorf("load oldSpecsByPkg failed")
        return nil
	}
    pkgNames, _ := unionKeys(specsByPkg, persistedSpecs.Maps)
    for _, pkgName := range pkgNames {
        newMaps := specsByPkg[pkgName]
        oldMaps := persistedSpecs.Maps[pkgName]
		if newMaps == nil || oldMaps == nil {
			continue
		}

        mapNames, _ := unionKeys(newMaps, oldMaps)
        for _, mapName := range mapNames {
            newSpec, hasNew := newMaps[mapName]
            oldSpec, hasOld := oldMaps[mapName]

            pinPath := filepath.Join(kmBpfPath, mapName)

            switch {
            case !hasNew && hasOld: // clean up
                oldMap, _ := ebpf.LoadPinnedMap(pinPath, &ebpf.LoadPinOptions{})
                if err := oldMap.Unpin(); err != nil && !os.IsNotExist(err) {
                    log.Warnf("failed to unpin old map: %v (continuing)", err)
                }
                if err := oldMap.Close(); err != nil {
                    log.Warnf("failed to close old map FD: %v (continuing)", err)
                }
                if err := os.Remove(pinPath); err != nil && !os.IsNotExist(err) {
                    log.Warnf("failed to remove old map pinpath: %v (continuing)", err)
                }
                break                
            case hasNew && !hasOld:
                if _, err := migrateMap(nil, newSpec, pkgName, mapName, pinPath); err != nil {
                    log.Errorf("create new map %s/%s failed: %v", pkgName, mapName, err)
                }
				break
            case hasNew && hasOld:
                if _, err := migrateMap(&oldSpec, newSpec, pkgName, mapName, pinPath); err != nil {
                    log.Errorf("migrate map %s/%s failed: %v", pkgName, mapName, err)
                }
				break
            }
        }
    }

    log.Infof("kmesh start with Update")
	SnapshotSpecsByPkg(specsByPkg)
    updateVersionInfo(versionMap)
    return versionMap
}

func updateVersionInfo(versionMap *ebpf.Map) {
	key := uint32(0)
	var value uint32
	hash.Reset()
	hash.Write([]byte(version.Get().GitVersion))
	value = hash.Sum32()
	if err := versionMap.Put(&key, &value); err != nil {
		log.Errorf("update Version Map failed, err is %v", err)
	}
}

func MigrateMap(
    oldMapSpec *PersistedMapSpec,
    newMapSpec *ebpf.MapSpec,
    pkgName, mapName, pinPath string,
) (*ebpf.Map, error)  {
    return migrateMap(oldMapSpec, newMapSpec, pkgName, mapName, pinPath)
}

func migrateMap(
    oldMapSpec *PersistedMapSpec,
    newMapSpec *ebpf.MapSpec,
    pkgName, mapName, pinPath string,
) (*ebpf.Map, error)  {
	if oldMapSpec == nil {
		return createEmptyMap(newMapSpec, pinPath, mapName, nil)
	}
    if  oldMapSpec.Type != newMapSpec.Type.String() ||
        oldMapSpec.KeySize != newMapSpec.KeySize ||
        oldMapSpec.ValueSize != newMapSpec.ValueSize || 
        oldMapSpec.MaxEntries != newMapSpec.MaxEntries {
        createEmptyMapWithPinnedMap(newMapSpec, pinPath, mapName)
	}

	if needsRecreate(oldMapSpec.KeyInfo, newMapSpec.Key) {
        createEmptyMapWithPinnedMap(newMapSpec, pinPath, mapName)
    }

    if needsRecreate(oldMapSpec.ValueInfo, newMapSpec.Value) {
        createEmptyMapWithPinnedMap(newMapSpec, pinPath, mapName)
    }
	return nil, nil
}

func needsRecreate(oldStruct StructInfo, newType btf.Type) bool {
    if newType == nil {
        if oldStruct.Name != "" || len(oldStruct.Members) != 0 {
            return true
        }
        return false
    }

    if newStruct, ok := newType.(*btf.Struct); ok {
        diff := diffStructInfoAgainstBTF(oldStruct, newStruct, make(map[string]bool))
        if diff.Added || diff.Removed || diff.TypeChanged ||
            diff.OffsetChanged || diff.NestedChanged {
                return true
        }
        return false
    }

    newTypeName := newType.TypeName()
    if len(oldStruct.Members) != 0 {
        return true
    }
    if oldStruct.Name == "" {
        return true
    }
    if oldStruct.Name != newTypeName {
        return true
    }
    return false
}

func createEmptyMapWithPinnedMap(spec *ebpf.MapSpec, pinPath, mapName string) (*ebpf.Map, error) {
    oldMap, err := ebpf.LoadPinnedMap(pinPath, &ebpf.LoadPinOptions{})
    if err != nil {
        return createEmptyMap(spec, pinPath, mapName, nil)
    }
    return createEmptyMap(spec, pinPath, mapName, oldMap)
}
 
func DiffStructInfoAgainstBTF(
	a StructInfo,
	b *btf.Struct,
	visited map[string]bool,
) StructDiff {
    return diffStructInfoAgainstBTF(a, b, visited)
}

func diffStructInfoAgainstBTF(
	a StructInfo,
	b *btf.Struct,
	visited map[string]bool,
) StructDiff {
	diff := StructDiff{}

	oldMap := make(map[string]MemberInfo, len(a.Members))
	for _, m := range a.Members {
		oldMap[m.Name] = m
	}
	newMap := make(map[string]btf.Member, len(b.Members))
	for _, m := range b.Members {
		newMap[m.Name] = m
	}

    // check added fields (present in new but not in old)
	for name := range newMap {
		if _, ok := oldMap[name]; !ok {
			diff.Added = true
			break
		}
	}

	// check removed / type / offset / nested changes
	for name, map_old := range oldMap {
		map_new, exists := newMap[name]
		if !exists {
			diff.Removed = true
			break
		}

		if map_old.Offset != uint32(map_new.Offset) || map_old.BitfieldSize != uint32(map_new.BitfieldSize) {
			diff.OffsetChanged = true
			break
		}
        
        if map_old.TypeName == map_new.Type.TypeName() {
            if mbStruct, ok := map_new.Type.(*btf.Struct); ok {
                if map_old.Nested != nil {
                    if map_old.Nested.Name != "" {
                        if !visited[map_old.Nested.Name] {
                            visited[map_old.Nested.Name] = true
                            nestedDiff := diffStructInfoAgainstBTF(*map_old.Nested, mbStruct, visited)
                            if nestedDiff.Added || nestedDiff.Removed || nestedDiff.TypeChanged ||
                                nestedDiff.OffsetChanged || nestedDiff.NestedChanged {
                                diff.NestedChanged = true
                                break
                            }
                        }
                        continue
                    }
                }
                diff.NestedChanged = true
                break
            } else { // if new side is not struct
                log.Info(map_old.Nested != nil)
                if map_old.TypeName != map_new.Type.TypeName() || map_old.Nested != nil{
                    diff.TypeChanged = true
		            break
                }
            }
        } else {
		    diff.TypeChanged = true
		    break
        }
    }
    return diff    
}

func createEmptyMap(spec *ebpf.MapSpec, pinPath string, mapName string, oldMap *ebpf.Map) (*ebpf.Map, error) {
    if oldMap == nil {
        if err := os.Remove(pinPath); err != nil && !os.IsNotExist(err) {
            return nil, fmt.Errorf("remove old pin %s failed: %w", pinPath, err)
        }
        m, err := ebpf.NewMap(spec)
        if err != nil {
            return nil, fmt.Errorf("new map %s: %w", mapName, err)
        }
        if err := os.MkdirAll(filepath.Dir(pinPath), syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
            return nil, fmt.Errorf("mkdir %s: %w", filepath.Dir(pinPath), err)
        }
        if err := m.Pin(pinPath); err != nil {
            return nil, fmt.Errorf("pin empty map %s: %w", pinPath, err)
        }
        return m, nil
    }

    tmpPinPath := pinPath + ".tmp"
    m, err := ebpf.NewMap(spec)
    if err != nil {
        return nil, fmt.Errorf("new map %s: %w", mapName, err)
    }
    if err := os.MkdirAll(filepath.Dir(tmpPinPath), 0755); err != nil && !os.IsExist(err) {
        m.Close()
        return nil, fmt.Errorf("mkdir %s: %w", tmpPinPath, err)
    }
    if err := m.Pin(tmpPinPath); err != nil {
        m.Close()
        return nil, fmt.Errorf("pin tmp map %s: %w", tmpPinPath, err)
    }
    if err := oldMap.Unpin(); err != nil && !os.IsNotExist(err) {
        log.Warnf("failed to unpin old map %s: %v (continuing)", pinPath, err)
    }
    if err := oldMap.Close(); err != nil {
        log.Warnf("failed to close old map FD: %v (continuing)", err)
    }
    if err := os.Remove(pinPath); err != nil && !os.IsNotExist(err) {
        m.Close()
        return nil, fmt.Errorf("remove old pin %s failed: %w", pinPath, err)
    }
    if err := os.Rename(tmpPinPath, pinPath); err != nil {
        m.Close()
        return nil, fmt.Errorf("rename tmp %s to %s failed: %w", tmpPinPath, pinPath, err)
    }
    return m, nil
}

func unionKeys(maps ...interface{}) ([]string, error) {
    set := make(map[string]struct{})

    for _, mp := range maps {
        if mp == nil {
            continue
        }
        rv := reflect.ValueOf(mp)
        if rv.Kind() != reflect.Map {
            return nil, fmt.Errorf("unionKeysAny: expected map, got %s", rv.Kind())
        }
        keyType := rv.Type().Key()
        if keyType.Kind() != reflect.String {
            return nil, fmt.Errorf("unionKeysAny: expected map key type string, got %s", keyType.Kind())
        }
        for _, k := range rv.MapKeys() {
            set[k.String()] = struct{}{}
        }
    }

    keys := make([]string, 0, len(set))
    for k := range set {
        keys = append(keys, k)
    }
    return keys, nil
}

func buildStructInfoRecursive(t btf.Type, registry map[string]StructInfo, visited map[btf.Type]bool) StructInfo {
	if t == nil {
		return StructInfo{}
	}

	st, ok := t.(*btf.Struct)
	if !ok {
		return StructInfo{Name: t.TypeName()}
	}

	if existing, ok := registry[st.Name]; ok {
		return existing
	}

	if visited[t] {
		return StructInfo{Name: st.Name}
	}

	visited[t] = true
	si := StructInfo{
		Name:    st.Name,
		Members: make([]MemberInfo, 0, len(st.Members)),
	}

	for _, m := range st.Members {
		offBytes := uint32(m.Offset)
		sizeBytes := uint32(m.BitfieldSize)
        log.Info("sizeBytes", sizeBytes)
		mi := MemberInfo{
			Name:     m.Name,
			TypeName: m.Type.TypeName(),
			Offset:   offBytes,
			BitfieldSize:     sizeBytes,
			Nested:   nil,
		}

		if nested, ok := m.Type.(*btf.Struct); ok {
			nestedInfo := buildStructInfoRecursive(nested, registry, visited)
			mi.Nested = &nestedInfo
			registry[nestedInfo.Name] = nestedInfo
		}

		si.Members = append(si.Members, mi)
	}
	registry[si.Name] = si
	return si
}

func SnapshotSpecsByPkg(specsByPkg map[string]map[string]*ebpf.MapSpec) error {
    wrapper := make(map[string]map[string]PersistedMapSpec, len(specsByPkg))
	registry := make(map[string]StructInfo)
	visited := make(map[btf.Type]bool)

	for pkg, maps := range specsByPkg {
		wrapper[pkg] = make(map[string]PersistedMapSpec, len(maps))
		for name, ms := range maps {
			if ms == nil {
				continue
			}

			var keyInfo StructInfo
			if ms.Key != nil {
				keyInfo = buildStructInfoRecursive(ms.Key, registry, visited)
			} else {
				keyInfo = StructInfo{Name: ""}
			}

			var valueInfo StructInfo
			if ms.Value != nil {
				valueInfo = buildStructInfoRecursive(ms.Value, registry, visited)
			} else {
				valueInfo = StructInfo{Name: ""}
			}

			pms := PersistedMapSpec{
				Name:       ms.Name,
				Type:       ms.Type.String(),
				KeySize:    ms.KeySize,
				ValueSize:  ms.ValueSize,
				MaxEntries: ms.MaxEntries,
				Flags:      ms.Flags,
				KeyInfo:    keyInfo,
				ValueInfo:  valueInfo,
			}
			wrapper[pkg][name] = pms
		}
	}

	snapshot := PersistedSnapshot{
		Maps:    wrapper,
	}

    if err := os.MkdirAll(MapSpecDir, 0755); err != nil {
        return fmt.Errorf("mkdir specDir: %w", err)
    }
    data, err := json.MarshalIndent(snapshot, "", "  ")
    if err != nil {
        return fmt.Errorf("marshal snapshot: %w", err)
    }
    tmp := filepath.Join(MapSpecDir, MapSpecFilename +".tmp")
    target := filepath.Join(MapSpecDir, MapSpecFilename)
    if err := os.WriteFile(tmp, data, 0644); err != nil {
        return fmt.Errorf("write tmp snapshot: %w", err)
    }
    if err := os.Rename(tmp, target); err != nil {
        return fmt.Errorf("rename wrapper: %w", err)
    }
    return nil
}

func LoadPersistedSnapshot() (*PersistedSnapshot, error) {
	path := filepath.Join(MapSpecDir, MapSpecFilename)
	buf, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read snapshot file: %w", err)
	}
	var snap PersistedSnapshot
	if err := json.Unmarshal(buf, &snap); err != nil {
		return nil, fmt.Errorf("unmarshal snapshot: %w", err)
	}
	return &snap, nil
}
