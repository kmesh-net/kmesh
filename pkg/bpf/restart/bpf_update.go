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

package restart

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/version"
)

type StructFieldChanges struct {
	FieldRemoved        bool // A field was present in the old struct (A) but is now missing in the new struct (B).
	FieldAdded          bool // A new field was added to the struct.
	FieldTypeChanged    bool // A field with the same name has a different type.
	FieldOffsetChanged  bool // The memory offset of a field with the same name has changed.
	NestedLayoutChanged bool // The layout of a nested struct has changed (e.g., its fields were added, removed, or changed).
}

type PersistedMemberLayout struct {
	Name         string                 `json:"name"`
	TypeName     string                 `json:"typeName"`
	Offset       uint32                 `json:"offset"`
	BitfieldSize uint32                 `json:"bitfieldsize"` // only have value when the type is bitfield
	Nested       *PersistedStructLayout `json:"nested,omitempty"`
}

type PersistedStructLayout struct {
	Name    string                  `json:"name"`
	Members []PersistedMemberLayout `json:"members"`
}

type PersistedMapSpec struct {
	Name            string                `json:"name"`
	Type            string                `json:"type"` // MapType.String()
	KeySize         uint32                `json:"keySize"`
	ValueSize       uint32                `json:"valueSize"`
	MaxEntries      uint32                `json:"maxEntries"`
	Flags           uint32                `json:"flags"`
	KeyStructInfo   PersistedStructLayout `json:"keyInfo"` // get from btf.Struct
	ValueStructInfo PersistedStructLayout `json:"valueInfo"`
}

type PersistedSnapshot struct {
	Maps map[string]map[string]PersistedMapSpec `json:"maps"`
}

const (
	MapSpecDir      = "/mnt/kmesh_mapspecs"
	MapSpecFilename = "mapspecs_by_prog.json"
)

// UpdateMapHandler handles the “Update” case in NewVersionMap.
// It will migrate any BPF maps whose on‑disk pin already exists but whose
// compiled MapSpec has changed
func UpdateMapHandler(versionMap *ebpf.Map, kmBpfPath string, config *options.BpfConfig) *ebpf.Map {
	persistedSpecs, err := LoadPersistedSnapshot()
	if err != nil {
		log.Errorf("load persisted map spec failed")
		return nil
	}
	if persistedSpecs == nil {
		log.Errorf("persisted map spec is nil")
		return nil
	}
	specsbyProg, err := LoadCompileTimeSpecs(config)
	if err != nil {
		log.Errorf("load oldSpecsbyProg failed")
		return nil
	}
	progNames := unionKeys(specsbyProg, persistedSpecs.Maps)
	for _, progName := range progNames {
		newMaps := specsbyProg[progName]
		oldMaps := persistedSpecs.Maps[progName]
		if newMaps == nil || oldMaps == nil {
			continue
		}

		mapNames := unionKeys(newMaps, oldMaps)
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
			case hasNew && !hasOld:
				if _, err := createEmptyMap(newSpec, pinPath, mapName, nil); err != nil {
					log.Errorf("create new map %s/%s failed: %v", progName, mapName, err)
				}
			case hasNew && hasOld:
				if _, err := migrateMap(&oldSpec, newSpec, progName, mapName, pinPath); err != nil {
					log.Errorf("migrate map %s/%s failed: %v", progName, mapName, err)
				}
			}
		}
	}

	log.Infof("kmesh start with Update")
	updateVersionInfo(versionMap)
	if err := SnapshotSpecsbyProg(specsbyProg); err != nil {
		return versionMap
	}
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
	progName, mapName, pinPath string,
) (*ebpf.Map, error) {
	return migrateMap(oldMapSpec, newMapSpec, progName, mapName, pinPath)
}

func migrateMap(
	oldMapSpec *PersistedMapSpec,
	newMapSpec *ebpf.MapSpec,
	progName, mapName, pinPath string,
) (*ebpf.Map, error) {
	if oldMapSpec == nil {
		return createEmptyMap(newMapSpec, pinPath, mapName, nil)
	}
	if oldMapSpec.Type != newMapSpec.Type.String() ||
		oldMapSpec.KeySize != newMapSpec.KeySize ||
		oldMapSpec.ValueSize != newMapSpec.ValueSize ||
		oldMapSpec.MaxEntries != newMapSpec.MaxEntries {
		return createEmptyMapWithPinnedMap(newMapSpec, pinPath, mapName)
	}

	if needsRecreate(oldMapSpec.KeyStructInfo, newMapSpec.Key) {
		return createEmptyMapWithPinnedMap(newMapSpec, pinPath, mapName)
	}

	if needsRecreate(oldMapSpec.ValueStructInfo, newMapSpec.Value) {
		return createEmptyMapWithPinnedMap(newMapSpec, pinPath, mapName)
	}
	return nil, nil
}

func needsRecreate(oldStruct PersistedStructLayout, newType btf.Type) bool {
	if newType == nil {
		if oldStruct.Name != "" || len(oldStruct.Members) != 0 {
			return true
		}
		return false
	}

	if newStruct, ok := newType.(*btf.Struct); ok {
		diff := diffStructInfoAgainstBTF(oldStruct, newStruct, make(map[string]bool))
		if diff.FieldAdded || diff.FieldRemoved || diff.FieldTypeChanged ||
			diff.FieldOffsetChanged || diff.NestedLayoutChanged {
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
	a PersistedStructLayout,
	b *btf.Struct,
	visited map[string]bool,
) StructFieldChanges {
	return diffStructInfoAgainstBTF(a, b, visited)
}

func diffStructInfoAgainstBTF(
	a PersistedStructLayout,
	b *btf.Struct,
	visited map[string]bool,
) StructFieldChanges {
	diff := StructFieldChanges{}

	oldMap := make(map[string]PersistedMemberLayout, len(a.Members))
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
			diff.FieldAdded = true
			break
		}
	}

	// check removed / type / offset / nested changes
	for name, map_old := range oldMap {
		map_new, exists := newMap[name]
		if !exists {
			diff.FieldRemoved = true
			break
		}

		if map_old.Offset != uint32(map_new.Offset) || map_old.BitfieldSize != uint32(map_new.BitfieldSize) {
			diff.FieldOffsetChanged = true
			break
		}

		if map_old.TypeName == map_new.Type.TypeName() {
			if mbStruct, ok := map_new.Type.(*btf.Struct); ok {
				if map_old.Nested != nil {
					if map_old.Nested.Name != "" {
						if !visited[map_old.Nested.Name] {
							visited[map_old.Nested.Name] = true
							nestedDiff := diffStructInfoAgainstBTF(*map_old.Nested, mbStruct, visited)
							if nestedDiff.FieldAdded || nestedDiff.FieldRemoved || nestedDiff.FieldTypeChanged ||
								nestedDiff.FieldOffsetChanged || nestedDiff.NestedLayoutChanged {
								diff.NestedLayoutChanged = true
								break
							}
						}
						continue
					}
				}
				diff.NestedLayoutChanged = true
				break
			} else { // if new side is not struct
				log.Info(map_old.Nested != nil)
				if map_old.TypeName != map_new.Type.TypeName() || map_old.Nested != nil {
					diff.FieldTypeChanged = true
					break
				}
			}
		} else {
			diff.FieldTypeChanged = true
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

// This function correctly handles two maps with different value types.
func unionKeys[V1, V2 any](map1 map[string]V1, map2 map[string]V2) []string {
	// Pre-allocate the set with a reasonable capacity.
	set := make(map[string]struct{}, len(map1))

	for k := range map1 {
		set[k] = struct{}{}
	}

	for k := range map2 {
		set[k] = struct{}{}
	}

	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	return keys
}

func buildStructInfoRecursive(t btf.Type, registry map[string]PersistedStructLayout, visited map[btf.Type]bool) PersistedStructLayout {
	if t == nil {
		return PersistedStructLayout{}
	}

	st, ok := t.(*btf.Struct)
	if !ok {
		return PersistedStructLayout{Name: t.TypeName()}
	}

	if existing, ok := registry[st.Name]; ok {
		return existing
	}

	if visited[t] {
		return PersistedStructLayout{Name: st.Name}
	}

	visited[t] = true
	si := PersistedStructLayout{
		Name:    st.Name,
		Members: make([]PersistedMemberLayout, 0, len(st.Members)),
	}

	for _, m := range st.Members {
		offBytes := uint32(m.Offset)
		sizeBytes := uint32(m.BitfieldSize)
		log.Info("sizeBytes", sizeBytes)
		mi := PersistedMemberLayout{
			Name:         m.Name,
			TypeName:     m.Type.TypeName(),
			Offset:       offBytes,
			BitfieldSize: sizeBytes,
			Nested:       nil,
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

// SnapshotSpecsbyProg takes a nested map of BPF map specifications and persists them to a file.
// The structure of the input map `specsbyProg` is:
//
//		map[programName] -> map[mapName] -> *ebpf.MapSpec
//
//	  - The first key (programName) is the name of the BPF program collection,
//	    e.g., "KmeshCgroupSock".
//	  - The second key (mapName) is the name of a specific BPF map within that program,
//	    e.g., "kmesh_endpoints".
func SnapshotSpecsbyProg(specsbyProg map[string]map[string]*ebpf.MapSpec) error {
	wrapper := make(map[string]map[string]PersistedMapSpec, len(specsbyProg))
	registry := make(map[string]PersistedStructLayout)
	visited := make(map[btf.Type]bool)

	for prog, maps := range specsbyProg {
		wrapper[prog] = make(map[string]PersistedMapSpec, len(maps))
		for name, ms := range maps {
			if ms == nil {
				continue
			}

			var keyInfo PersistedStructLayout
			if ms.Key != nil {
				keyInfo = buildStructInfoRecursive(ms.Key, registry, visited)
			} else {
				keyInfo = PersistedStructLayout{Name: ""}
			}

			var valueInfo PersistedStructLayout
			if ms.Value != nil {
				valueInfo = buildStructInfoRecursive(ms.Value, registry, visited)
			} else {
				valueInfo = PersistedStructLayout{Name: ""}
			}

			pms := PersistedMapSpec{
				Name:            ms.Name,
				Type:            ms.Type.String(),
				KeySize:         ms.KeySize,
				ValueSize:       ms.ValueSize,
				MaxEntries:      ms.MaxEntries,
				Flags:           ms.Flags,
				KeyStructInfo:   keyInfo,
				ValueStructInfo: valueInfo,
			}
			wrapper[prog][name] = pms
		}
	}

	snapshot := PersistedSnapshot{
		Maps: wrapper,
	}

	if err := os.MkdirAll(MapSpecDir, 0755); err != nil {
		return fmt.Errorf("mkdir specDir: %w", err)
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	tmp := filepath.Join(MapSpecDir, MapSpecFilename+".tmp")
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
