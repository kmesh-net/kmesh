package restart

import (
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
)

func TestUnionKeys(t *testing.T) {
	map1 := map[string]int{"a": 1, "b": 2}
	map2 := map[string]string{"b": "hello", "c": "world"}

	keys := unionKeys(map1, map2)
	assert.ElementsMatch(t, []string{"a", "b", "c"}, keys)
}

func TestDiffStructInfoAgainstBTF(t *testing.T) {
	oldStruct := PersistedStructLayout{
		Name: "test_struct",
		Members: []PersistedMemberLayout{
			{Name: "field1", TypeName: "int", Offset: 0, BitfieldSize: 0},
			{Name: "field2", TypeName: "int", Offset: 32, BitfieldSize: 0},
		},
	}

	newBtfStruct := &btf.Struct{
		Name: "test_struct",
		Members: []btf.Member{
			{Name: "field1", Type: &btf.Int{Name: "int"}, Offset: 0},
			{Name: "field2", Type: &btf.Int{Name: "int"}, Offset: 32},
		},
	}

	diff := DiffStructInfoAgainstBTF(oldStruct, newBtfStruct, make(map[string]bool))
	assert.False(t, diff.FieldAdded)
	assert.False(t, diff.FieldRemoved)
	assert.False(t, diff.FieldTypeChanged)
	assert.False(t, diff.FieldOffsetChanged)
	assert.False(t, diff.NestedLayoutChanged)

	newBtfStructAdded := &btf.Struct{
		Name: "test_struct",
		Members: []btf.Member{
			{Name: "field1", Type: &btf.Int{Name: "int"}, Offset: 0},
			{Name: "field2", Type: &btf.Int{Name: "int"}, Offset: 32},
			{Name: "field3", Type: &btf.Int{Name: "int"}, Offset: 64},
		},
	}
	diffAdded := DiffStructInfoAgainstBTF(oldStruct, newBtfStructAdded, make(map[string]bool))
	assert.True(t, diffAdded.FieldAdded)

	newBtfStructRemoved := &btf.Struct{
		Name: "test_struct",
		Members: []btf.Member{
			{Name: "field1", Type: &btf.Int{Name: "int"}, Offset: 0},
		},
	}
	diffRemoved := DiffStructInfoAgainstBTF(oldStruct, newBtfStructRemoved, make(map[string]bool))
	assert.True(t, diffRemoved.FieldRemoved)

	newBtfStructOffset := &btf.Struct{
		Name: "test_struct",
		Members: []btf.Member{
			{Name: "field1", Type: &btf.Int{Name: "int"}, Offset: 0},
			{Name: "field2", Type: &btf.Int{Name: "int"}, Offset: 64}, // Offset changed
		},
	}
	diffOffset := DiffStructInfoAgainstBTF(oldStruct, newBtfStructOffset, make(map[string]bool))
	assert.True(t, diffOffset.FieldOffsetChanged)

	newBtfStructType := &btf.Struct{
		Name: "test_struct",
		Members: []btf.Member{
			{Name: "field1", Type: &btf.Int{Name: "int"}, Offset: 0},
			{Name: "field2", Type: &btf.Int{Name: "uint"}, Offset: 32}, // Type changed
		},
	}
	diffType := DiffStructInfoAgainstBTF(oldStruct, newBtfStructType, make(map[string]bool))
	assert.True(t, diffType.FieldTypeChanged)
}

func TestNeedsRecreate(t *testing.T) {
	oldStruct := PersistedStructLayout{
		Name: "test_struct",
		Members: []PersistedMemberLayout{
			{Name: "field1", TypeName: "int", Offset: 0, BitfieldSize: 0},
		},
	}

	newType := &btf.Struct{
		Name: "test_struct",
		Members: []btf.Member{
			{Name: "field1", Type: &btf.Int{Name: "int"}, Offset: 0},
		},
	}

	assert.False(t, needsRecreate(oldStruct, newType))

	newTypeDiff := &btf.Struct{
		Name: "test_struct",
		Members: []btf.Member{
			{Name: "field1", Type: &btf.Int{Name: "int"}, Offset: 0},
			{Name: "field2", Type: &btf.Int{Name: "int"}, Offset: 32}, // Field added
		},
	}
	assert.True(t, needsRecreate(oldStruct, newTypeDiff))
}
