package restart

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStartType(t *testing.T) {
	SetStartType(Restart)
	assert.Equal(t, Restart, GetStartType())

	SetStartType(Update)
	assert.Equal(t, Update, GetStartType())

	SetStartType(Normal)
	assert.Equal(t, Normal, GetStartType())
}

func TestExitType(t *testing.T) {
	SetExitType(Restart)
	assert.Equal(t, Restart, GetExitType())

	SetExitType(Update)
	assert.Equal(t, Update, GetExitType())

	SetExitType(Normal)
	assert.Equal(t, Normal, GetExitType())
}

func TestInferNextStartType(t *testing.T) {
	// Since we don't have a mocked kube client or a real cluster running,
	// kube.CreateKubeClient will return an error and the function will fallback to Normal start.
	startType := InferNextStartType()
	assert.Equal(t, Normal, startType)
}
