package plugintest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SecurityBrewery/catalyst-analysis/plugin"
)

func TestPlugin(t *testing.T, p plugin.Plugin) {
	t.Helper()

	// Test plugin name
	assert.NotEmpty(t, p.Info().Name)

	// Test patterns exist
	require.NotEmpty(t, p.Info().ResourceTypes)
}
