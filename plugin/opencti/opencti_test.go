package opencti

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/SecurityBrewery/catalyst-analysis/config"
	"github.com/SecurityBrewery/catalyst-analysis/plugin/plugintest"
)

func TestOpenCTI(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	plugin, err := New(ctx, config.NewMapProvider(&config.JSONConfig{
		Services: map[string]*config.JSONServiceConfig{
			"opencti": {
				Plugin: "opencti",
				Config: map[string]string{
					"url": "https://opencti.internal",
				},
			},
		},
	}))
	require.NoError(t, err)

	plugintest.TestPlugin(t, plugin)

	plugintest.TestResourceType(t, plugintest.ResourceTypeTest{
		ResourceType:        &Object{g: plugin},
		MatchingExamples:    []string{"https://opencti.internal/dashboard/observations/observables/6244031a-0f12-45f8-b802-51986b3d41a4"},
		NonMatchingExamples: []string{"/dashboard/observations/observables/6244031a-0f12-45f8-b802-51986b3d41a4"},
	})
}
