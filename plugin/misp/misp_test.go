package misp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/SecurityBrewery/catalyst-analysis/config"
	"github.com/SecurityBrewery/catalyst-analysis/plugin/plugintest"
)

func TestMISP(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	plugin, err := New(ctx, config.NewMapProvider(&config.JSONConfig{
		Services: map[string]*config.JSONServiceConfig{
			"misp": {
				Plugin: "misp",
				Config: map[string]string{
					"url": "https://misp.internal",
				},
			},
		},
	}))
	require.NoError(t, err)

	plugintest.TestPlugin(t, plugin)

	plugintest.TestResourceType(t, plugintest.ResourceTypeTest{
		ResourceType:        &Event{g: plugin},
		MatchingExamples:    []string{"https://misp.internal/events/view/163447"},
		NonMatchingExamples: []string{"/events/view/163447"},
	})
}
