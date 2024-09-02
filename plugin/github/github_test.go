package github

import (
	"testing"

	"github.com/SecurityBrewery/catalyst-analysis/config"
	"github.com/SecurityBrewery/catalyst-analysis/plugin/plugintest"
)

func TestGithub(t *testing.T) {
	t.Parallel()

	plugin := New(config.NewMapProvider(&config.JSONConfig{Services: map[string]*config.JSONServiceConfig{}}))

	plugintest.TestPlugin(t, plugin)

	plugintest.TestResourceType(t, plugintest.ResourceTypeTest{
		ResourceType:        &Issue{g: plugin},
		MatchingExamples:    []string{"https://github.com/SecurityBrewery/catalyst/issues/446"},
		NonMatchingExamples: []string{"SecurityBrewery/catalyst/issues/446"},
	})
}
