package attack

import (
	"context"

	"github.com/SecurityBrewery/goattack"

	"github.com/SecurityBrewery/catalyst-analysis/plugin"
)

var (
	Technique = &Object{id: "technique", name: "Technique", objectType: "attack-pattern"} //nolint: gochecknoglobals
	Tactic    = &Object{id: "tactic", name: "Tactic", objectType: "x-mitre-tactic"}       //nolint: gochecknoglobals
)

var _ plugin.Enricher = &Object{}

type Object struct {
	id         string
	name       string
	objectType string
}

func (a *Object) Info() plugin.ResourceTypeInfo {
	var patterns []string

	for _, obj := range goattack.Objects {
		if obj.Type == a.objectType {
			patterns = append(patterns, obj.ID)
		}
	}

	return plugin.ResourceTypeInfo{
		ID:                 a.id,
		Name:               a.name,
		Attributes:         []string{},
		EnrichmentPatterns: patterns,
	}
}

func (a *Object) Resource(_ context.Context, id string) (*plugin.Resource, error) {
	return resource(a.Info().ID, a.objectType, id)
}

func (a *Object) Enrich(_ context.Context, value string) (*plugin.Resource, error) {
	return resource(a.Info().ID, a.objectType, value)
}

func (a *Object) Suggest(_ context.Context, value string) []*plugin.Resource {
	return suggest(a.Info().ID, a.objectType, value)
}
