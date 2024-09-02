package attack

import (
	"cmp"
	"errors"
	"slices"
	"strings"

	"github.com/SecurityBrewery/goattack"

	"github.com/SecurityBrewery/catalyst-analysis/plugin"
)

var _ plugin.Plugin = &Attack{}

type Attack struct{}

func New() *Attack {
	return &Attack{}
}

func (g *Attack) Info() plugin.Info {
	return plugin.Info{
		Name: "MITRE ATT&CK",
		ResourceTypes: []plugin.ResourceType{
			Technique,
			Tactic,
		},
	}
}

func toResource(resource string, obj *goattack.Object) *plugin.Resource {
	return &plugin.Resource{
		Type:        resource,
		ID:          obj.ID,
		Name:        obj.ID + " " + obj.FullName,
		Icon:        "Shield",
		Description: obj.Description,
		URL:         obj.URL,
		Attributes:  []plugin.Attribute{},
	}
}

func resource(resourceType, objectType, id string) (*plugin.Resource, error) {
	if obj, ok := goattack.Objects[id]; ok {
		if obj.Type != objectType {
			return nil, errors.New("invalid object type")
		}

		return toResource(resourceType, obj), nil
	}

	return nil, errors.New("unknown attack technique")
}

func suggest(resourceType, objType, value string) []*plugin.Resource {
	if len(value) < 3 {
		return nil
	}

	var (
		idResources    []*plugin.Resource
		titleResources []*plugin.Resource
	)

	value = strings.ToLower(value)

	for _, key := range sortedMapKeys(goattack.Objects) {
		object := goattack.Objects[key]

		if object.Type != objType {
			continue
		}

		switch {
		case strings.Contains(strings.ToLower(object.ID), value):
			idResources = append(idResources, toResource(resourceType, object))
		case strings.Contains(strings.ToLower(object.Name), value):
			titleResources = append(titleResources, toResource(resourceType, object))
		}

		if len(idResources) >= 5 {
			break
		}
	}

	idResources = append(idResources, titleResources...)

	if len(idResources) > 5 {
		idResources = idResources[:5]
	}

	return idResources
}

func sortedMapKeys[K cmp.Ordered, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	slices.Sort(keys)

	return keys
}
