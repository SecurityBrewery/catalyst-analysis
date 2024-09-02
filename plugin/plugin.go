package plugin

import (
	"context"
)

// Plugin is an interface that defines methods for enriching data.
// Implementations of this interface should provide a Type method to identify the enricher
// and an Enrich method to enrich a given string based on the context.
type Plugin interface {
	Info() Info
}

type Info struct {
	Name          string
	ResourceTypes []ResourceType
}

type Connector interface {
	Plugin

	// Connect tests the connection to the plugin.
	Connect(ctx context.Context) error
}

type ResourceType interface {
	Info() ResourceTypeInfo

	Resource(ctx context.Context, id string) (*Resource, error)
}

type ResourceTypeInfo struct {
	ID                 string
	Name               string
	Attributes         []string
	EnrichmentPatterns []string
}

type Enricher interface {
	ResourceType

	// Enrich returns an Enrichment based on the context and the given string.
	// If no enrichment is possible, it returns nil.
	Enrich(ctx context.Context, value string) (*Resource, error)
}

type Suggestor interface {
	ResourceType

	// Suggest returns a list of Enrichments based on the context and the given string.
	// If no suggestions are possible, it returns nil.
	Suggest(ctx context.Context, value string) []*Resource
}

type Resource struct {
	Type        string
	ID          string
	Name        string
	Icon        string
	Description string
	URL         string
	Attributes  []Attribute
}

type Attribute struct {
	ID    string
	Name  string
	Icon  string
	Value string
}
