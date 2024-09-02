package service

import (
	"github.com/SecurityBrewery/catalyst-analysis/analysis"
	"github.com/SecurityBrewery/catalyst-analysis/generated/api"
	"github.com/SecurityBrewery/catalyst-analysis/plugin"
)

func enrichmentAPIResource(enrichment *analysis.Enrichment) api.Resource {
	return apiResource(enrichment.ServiceID, enrichment.Resource)
}

func apiResource(serviceID string, resource *plugin.Resource) api.Resource {
	return api.Resource{
		Service:     serviceID,
		Type:        resource.Type,
		ID:          resource.ID,
		Name:        resource.Name,
		Icon:        resource.Icon,
		Description: api.NewOptString(resource.Description),
		URL:         api.NewOptString(resource.URL),
		Attributes:  mapSlice(resource.Attributes, apiAttribute),
	}
}

func apiAttribute(attribute plugin.Attribute) api.Attribute {
	return api.Attribute{
		ID:    attribute.ID,
		Name:  attribute.Name,
		Icon:  attribute.Icon,
		Value: attribute.Value,
	}
}

func apiService(service *analysis.Service) api.Service {
	return api.Service{
		ID:            service.ID,
		Type:          service.Plugin.Info().Name,
		ResourceTypes: mapSlice(service.Plugin.Info().ResourceTypes, apiResourceType),
	}
}

func apiResourceType(resource plugin.ResourceType) api.ResourceType {
	return api.ResourceType{
		ID:                 resource.Info().ID,
		Name:               resource.Info().Name,
		EnrichmentPatterns: resource.Info().EnrichmentPatterns,
		Attributes:         resource.Info().Attributes,
	}
}
