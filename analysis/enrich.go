package analysis

import (
	"context"
	"errors"

	"github.com/SecurityBrewery/catalyst-analysis/plugin"
)

type Enrichment struct {
	ServiceID string
	Resource  *plugin.Resource
}

func (s *Engine) Enrich(ctx context.Context, value string, limit int) ([]*Enrichment, error) {
	var enrichments []*Enrichment

	for _, service := range s.services {
		for _, resourceType := range service.Plugin.Info().ResourceTypes {
			if enricher, ok := resourceType.(plugin.Enricher); ok {
				enrichment, err := enricher.Enrich(ctx, value)
				if err != nil {
					continue
				}

				if limit != 0 && len(enrichments) >= limit {
					break
				}

				enrichments = append(enrichments, &Enrichment{
					ServiceID: service.ID,
					Resource:  enrichment,
				})
			}
		}
	}

	return enrichments, nil
}

func (s *Engine) EnrichResource(ctx context.Context, serviceID, resourceTypeID, value string) (*Enrichment, error) {
	resourceType, err := s.resourceType(serviceID, resourceTypeID)
	if err != nil {
		return nil, err
	}

	if enricher, ok := resourceType.(plugin.Enricher); ok {
		resource, err := enricher.Enrich(ctx, value)
		if err != nil {
			return nil, err
		}

		return &Enrichment{
			ServiceID: serviceID,
			Resource:  resource,
		}, nil
	}

	return nil, errors.New("resource type does not support enrichment")
}
