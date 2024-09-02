package analysis

import (
	"context"

	"github.com/SecurityBrewery/catalyst-analysis/plugin"
)

const maxSuggestionsPerResourceType = 3

func (s *Engine) Suggest(ctx context.Context, partial string) []*Enrichment {
	var apiSuggestions []*Enrichment

	for _, service := range s.services {
		for _, resource := range service.Plugin.Info().ResourceTypes {
			if suggestor, ok := resource.(plugin.Suggestor); ok {
				for i, suggestion := range suggestor.Suggest(ctx, partial) {
					if i > maxSuggestionsPerResourceType {
						break
					}

					apiSuggestions = append(apiSuggestions, &Enrichment{
						ServiceID: service.ID,
						Resource:  suggestion,
					})
				}
			}
		}
	}

	return apiSuggestions
}
