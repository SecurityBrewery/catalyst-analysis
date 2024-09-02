package plugintest

import (
	"context"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SecurityBrewery/catalyst-analysis/generated/icons"
	"github.com/SecurityBrewery/catalyst-analysis/plugin"
)

type ResourceTypeTest struct {
	ResourceType plugin.ResourceType

	// patterns
	MatchingExamples    []string
	NonMatchingExamples []string

	// enrichments
	Enrichments map[string]*plugin.Resource

	// suggestions
	Suggestions map[string][]*plugin.Resource

	IgnoreAttributeValues []string
}

func TestResourceType(t *testing.T, pt ResourceTypeTest) {
	t.Helper()

	ctx := context.Background()

	// Test patterns are valid regex
	assert.Regexp(t, "^[A-Za-z0-9-]+$", pt.ResourceType.Info().Name)

	for _, pattern := range pt.ResourceType.Info().EnrichmentPatterns {
		requireIsRegex(t, pattern)
		requireIsJSRegex(t, pattern)
	}

	// Test examples match patterns
	for _, example := range pt.MatchingExamples {
		assertExampleResourceType(t, pt.ResourceType, example, true)
	}

	for _, example := range pt.NonMatchingExamples {
		assertExampleResourceType(t, pt.ResourceType, example, false)
	}

	// Test plugin enrichments
	for trigger, enrichment := range pt.Enrichments {
		if enricher, ok := pt.ResourceType.(plugin.Enricher); ok {
			got, err := enricher.Enrich(ctx, trigger)
			require.NoError(t, err)

			assert.Contains(t, icons.Icons, got.Icon)

			var attributeIDs []string
			for _, attribute := range got.Attributes {
				attributeIDs = append(attributeIDs, attribute.ID)

				assert.Contains(t, icons.Icons, attribute.Icon)
			}

			assert.ElementsMatch(t, pt.ResourceType.Info().Attributes, attributeIDs)

			for _, ignored := range pt.IgnoreAttributeValues {
				for i, attribute := range got.Attributes {
					if attribute.Name == ignored {
						got.Attributes[i].Value = ""
					}
				}
			}

			assert.Equal(t, enrichment, got)
		} else {
			assert.Failf(t, "ResourceType is not an enricher", "ResourceType %q is not an enricher", pt.ResourceType.Info().ID)
		}
	}

	// Test plugin suggestions
	for trigger, wantSuggestions := range pt.Suggestions {
		if suggestor, ok := pt.ResourceType.(plugin.Suggestor); ok {
			gotSuggestions := suggestor.Suggest(ctx, trigger)

			require.NotNil(t, gotSuggestions)
			require.NotEmpty(t, gotSuggestions)

			for _, ignored := range pt.IgnoreAttributeValues {
				for i, gotSuggestion := range gotSuggestions {
					for j, attribute := range gotSuggestion.Attributes {
						if attribute.Name == ignored {
							gotSuggestions[i].Attributes[j].Value = ""
						}
					}
				}
			}

			assert.Equal(t, wantSuggestions, gotSuggestions)
		} else {
			assert.Failf(t, "ResourceType is not a suggestor", "ResourceType %q is not a suggestor", pt.ResourceType.Info().ID)
		}
	}
}

func assertExampleResourceType(t *testing.T, resourceType plugin.ResourceType, example string, want bool) {
	t.Helper()

	matched := false

	for _, pattern := range resourceType.Info().EnrichmentPatterns {
		goMatched := regexp.MustCompile(pattern).MatchString(example)
		jsMatched := jsRegexMatches(t, pattern, example)
		assert.Equal(t, goMatched, jsMatched, "Go and JS regex should match the same examples, pattern: %q, example: %q, goMatched: %t, jsMatched: %t", pattern, example, goMatched, jsMatched)

		if goMatched {
			matched = true
		}
	}

	if want {
		assert.True(t, matched, "Example should match, example: %q", example)
	} else {
		assert.False(t, matched, "Example should not match, example: %q", example)
	}
}
