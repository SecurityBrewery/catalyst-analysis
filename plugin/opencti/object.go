package opencti

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/SecurityBrewery/catalyst-analysis/plugin"
)

var _ plugin.Enricher = &Object{}

type Object struct {
	g *OpenCTI
}

func (o *Object) Info() plugin.ResourceTypeInfo {
	return plugin.ResourceTypeInfo{
		ID:         "object",
		Name:       "Object",
		Attributes: []string{"type", "created", "updated", "creator"},
		EnrichmentPatterns: []string{
			o.g.url + `\/dashboard\/observations\/observables\/[a-f0-9-]+`,
		},
	}
}

func (o *Object) Resource(ctx context.Context, id string) (*plugin.Resource, error) {
	return o.resource(ctx, id)
}

func (o *Object) Enrich(ctx context.Context, value string) (*plugin.Resource, error) {
	openCTIEventRegex, err := regexp.Compile(`^` + o.g.url + `\/dashboard\/observations\/observables\/([a-f0-9-]+)`)
	if err != nil {
		return nil, err
	}

	if !openCTIEventRegex.MatchString(value) {
		return nil, errors.New("not a opencti event")
	}

	matches := openCTIEventRegex.FindStringSubmatch(value)

	if len(matches) != 2 {
		return nil, errors.New("invalid opencti event url")
	}

	return o.resource(ctx, matches[1])
}

const query = `query StixCyberObservable($id: String!) { stixCyberObservable(id: $id) { id standard_id entity_type observable_value creators { name } created_at updated_at } }`

type openCTIObservablesResponse struct {
	Data struct {
		StixCyberObservable `json:"stixCyberObservable"`
		ConnectorsForImport []struct {
			ID             string        `json:"id"`
			Name           string        `json:"name"`
			Active         bool          `json:"active"`
			ConnectorScope []string      `json:"connector_scope"`
			UpdatedAt      interface{}   `json:"updated_at"`
			Configurations []interface{} `json:"configurations"`
		} `json:"connectorsForImport"`
		ConnectorsForExport []interface{} `json:"connectorsForExport"`
	} `json:"data"`
}

func (o *Object) resource(ctx context.Context, observable string) (*plugin.Resource, error) {
	body, err := json.Marshal(map[string]any{
		"query":     query,
		"variables": map[string]string{"id": observable},
	})
	if err != nil {
		return nil, err
	}

	resp, err := o.g.request(ctx, http.MethodPost, o.g.url+"/graphql", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var openCTIEvent openCTIObservablesResponse
	if err := json.NewDecoder(resp.Body).Decode(&openCTIEvent); err != nil {
		return nil, err
	}

	object := openCTIEvent.Data.StixCyberObservable

	attributes := []plugin.Attribute{
		{
			ID:    "type",
			Icon:  "Info",
			Name:  "Type",
			Value: object.EntityType,
		},
		{
			ID:    "created",
			Name:  "Created At",
			Icon:  "Calendar",
			Value: object.CreatedAt.Format(time.DateTime),
		},
		{
			ID:    "updated",
			Name:  "Updated At",
			Icon:  "Calendar",
			Value: object.UpdatedAt.Format(time.DateTime),
		},
	}

	if len(object.Creators) > 0 {
		attributes = append(attributes, plugin.Attribute{
			ID:    "creator",
			Name:  "Creator",
			Icon:  "User",
			Value: object.Creators[0].Name,
		})
	}

	return &plugin.Resource{
		Type:       o.Info().ID,
		ID:         object.ID,
		Name:       object.ObservableValue,
		Icon:       "Brain",
		URL:        o.g.url + `/dashboard/observations/observables/` + object.ID,
		Attributes: attributes,
	}, nil
}
