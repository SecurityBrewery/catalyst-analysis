package misp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"

	"github.com/SecurityBrewery/catalyst-analysis/plugin"
)

var _ plugin.Enricher = &Event{}

type Event struct {
	g *MISP
}

func (e *Event) Info() plugin.ResourceTypeInfo {
	return plugin.ResourceTypeInfo{
		ID:         "event",
		Name:       "Event",
		Attributes: []string{},
		EnrichmentPatterns: []string{
			e.g.url + `\/events\/view\/\d+`,
		},
	}
}

func (e *Event) Resource(ctx context.Context, id string) (*plugin.Resource, error) {
	return e.event(ctx, id)
}

type EventResponse struct {
	Event struct {
		Info string `json:"info"`
		Tag  []Tag  `json:"Tag"`
	} `json:"Event"`
}

type Tag struct {
	Name string `json:"name"`
}

func (e *Event) Enrich(ctx context.Context, value string) (*plugin.Resource, error) {
	mispEventRegex := regexp.MustCompile(`^` + e.g.url + `\/events\/view\/(\d+)`)

	if !mispEventRegex.MatchString(value) {
		return nil, errors.New("not a misp event")
	}

	matches := mispEventRegex.FindStringSubmatch(value)

	if len(matches) != 2 {
		return nil, errors.New("invalid misp event url")
	}

	return e.event(ctx, matches[1])
}

func (e *Event) event(ctx context.Context, number string) (*plugin.Resource, error) {
	resp, err := e.g.request(ctx, http.MethodGet, e.g.url+"/events/view/"+number, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var mispEvent EventResponse
	if err := json.NewDecoder(resp.Body).Decode(&mispEvent); err != nil {
		return nil, err
	}

	return &plugin.Resource{
		Type:       e.Info().ID,
		ID:         number,
		Name:       mispEvent.Event.Info,
		Icon:       "Brain",
		URL:        e.g.url + "/events/view/" + number,
		Attributes: []plugin.Attribute{},
	}, nil
}
