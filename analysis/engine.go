package analysis

import (
	"context"
	"errors"

	"github.com/SecurityBrewery/catalyst-analysis/plugin"
)

type Service struct {
	ID     string
	Plugin plugin.Plugin
}

type Engine struct {
	services []*Service
}

func NewEngine(services []*Service) *Engine {
	return &Engine{
		services: services,
	}
}

func (s *Engine) Services() []*Service {
	return s.services
}

func (s *Engine) Service(serviceID string) (*Service, error) {
	for _, service := range s.services {
		if service.ID == serviceID {
			return service, nil
		}
	}

	return nil, errors.New("service not found")
}

func (s *Engine) resourceType(serviceID, resourceType string) (plugin.ResourceType, error) {
	service, err := s.Service(serviceID)
	if err != nil {
		return nil, err
	}

	for _, resource := range service.Plugin.Info().ResourceTypes {
		if resource.Info().ID == resourceType {
			return resource, nil
		}
	}

	return nil, errors.New("resource type not found")
}

func (s *Engine) Resource(ctx context.Context, serviceID, resourceType, resourceID string) (*plugin.Resource, error) {
	r, err := s.resourceType(serviceID, resourceType)
	if err != nil {
		return nil, err
	}

	return r.Resource(ctx, resourceID)
}

func (s *Engine) Attribute(ctx context.Context, serviceID, resourceType, resourceID, attributeID string) (*plugin.Attribute, error) {
	r, err := s.Resource(ctx, serviceID, resourceType, resourceID)
	if err != nil {
		return nil, err
	}

	for _, attribute := range r.Attributes {
		if attribute.ID == attributeID {
			return &attribute, nil
		}
	}

	return nil, errors.New("attribute not found")
}
