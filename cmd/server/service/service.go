package service

import (
	"context"

	"github.com/SecurityBrewery/catalyst-analysis/analysis"
	api2 "github.com/SecurityBrewery/catalyst-analysis/generated/api"
)

var _ api2.Handler = &Service{}

type Service struct {
	analysis *analysis.Engine
}

func New(analysis *analysis.Engine) *Service {
	return &Service{
		analysis: analysis,
	}
}

func (s *Service) ListServices(_ context.Context) (*api2.ServiceListResponse, error) {
	return &api2.ServiceListResponse{Services: mapSlice(s.analysis.Services(), apiService)}, nil
}

func (s *Service) GetResource(ctx context.Context, params api2.GetResourceParams) (*api2.Resource, error) {
	resource, err := s.analysis.Resource(ctx, params.ServiceID, params.ResourceTypeID, params.ResourceID)
	if err != nil {
		return nil, err
	}

	return pointer(apiResource(params.ServiceID, resource)), nil
}

func (s *Service) GetAttribute(ctx context.Context, params api2.GetAttributeParams) (*api2.Attribute, error) {
	attribute, err := s.analysis.Attribute(ctx, params.ServiceID, params.ResourceTypeID, params.ResourceID, params.AttributeID)
	if err != nil {
		return nil, err
	}

	return pointer(apiAttribute(*attribute)), nil
}

func (s *Service) Enrich(ctx context.Context, params api2.EnrichParams) (*api2.ResourceListResponse, error) {
	enrichments, err := s.analysis.Enrich(ctx, params.Value, params.Limit.Value)
	if err != nil {
		return nil, err
	}

	return &api2.ResourceListResponse{Resources: mapSlice(enrichments, enrichmentAPIResource)}, nil
}

func (s *Service) EnrichResource(ctx context.Context, params api2.EnrichResourceParams) (*api2.Resource, error) {
	enrichment, err := s.analysis.EnrichResource(ctx, params.ServiceID, params.ResourceTypeID, params.Value)
	if err != nil {
		return nil, err
	}

	return pointer(apiResource(enrichment.ServiceID, enrichment.Resource)), nil
}

func (s *Service) Suggest(ctx context.Context, params api2.SuggestParams) (*api2.ResourceListResponse, error) {
	return &api2.ResourceListResponse{Resources: mapSlice(s.analysis.Suggest(ctx, params.Partial), enrichmentAPIResource)}, nil
}
