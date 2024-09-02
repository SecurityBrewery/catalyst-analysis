// Code generated by ogen, DO NOT EDIT.

package api

import (
	"context"
)

// Handler handles operations described by OpenAPI v3 specification.
type Handler interface {
	// Enrich implements enrich operation.
	//
	// Enrich a value with data from various services.
	//
	// GET /enrich
	Enrich(ctx context.Context, params EnrichParams) (*ResourceListResponse, error)
	// EnrichResource implements enrichResource operation.
	//
	// Enrich a value with data from various services.
	//
	// GET /enrich/{service_id}/{resource_type_id}
	EnrichResource(ctx context.Context, params EnrichResourceParams) (*Resource, error)
	// GetAttribute implements getAttribute operation.
	//
	// Retrieve a specific attribute from a resource.
	//
	// GET /services/{service_id}/{resource_type_id}/{resource_id}/{attribute_id}
	GetAttribute(ctx context.Context, params GetAttributeParams) (*Attribute, error)
	// GetResource implements getResource operation.
	//
	// Retrieve a specific resource from a service.
	//
	// GET /services/{service_id}/{resource_type_id}/{resource_id}
	GetResource(ctx context.Context, params GetResourceParams) (*Resource, error)
	// ListServices implements listServices operation.
	//
	// Retrieve the list of available services.
	//
	// GET /services
	ListServices(ctx context.Context) (*ServiceListResponse, error)
	// Suggest implements suggest operation.
	//
	// Suggest resources based on a partial value.
	//
	// GET /suggest
	Suggest(ctx context.Context, params SuggestParams) (*ResourceListResponse, error)
}

// Server implements http server based on OpenAPI v3 specification and
// calls Handler to handle requests.
type Server struct {
	h Handler
	baseServer
}

// NewServer creates new Server.
func NewServer(h Handler, opts ...ServerOption) (*Server, error) {
	s, err := newServerConfig(opts...).baseServer()
	if err != nil {
		return nil, err
	}
	return &Server{
		h:          h,
		baseServer: s,
	}, nil
}