// Code generated by ogen, DO NOT EDIT.

package api

import (
	"context"
	"net/http"
	"time"

	"github.com/go-faster/errors"
	ht "github.com/ogen-go/ogen/http"
	"github.com/ogen-go/ogen/middleware"
	"github.com/ogen-go/ogen/ogenerrors"
	"github.com/ogen-go/ogen/otelogen"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
	"go.opentelemetry.io/otel/trace"
)

// handleEnrichRequest handles enrich operation.
//
// Enrich a value with data from various services.
//
// GET /enrich
func (s *Server) handleEnrichRequest(args [0]string, argsEscaped bool, w http.ResponseWriter, r *http.Request) {
	otelAttrs := []attribute.KeyValue{
		otelogen.OperationID("enrich"),
		semconv.HTTPMethodKey.String("GET"),
		semconv.HTTPRouteKey.String("/enrich"),
	}

	// Start a span for this request.
	ctx, span := s.cfg.Tracer.Start(r.Context(), "Enrich",
		trace.WithAttributes(otelAttrs...),
		serverSpanKind,
	)
	defer span.End()

	// Add Labeler to context.
	labeler := &Labeler{attrs: otelAttrs}
	ctx = contextWithLabeler(ctx, labeler)

	// Run stopwatch.
	startTime := time.Now()
	defer func() {
		elapsedDuration := time.Since(startTime)
		attrOpt := metric.WithAttributeSet(labeler.AttributeSet())

		// Increment request counter.
		s.requests.Add(ctx, 1, attrOpt)

		// Use floating point division here for higher precision (instead of Millisecond method).
		s.duration.Record(ctx, float64(float64(elapsedDuration)/float64(time.Millisecond)), attrOpt)
	}()

	var (
		recordError = func(stage string, err error) {
			span.RecordError(err)
			span.SetStatus(codes.Error, stage)
			s.errors.Add(ctx, 1, metric.WithAttributeSet(labeler.AttributeSet()))
		}
		err          error
		opErrContext = ogenerrors.OperationContext{
			Name: "Enrich",
			ID:   "enrich",
		}
	)
	params, err := decodeEnrichParams(args, argsEscaped, r)
	if err != nil {
		err = &ogenerrors.DecodeParamsError{
			OperationContext: opErrContext,
			Err:              err,
		}
		defer recordError("DecodeParams", err)
		s.cfg.ErrorHandler(ctx, w, r, err)
		return
	}

	var response *ResourceListResponse
	if m := s.cfg.Middleware; m != nil {
		mreq := middleware.Request{
			Context:          ctx,
			OperationName:    "Enrich",
			OperationSummary: "Enrich a value with data from various services",
			OperationID:      "enrich",
			Body:             nil,
			Params: middleware.Parameters{
				{
					Name: "value",
					In:   "query",
				}: params.Value,
				{
					Name: "limit",
					In:   "query",
				}: params.Limit,
			},
			Raw: r,
		}

		type (
			Request  = struct{}
			Params   = EnrichParams
			Response = *ResourceListResponse
		)
		response, err = middleware.HookMiddleware[
			Request,
			Params,
			Response,
		](
			m,
			mreq,
			unpackEnrichParams,
			func(ctx context.Context, request Request, params Params) (response Response, err error) {
				response, err = s.h.Enrich(ctx, params)
				return response, err
			},
		)
	} else {
		response, err = s.h.Enrich(ctx, params)
	}
	if err != nil {
		defer recordError("Internal", err)
		s.cfg.ErrorHandler(ctx, w, r, err)
		return
	}

	if err := encodeEnrichResponse(response, w, span); err != nil {
		defer recordError("EncodeResponse", err)
		if !errors.Is(err, ht.ErrInternalServerErrorResponse) {
			s.cfg.ErrorHandler(ctx, w, r, err)
		}
		return
	}
}

// handleEnrichResourceRequest handles enrichResource operation.
//
// Enrich a value with data from various services.
//
// GET /enrich/{service_id}/{resource_type_id}
func (s *Server) handleEnrichResourceRequest(args [2]string, argsEscaped bool, w http.ResponseWriter, r *http.Request) {
	otelAttrs := []attribute.KeyValue{
		otelogen.OperationID("enrichResource"),
		semconv.HTTPMethodKey.String("GET"),
		semconv.HTTPRouteKey.String("/enrich/{service_id}/{resource_type_id}"),
	}

	// Start a span for this request.
	ctx, span := s.cfg.Tracer.Start(r.Context(), "EnrichResource",
		trace.WithAttributes(otelAttrs...),
		serverSpanKind,
	)
	defer span.End()

	// Add Labeler to context.
	labeler := &Labeler{attrs: otelAttrs}
	ctx = contextWithLabeler(ctx, labeler)

	// Run stopwatch.
	startTime := time.Now()
	defer func() {
		elapsedDuration := time.Since(startTime)
		attrOpt := metric.WithAttributeSet(labeler.AttributeSet())

		// Increment request counter.
		s.requests.Add(ctx, 1, attrOpt)

		// Use floating point division here for higher precision (instead of Millisecond method).
		s.duration.Record(ctx, float64(float64(elapsedDuration)/float64(time.Millisecond)), attrOpt)
	}()

	var (
		recordError = func(stage string, err error) {
			span.RecordError(err)
			span.SetStatus(codes.Error, stage)
			s.errors.Add(ctx, 1, metric.WithAttributeSet(labeler.AttributeSet()))
		}
		err          error
		opErrContext = ogenerrors.OperationContext{
			Name: "EnrichResource",
			ID:   "enrichResource",
		}
	)
	params, err := decodeEnrichResourceParams(args, argsEscaped, r)
	if err != nil {
		err = &ogenerrors.DecodeParamsError{
			OperationContext: opErrContext,
			Err:              err,
		}
		defer recordError("DecodeParams", err)
		s.cfg.ErrorHandler(ctx, w, r, err)
		return
	}

	var response *Resource
	if m := s.cfg.Middleware; m != nil {
		mreq := middleware.Request{
			Context:          ctx,
			OperationName:    "EnrichResource",
			OperationSummary: "Enrich a value with data from various services",
			OperationID:      "enrichResource",
			Body:             nil,
			Params: middleware.Parameters{
				{
					Name: "service_id",
					In:   "path",
				}: params.ServiceID,
				{
					Name: "resource_type_id",
					In:   "path",
				}: params.ResourceTypeID,
				{
					Name: "value",
					In:   "query",
				}: params.Value,
				{
					Name: "limit",
					In:   "query",
				}: params.Limit,
			},
			Raw: r,
		}

		type (
			Request  = struct{}
			Params   = EnrichResourceParams
			Response = *Resource
		)
		response, err = middleware.HookMiddleware[
			Request,
			Params,
			Response,
		](
			m,
			mreq,
			unpackEnrichResourceParams,
			func(ctx context.Context, request Request, params Params) (response Response, err error) {
				response, err = s.h.EnrichResource(ctx, params)
				return response, err
			},
		)
	} else {
		response, err = s.h.EnrichResource(ctx, params)
	}
	if err != nil {
		defer recordError("Internal", err)
		s.cfg.ErrorHandler(ctx, w, r, err)
		return
	}

	if err := encodeEnrichResourceResponse(response, w, span); err != nil {
		defer recordError("EncodeResponse", err)
		if !errors.Is(err, ht.ErrInternalServerErrorResponse) {
			s.cfg.ErrorHandler(ctx, w, r, err)
		}
		return
	}
}

// handleGetAttributeRequest handles getAttribute operation.
//
// Retrieve a specific attribute from a resource.
//
// GET /services/{service_id}/{resource_type_id}/{resource_id}/{attribute_id}
func (s *Server) handleGetAttributeRequest(args [4]string, argsEscaped bool, w http.ResponseWriter, r *http.Request) {
	otelAttrs := []attribute.KeyValue{
		otelogen.OperationID("getAttribute"),
		semconv.HTTPMethodKey.String("GET"),
		semconv.HTTPRouteKey.String("/services/{service_id}/{resource_type_id}/{resource_id}/{attribute_id}"),
	}

	// Start a span for this request.
	ctx, span := s.cfg.Tracer.Start(r.Context(), "GetAttribute",
		trace.WithAttributes(otelAttrs...),
		serverSpanKind,
	)
	defer span.End()

	// Add Labeler to context.
	labeler := &Labeler{attrs: otelAttrs}
	ctx = contextWithLabeler(ctx, labeler)

	// Run stopwatch.
	startTime := time.Now()
	defer func() {
		elapsedDuration := time.Since(startTime)
		attrOpt := metric.WithAttributeSet(labeler.AttributeSet())

		// Increment request counter.
		s.requests.Add(ctx, 1, attrOpt)

		// Use floating point division here for higher precision (instead of Millisecond method).
		s.duration.Record(ctx, float64(float64(elapsedDuration)/float64(time.Millisecond)), attrOpt)
	}()

	var (
		recordError = func(stage string, err error) {
			span.RecordError(err)
			span.SetStatus(codes.Error, stage)
			s.errors.Add(ctx, 1, metric.WithAttributeSet(labeler.AttributeSet()))
		}
		err          error
		opErrContext = ogenerrors.OperationContext{
			Name: "GetAttribute",
			ID:   "getAttribute",
		}
	)
	params, err := decodeGetAttributeParams(args, argsEscaped, r)
	if err != nil {
		err = &ogenerrors.DecodeParamsError{
			OperationContext: opErrContext,
			Err:              err,
		}
		defer recordError("DecodeParams", err)
		s.cfg.ErrorHandler(ctx, w, r, err)
		return
	}

	var response *Attribute
	if m := s.cfg.Middleware; m != nil {
		mreq := middleware.Request{
			Context:          ctx,
			OperationName:    "GetAttribute",
			OperationSummary: "Retrieve a specific attribute from a resource",
			OperationID:      "getAttribute",
			Body:             nil,
			Params: middleware.Parameters{
				{
					Name: "service_id",
					In:   "path",
				}: params.ServiceID,
				{
					Name: "resource_type_id",
					In:   "path",
				}: params.ResourceTypeID,
				{
					Name: "resource_id",
					In:   "path",
				}: params.ResourceID,
				{
					Name: "attribute_id",
					In:   "path",
				}: params.AttributeID,
			},
			Raw: r,
		}

		type (
			Request  = struct{}
			Params   = GetAttributeParams
			Response = *Attribute
		)
		response, err = middleware.HookMiddleware[
			Request,
			Params,
			Response,
		](
			m,
			mreq,
			unpackGetAttributeParams,
			func(ctx context.Context, request Request, params Params) (response Response, err error) {
				response, err = s.h.GetAttribute(ctx, params)
				return response, err
			},
		)
	} else {
		response, err = s.h.GetAttribute(ctx, params)
	}
	if err != nil {
		defer recordError("Internal", err)
		s.cfg.ErrorHandler(ctx, w, r, err)
		return
	}

	if err := encodeGetAttributeResponse(response, w, span); err != nil {
		defer recordError("EncodeResponse", err)
		if !errors.Is(err, ht.ErrInternalServerErrorResponse) {
			s.cfg.ErrorHandler(ctx, w, r, err)
		}
		return
	}
}

// handleGetResourceRequest handles getResource operation.
//
// Retrieve a specific resource from a service.
//
// GET /services/{service_id}/{resource_type_id}/{resource_id}
func (s *Server) handleGetResourceRequest(args [3]string, argsEscaped bool, w http.ResponseWriter, r *http.Request) {
	otelAttrs := []attribute.KeyValue{
		otelogen.OperationID("getResource"),
		semconv.HTTPMethodKey.String("GET"),
		semconv.HTTPRouteKey.String("/services/{service_id}/{resource_type_id}/{resource_id}"),
	}

	// Start a span for this request.
	ctx, span := s.cfg.Tracer.Start(r.Context(), "GetResource",
		trace.WithAttributes(otelAttrs...),
		serverSpanKind,
	)
	defer span.End()

	// Add Labeler to context.
	labeler := &Labeler{attrs: otelAttrs}
	ctx = contextWithLabeler(ctx, labeler)

	// Run stopwatch.
	startTime := time.Now()
	defer func() {
		elapsedDuration := time.Since(startTime)
		attrOpt := metric.WithAttributeSet(labeler.AttributeSet())

		// Increment request counter.
		s.requests.Add(ctx, 1, attrOpt)

		// Use floating point division here for higher precision (instead of Millisecond method).
		s.duration.Record(ctx, float64(float64(elapsedDuration)/float64(time.Millisecond)), attrOpt)
	}()

	var (
		recordError = func(stage string, err error) {
			span.RecordError(err)
			span.SetStatus(codes.Error, stage)
			s.errors.Add(ctx, 1, metric.WithAttributeSet(labeler.AttributeSet()))
		}
		err          error
		opErrContext = ogenerrors.OperationContext{
			Name: "GetResource",
			ID:   "getResource",
		}
	)
	params, err := decodeGetResourceParams(args, argsEscaped, r)
	if err != nil {
		err = &ogenerrors.DecodeParamsError{
			OperationContext: opErrContext,
			Err:              err,
		}
		defer recordError("DecodeParams", err)
		s.cfg.ErrorHandler(ctx, w, r, err)
		return
	}

	var response *Resource
	if m := s.cfg.Middleware; m != nil {
		mreq := middleware.Request{
			Context:          ctx,
			OperationName:    "GetResource",
			OperationSummary: "Retrieve a specific resource from a service",
			OperationID:      "getResource",
			Body:             nil,
			Params: middleware.Parameters{
				{
					Name: "service_id",
					In:   "path",
				}: params.ServiceID,
				{
					Name: "resource_type_id",
					In:   "path",
				}: params.ResourceTypeID,
				{
					Name: "resource_id",
					In:   "path",
				}: params.ResourceID,
			},
			Raw: r,
		}

		type (
			Request  = struct{}
			Params   = GetResourceParams
			Response = *Resource
		)
		response, err = middleware.HookMiddleware[
			Request,
			Params,
			Response,
		](
			m,
			mreq,
			unpackGetResourceParams,
			func(ctx context.Context, request Request, params Params) (response Response, err error) {
				response, err = s.h.GetResource(ctx, params)
				return response, err
			},
		)
	} else {
		response, err = s.h.GetResource(ctx, params)
	}
	if err != nil {
		defer recordError("Internal", err)
		s.cfg.ErrorHandler(ctx, w, r, err)
		return
	}

	if err := encodeGetResourceResponse(response, w, span); err != nil {
		defer recordError("EncodeResponse", err)
		if !errors.Is(err, ht.ErrInternalServerErrorResponse) {
			s.cfg.ErrorHandler(ctx, w, r, err)
		}
		return
	}
}

// handleListServicesRequest handles listServices operation.
//
// Retrieve the list of available services.
//
// GET /services
func (s *Server) handleListServicesRequest(args [0]string, argsEscaped bool, w http.ResponseWriter, r *http.Request) {
	otelAttrs := []attribute.KeyValue{
		otelogen.OperationID("listServices"),
		semconv.HTTPMethodKey.String("GET"),
		semconv.HTTPRouteKey.String("/services"),
	}

	// Start a span for this request.
	ctx, span := s.cfg.Tracer.Start(r.Context(), "ListServices",
		trace.WithAttributes(otelAttrs...),
		serverSpanKind,
	)
	defer span.End()

	// Add Labeler to context.
	labeler := &Labeler{attrs: otelAttrs}
	ctx = contextWithLabeler(ctx, labeler)

	// Run stopwatch.
	startTime := time.Now()
	defer func() {
		elapsedDuration := time.Since(startTime)
		attrOpt := metric.WithAttributeSet(labeler.AttributeSet())

		// Increment request counter.
		s.requests.Add(ctx, 1, attrOpt)

		// Use floating point division here for higher precision (instead of Millisecond method).
		s.duration.Record(ctx, float64(float64(elapsedDuration)/float64(time.Millisecond)), attrOpt)
	}()

	var (
		recordError = func(stage string, err error) {
			span.RecordError(err)
			span.SetStatus(codes.Error, stage)
			s.errors.Add(ctx, 1, metric.WithAttributeSet(labeler.AttributeSet()))
		}
		err error
	)

	var response *ServiceListResponse
	if m := s.cfg.Middleware; m != nil {
		mreq := middleware.Request{
			Context:          ctx,
			OperationName:    "ListServices",
			OperationSummary: "Retrieve the list of available services",
			OperationID:      "listServices",
			Body:             nil,
			Params:           middleware.Parameters{},
			Raw:              r,
		}

		type (
			Request  = struct{}
			Params   = struct{}
			Response = *ServiceListResponse
		)
		response, err = middleware.HookMiddleware[
			Request,
			Params,
			Response,
		](
			m,
			mreq,
			nil,
			func(ctx context.Context, request Request, params Params) (response Response, err error) {
				response, err = s.h.ListServices(ctx)
				return response, err
			},
		)
	} else {
		response, err = s.h.ListServices(ctx)
	}
	if err != nil {
		defer recordError("Internal", err)
		s.cfg.ErrorHandler(ctx, w, r, err)
		return
	}

	if err := encodeListServicesResponse(response, w, span); err != nil {
		defer recordError("EncodeResponse", err)
		if !errors.Is(err, ht.ErrInternalServerErrorResponse) {
			s.cfg.ErrorHandler(ctx, w, r, err)
		}
		return
	}
}

// handleSuggestRequest handles suggest operation.
//
// Suggest resources based on a partial value.
//
// GET /suggest
func (s *Server) handleSuggestRequest(args [0]string, argsEscaped bool, w http.ResponseWriter, r *http.Request) {
	otelAttrs := []attribute.KeyValue{
		otelogen.OperationID("suggest"),
		semconv.HTTPMethodKey.String("GET"),
		semconv.HTTPRouteKey.String("/suggest"),
	}

	// Start a span for this request.
	ctx, span := s.cfg.Tracer.Start(r.Context(), "Suggest",
		trace.WithAttributes(otelAttrs...),
		serverSpanKind,
	)
	defer span.End()

	// Add Labeler to context.
	labeler := &Labeler{attrs: otelAttrs}
	ctx = contextWithLabeler(ctx, labeler)

	// Run stopwatch.
	startTime := time.Now()
	defer func() {
		elapsedDuration := time.Since(startTime)
		attrOpt := metric.WithAttributeSet(labeler.AttributeSet())

		// Increment request counter.
		s.requests.Add(ctx, 1, attrOpt)

		// Use floating point division here for higher precision (instead of Millisecond method).
		s.duration.Record(ctx, float64(float64(elapsedDuration)/float64(time.Millisecond)), attrOpt)
	}()

	var (
		recordError = func(stage string, err error) {
			span.RecordError(err)
			span.SetStatus(codes.Error, stage)
			s.errors.Add(ctx, 1, metric.WithAttributeSet(labeler.AttributeSet()))
		}
		err          error
		opErrContext = ogenerrors.OperationContext{
			Name: "Suggest",
			ID:   "suggest",
		}
	)
	params, err := decodeSuggestParams(args, argsEscaped, r)
	if err != nil {
		err = &ogenerrors.DecodeParamsError{
			OperationContext: opErrContext,
			Err:              err,
		}
		defer recordError("DecodeParams", err)
		s.cfg.ErrorHandler(ctx, w, r, err)
		return
	}

	var response *ResourceListResponse
	if m := s.cfg.Middleware; m != nil {
		mreq := middleware.Request{
			Context:          ctx,
			OperationName:    "Suggest",
			OperationSummary: "Suggest resources based on a partial value",
			OperationID:      "suggest",
			Body:             nil,
			Params: middleware.Parameters{
				{
					Name: "partial",
					In:   "query",
				}: params.Partial,
			},
			Raw: r,
		}

		type (
			Request  = struct{}
			Params   = SuggestParams
			Response = *ResourceListResponse
		)
		response, err = middleware.HookMiddleware[
			Request,
			Params,
			Response,
		](
			m,
			mreq,
			unpackSuggestParams,
			func(ctx context.Context, request Request, params Params) (response Response, err error) {
				response, err = s.h.Suggest(ctx, params)
				return response, err
			},
		)
	} else {
		response, err = s.h.Suggest(ctx, params)
	}
	if err != nil {
		defer recordError("Internal", err)
		s.cfg.ErrorHandler(ctx, w, r, err)
		return
	}

	if err := encodeSuggestResponse(response, w, span); err != nil {
		defer recordError("EncodeResponse", err)
		if !errors.Is(err, ht.ErrInternalServerErrorResponse) {
			s.cfg.ErrorHandler(ctx, w, r, err)
		}
		return
	}
}
