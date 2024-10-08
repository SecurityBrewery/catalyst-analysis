// Code generated by ogen, DO NOT EDIT.

package api

import (
	"net/http"
	"net/url"

	"github.com/go-faster/errors"
	"github.com/ogen-go/ogen/conv"
	"github.com/ogen-go/ogen/middleware"
	"github.com/ogen-go/ogen/ogenerrors"
	"github.com/ogen-go/ogen/uri"
	"github.com/ogen-go/ogen/validate"
)

// EnrichParams is parameters of enrich operation.
type EnrichParams struct {
	Value string
	// Limit the number of enrichments, default is unlimited.
	Limit OptInt
}

func unpackEnrichParams(packed middleware.Parameters) (params EnrichParams) {
	{
		key := middleware.ParameterKey{
			Name: "value",
			In:   "query",
		}
		params.Value = packed[key].(string)
	}
	{
		key := middleware.ParameterKey{
			Name: "limit",
			In:   "query",
		}
		if v, ok := packed[key]; ok {
			params.Limit = v.(OptInt)
		}
	}
	return params
}

func decodeEnrichParams(args [0]string, argsEscaped bool, r *http.Request) (params EnrichParams, _ error) {
	q := uri.NewQueryDecoder(r.URL.Query())
	// Decode query: value.
	if err := func() error {
		cfg := uri.QueryParameterDecodingConfig{
			Name:    "value",
			Style:   uri.QueryStyleForm,
			Explode: true,
		}

		if err := q.HasParam(cfg); err == nil {
			if err := q.DecodeParam(cfg, func(d uri.Decoder) error {
				val, err := d.DecodeValue()
				if err != nil {
					return err
				}

				c, err := conv.ToString(val)
				if err != nil {
					return err
				}

				params.Value = c
				return nil
			}); err != nil {
				return err
			}
		} else {
			return validate.ErrFieldRequired
		}
		return nil
	}(); err != nil {
		return params, &ogenerrors.DecodeParamError{
			Name: "value",
			In:   "query",
			Err:  err,
		}
	}
	// Decode query: limit.
	if err := func() error {
		cfg := uri.QueryParameterDecodingConfig{
			Name:    "limit",
			Style:   uri.QueryStyleForm,
			Explode: true,
		}

		if err := q.HasParam(cfg); err == nil {
			if err := q.DecodeParam(cfg, func(d uri.Decoder) error {
				var paramsDotLimitVal int
				if err := func() error {
					val, err := d.DecodeValue()
					if err != nil {
						return err
					}

					c, err := conv.ToInt(val)
					if err != nil {
						return err
					}

					paramsDotLimitVal = c
					return nil
				}(); err != nil {
					return err
				}
				params.Limit.SetTo(paramsDotLimitVal)
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}(); err != nil {
		return params, &ogenerrors.DecodeParamError{
			Name: "limit",
			In:   "query",
			Err:  err,
		}
	}
	return params, nil
}

// EnrichResourceParams is parameters of enrichResource operation.
type EnrichResourceParams struct {
	ServiceID      string
	ResourceTypeID string
	Value          string
	// Limit the number of enrichments, default is unlimited.
	Limit OptInt
}

func unpackEnrichResourceParams(packed middleware.Parameters) (params EnrichResourceParams) {
	{
		key := middleware.ParameterKey{
			Name: "service_id",
			In:   "path",
		}
		params.ServiceID = packed[key].(string)
	}
	{
		key := middleware.ParameterKey{
			Name: "resource_type_id",
			In:   "path",
		}
		params.ResourceTypeID = packed[key].(string)
	}
	{
		key := middleware.ParameterKey{
			Name: "value",
			In:   "query",
		}
		params.Value = packed[key].(string)
	}
	{
		key := middleware.ParameterKey{
			Name: "limit",
			In:   "query",
		}
		if v, ok := packed[key]; ok {
			params.Limit = v.(OptInt)
		}
	}
	return params
}

func decodeEnrichResourceParams(args [2]string, argsEscaped bool, r *http.Request) (params EnrichResourceParams, _ error) {
	q := uri.NewQueryDecoder(r.URL.Query())
	// Decode path: service_id.
	if err := func() error {
		param := args[0]
		if argsEscaped {
			unescaped, err := url.PathUnescape(args[0])
			if err != nil {
				return errors.Wrap(err, "unescape path")
			}
			param = unescaped
		}
		if len(param) > 0 {
			d := uri.NewPathDecoder(uri.PathDecoderConfig{
				Param:   "service_id",
				Value:   param,
				Style:   uri.PathStyleSimple,
				Explode: false,
			})

			if err := func() error {
				val, err := d.DecodeValue()
				if err != nil {
					return err
				}

				c, err := conv.ToString(val)
				if err != nil {
					return err
				}

				params.ServiceID = c
				return nil
			}(); err != nil {
				return err
			}
		} else {
			return validate.ErrFieldRequired
		}
		return nil
	}(); err != nil {
		return params, &ogenerrors.DecodeParamError{
			Name: "service_id",
			In:   "path",
			Err:  err,
		}
	}
	// Decode path: resource_type_id.
	if err := func() error {
		param := args[1]
		if argsEscaped {
			unescaped, err := url.PathUnescape(args[1])
			if err != nil {
				return errors.Wrap(err, "unescape path")
			}
			param = unescaped
		}
		if len(param) > 0 {
			d := uri.NewPathDecoder(uri.PathDecoderConfig{
				Param:   "resource_type_id",
				Value:   param,
				Style:   uri.PathStyleSimple,
				Explode: false,
			})

			if err := func() error {
				val, err := d.DecodeValue()
				if err != nil {
					return err
				}

				c, err := conv.ToString(val)
				if err != nil {
					return err
				}

				params.ResourceTypeID = c
				return nil
			}(); err != nil {
				return err
			}
		} else {
			return validate.ErrFieldRequired
		}
		return nil
	}(); err != nil {
		return params, &ogenerrors.DecodeParamError{
			Name: "resource_type_id",
			In:   "path",
			Err:  err,
		}
	}
	// Decode query: value.
	if err := func() error {
		cfg := uri.QueryParameterDecodingConfig{
			Name:    "value",
			Style:   uri.QueryStyleForm,
			Explode: true,
		}

		if err := q.HasParam(cfg); err == nil {
			if err := q.DecodeParam(cfg, func(d uri.Decoder) error {
				val, err := d.DecodeValue()
				if err != nil {
					return err
				}

				c, err := conv.ToString(val)
				if err != nil {
					return err
				}

				params.Value = c
				return nil
			}); err != nil {
				return err
			}
		} else {
			return validate.ErrFieldRequired
		}
		return nil
	}(); err != nil {
		return params, &ogenerrors.DecodeParamError{
			Name: "value",
			In:   "query",
			Err:  err,
		}
	}
	// Decode query: limit.
	if err := func() error {
		cfg := uri.QueryParameterDecodingConfig{
			Name:    "limit",
			Style:   uri.QueryStyleForm,
			Explode: true,
		}

		if err := q.HasParam(cfg); err == nil {
			if err := q.DecodeParam(cfg, func(d uri.Decoder) error {
				var paramsDotLimitVal int
				if err := func() error {
					val, err := d.DecodeValue()
					if err != nil {
						return err
					}

					c, err := conv.ToInt(val)
					if err != nil {
						return err
					}

					paramsDotLimitVal = c
					return nil
				}(); err != nil {
					return err
				}
				params.Limit.SetTo(paramsDotLimitVal)
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}(); err != nil {
		return params, &ogenerrors.DecodeParamError{
			Name: "limit",
			In:   "query",
			Err:  err,
		}
	}
	return params, nil
}

// GetAttributeParams is parameters of getAttribute operation.
type GetAttributeParams struct {
	ServiceID      string
	ResourceTypeID string
	ResourceID     string
	AttributeID    string
}

func unpackGetAttributeParams(packed middleware.Parameters) (params GetAttributeParams) {
	{
		key := middleware.ParameterKey{
			Name: "service_id",
			In:   "path",
		}
		params.ServiceID = packed[key].(string)
	}
	{
		key := middleware.ParameterKey{
			Name: "resource_type_id",
			In:   "path",
		}
		params.ResourceTypeID = packed[key].(string)
	}
	{
		key := middleware.ParameterKey{
			Name: "resource_id",
			In:   "path",
		}
		params.ResourceID = packed[key].(string)
	}
	{
		key := middleware.ParameterKey{
			Name: "attribute_id",
			In:   "path",
		}
		params.AttributeID = packed[key].(string)
	}
	return params
}

func decodeGetAttributeParams(args [4]string, argsEscaped bool, r *http.Request) (params GetAttributeParams, _ error) {
	// Decode path: service_id.
	if err := func() error {
		param := args[0]
		if argsEscaped {
			unescaped, err := url.PathUnescape(args[0])
			if err != nil {
				return errors.Wrap(err, "unescape path")
			}
			param = unescaped
		}
		if len(param) > 0 {
			d := uri.NewPathDecoder(uri.PathDecoderConfig{
				Param:   "service_id",
				Value:   param,
				Style:   uri.PathStyleSimple,
				Explode: false,
			})

			if err := func() error {
				val, err := d.DecodeValue()
				if err != nil {
					return err
				}

				c, err := conv.ToString(val)
				if err != nil {
					return err
				}

				params.ServiceID = c
				return nil
			}(); err != nil {
				return err
			}
		} else {
			return validate.ErrFieldRequired
		}
		return nil
	}(); err != nil {
		return params, &ogenerrors.DecodeParamError{
			Name: "service_id",
			In:   "path",
			Err:  err,
		}
	}
	// Decode path: resource_type_id.
	if err := func() error {
		param := args[1]
		if argsEscaped {
			unescaped, err := url.PathUnescape(args[1])
			if err != nil {
				return errors.Wrap(err, "unescape path")
			}
			param = unescaped
		}
		if len(param) > 0 {
			d := uri.NewPathDecoder(uri.PathDecoderConfig{
				Param:   "resource_type_id",
				Value:   param,
				Style:   uri.PathStyleSimple,
				Explode: false,
			})

			if err := func() error {
				val, err := d.DecodeValue()
				if err != nil {
					return err
				}

				c, err := conv.ToString(val)
				if err != nil {
					return err
				}

				params.ResourceTypeID = c
				return nil
			}(); err != nil {
				return err
			}
		} else {
			return validate.ErrFieldRequired
		}
		return nil
	}(); err != nil {
		return params, &ogenerrors.DecodeParamError{
			Name: "resource_type_id",
			In:   "path",
			Err:  err,
		}
	}
	// Decode path: resource_id.
	if err := func() error {
		param := args[2]
		if argsEscaped {
			unescaped, err := url.PathUnescape(args[2])
			if err != nil {
				return errors.Wrap(err, "unescape path")
			}
			param = unescaped
		}
		if len(param) > 0 {
			d := uri.NewPathDecoder(uri.PathDecoderConfig{
				Param:   "resource_id",
				Value:   param,
				Style:   uri.PathStyleSimple,
				Explode: false,
			})

			if err := func() error {
				val, err := d.DecodeValue()
				if err != nil {
					return err
				}

				c, err := conv.ToString(val)
				if err != nil {
					return err
				}

				params.ResourceID = c
				return nil
			}(); err != nil {
				return err
			}
		} else {
			return validate.ErrFieldRequired
		}
		return nil
	}(); err != nil {
		return params, &ogenerrors.DecodeParamError{
			Name: "resource_id",
			In:   "path",
			Err:  err,
		}
	}
	// Decode path: attribute_id.
	if err := func() error {
		param := args[3]
		if argsEscaped {
			unescaped, err := url.PathUnescape(args[3])
			if err != nil {
				return errors.Wrap(err, "unescape path")
			}
			param = unescaped
		}
		if len(param) > 0 {
			d := uri.NewPathDecoder(uri.PathDecoderConfig{
				Param:   "attribute_id",
				Value:   param,
				Style:   uri.PathStyleSimple,
				Explode: false,
			})

			if err := func() error {
				val, err := d.DecodeValue()
				if err != nil {
					return err
				}

				c, err := conv.ToString(val)
				if err != nil {
					return err
				}

				params.AttributeID = c
				return nil
			}(); err != nil {
				return err
			}
		} else {
			return validate.ErrFieldRequired
		}
		return nil
	}(); err != nil {
		return params, &ogenerrors.DecodeParamError{
			Name: "attribute_id",
			In:   "path",
			Err:  err,
		}
	}
	return params, nil
}

// GetResourceParams is parameters of getResource operation.
type GetResourceParams struct {
	ServiceID      string
	ResourceTypeID string
	ResourceID     string
}

func unpackGetResourceParams(packed middleware.Parameters) (params GetResourceParams) {
	{
		key := middleware.ParameterKey{
			Name: "service_id",
			In:   "path",
		}
		params.ServiceID = packed[key].(string)
	}
	{
		key := middleware.ParameterKey{
			Name: "resource_type_id",
			In:   "path",
		}
		params.ResourceTypeID = packed[key].(string)
	}
	{
		key := middleware.ParameterKey{
			Name: "resource_id",
			In:   "path",
		}
		params.ResourceID = packed[key].(string)
	}
	return params
}

func decodeGetResourceParams(args [3]string, argsEscaped bool, r *http.Request) (params GetResourceParams, _ error) {
	// Decode path: service_id.
	if err := func() error {
		param := args[0]
		if argsEscaped {
			unescaped, err := url.PathUnescape(args[0])
			if err != nil {
				return errors.Wrap(err, "unescape path")
			}
			param = unescaped
		}
		if len(param) > 0 {
			d := uri.NewPathDecoder(uri.PathDecoderConfig{
				Param:   "service_id",
				Value:   param,
				Style:   uri.PathStyleSimple,
				Explode: false,
			})

			if err := func() error {
				val, err := d.DecodeValue()
				if err != nil {
					return err
				}

				c, err := conv.ToString(val)
				if err != nil {
					return err
				}

				params.ServiceID = c
				return nil
			}(); err != nil {
				return err
			}
		} else {
			return validate.ErrFieldRequired
		}
		return nil
	}(); err != nil {
		return params, &ogenerrors.DecodeParamError{
			Name: "service_id",
			In:   "path",
			Err:  err,
		}
	}
	// Decode path: resource_type_id.
	if err := func() error {
		param := args[1]
		if argsEscaped {
			unescaped, err := url.PathUnescape(args[1])
			if err != nil {
				return errors.Wrap(err, "unescape path")
			}
			param = unescaped
		}
		if len(param) > 0 {
			d := uri.NewPathDecoder(uri.PathDecoderConfig{
				Param:   "resource_type_id",
				Value:   param,
				Style:   uri.PathStyleSimple,
				Explode: false,
			})

			if err := func() error {
				val, err := d.DecodeValue()
				if err != nil {
					return err
				}

				c, err := conv.ToString(val)
				if err != nil {
					return err
				}

				params.ResourceTypeID = c
				return nil
			}(); err != nil {
				return err
			}
		} else {
			return validate.ErrFieldRequired
		}
		return nil
	}(); err != nil {
		return params, &ogenerrors.DecodeParamError{
			Name: "resource_type_id",
			In:   "path",
			Err:  err,
		}
	}
	// Decode path: resource_id.
	if err := func() error {
		param := args[2]
		if argsEscaped {
			unescaped, err := url.PathUnescape(args[2])
			if err != nil {
				return errors.Wrap(err, "unescape path")
			}
			param = unescaped
		}
		if len(param) > 0 {
			d := uri.NewPathDecoder(uri.PathDecoderConfig{
				Param:   "resource_id",
				Value:   param,
				Style:   uri.PathStyleSimple,
				Explode: false,
			})

			if err := func() error {
				val, err := d.DecodeValue()
				if err != nil {
					return err
				}

				c, err := conv.ToString(val)
				if err != nil {
					return err
				}

				params.ResourceID = c
				return nil
			}(); err != nil {
				return err
			}
		} else {
			return validate.ErrFieldRequired
		}
		return nil
	}(); err != nil {
		return params, &ogenerrors.DecodeParamError{
			Name: "resource_id",
			In:   "path",
			Err:  err,
		}
	}
	return params, nil
}

// SuggestParams is parameters of suggest operation.
type SuggestParams struct {
	Partial string
}

func unpackSuggestParams(packed middleware.Parameters) (params SuggestParams) {
	{
		key := middleware.ParameterKey{
			Name: "partial",
			In:   "query",
		}
		params.Partial = packed[key].(string)
	}
	return params
}

func decodeSuggestParams(args [0]string, argsEscaped bool, r *http.Request) (params SuggestParams, _ error) {
	q := uri.NewQueryDecoder(r.URL.Query())
	// Decode query: partial.
	if err := func() error {
		cfg := uri.QueryParameterDecodingConfig{
			Name:    "partial",
			Style:   uri.QueryStyleForm,
			Explode: true,
		}

		if err := q.HasParam(cfg); err == nil {
			if err := q.DecodeParam(cfg, func(d uri.Decoder) error {
				val, err := d.DecodeValue()
				if err != nil {
					return err
				}

				c, err := conv.ToString(val)
				if err != nil {
					return err
				}

				params.Partial = c
				return nil
			}); err != nil {
				return err
			}
		} else {
			return validate.ErrFieldRequired
		}
		return nil
	}(); err != nil {
		return params, &ogenerrors.DecodeParamError{
			Name: "partial",
			In:   "query",
			Err:  err,
		}
	}
	return params, nil
}
