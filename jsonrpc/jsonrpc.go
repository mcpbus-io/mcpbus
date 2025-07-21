package jsonrpc

import (
	"encoding/json"
	"errors"
	"math"
)

const (
	ERROR_SERVER           = -32000
	ERROR_NOT_FOUND        = -32001
	ERROR_PARSE            = -32700
	ERROR_INVALID_REQUEST  = -32600
	ERROR_METHOD_NOT_FOUND = -32601
	ERROR_INVALID_PARAMS   = -32602
	ERROR_INTERNAL         = -32603
)

const (
	JsonRpcVersion = "2.0"
)

const (
	MSG_TYPE_REQUEST = iota
	MSG_TYPE_RESPONSE
	MSG_TYPE_NOTIFY
	MSG_TYPE_ERROR
)

type RawMessage struct {
	JsonRpc string          `json:"jsonrpc"`
	Id      *any            `json:"id,omitempty"`
	Method  *string         `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

func (rm *RawMessage) Validate() (int, error) {
	if rm.JsonRpc != JsonRpcVersion {
		return MSG_TYPE_ERROR, errors.New("invalid or missing JSON-RPC version")
	}
	isPresentId := rm.Id != nil
	isMethodPresent := rm.Method != nil
	isParamsPresent := rm.Params != nil
	isResultPresent := rm.Result != nil
	isErrorPresent := rm.Error != nil

	// check id type (must be string or integer number)
	if isPresentId {
		val := *rm.Id
		if _, ok := val.(string); !ok {
			if floatVal, ok := val.(float64); !ok {
				return MSG_TYPE_ERROR, errors.New("id must be a string or an integer number")
			} else if _, frac := math.Modf(floatVal); frac != 0 {
				return MSG_TYPE_ERROR, errors.New("id must be a string or an integer number")
			}
		}
	}

	if isMethodPresent {
		// request or notification
		if isResultPresent || isErrorPresent {
			return MSG_TYPE_ERROR, errors.New("both method and result or error are present")
		}
		if !isPresentId {
			return MSG_TYPE_NOTIFY, nil
		} else {
			return MSG_TYPE_REQUEST, nil
		}
	}

	// response
	if !isPresentId {
		return MSG_TYPE_ERROR, errors.New("id is missing")
	}
	if !isResultPresent && !isErrorPresent {
		return MSG_TYPE_ERROR, errors.New("both result or error are missing")
	} else if isResultPresent && isErrorPresent {
		return MSG_TYPE_ERROR, errors.New("result and error are both present")
	}
	if isParamsPresent {
		return MSG_TYPE_ERROR, errors.New("params are present in response")
	}

	return MSG_TYPE_RESPONSE, nil
}

type Request struct {
	JsonRpc string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	Id      any             `json:"id,omitempty"`
}

type Response struct {
	JsonRpc string         `json:"jsonrpc"`
	Result  any            `json:"result,omitempty"`
	Error   *ErrorResponse `json:"error,omitempty"`
	Id      any            `json:"id"`
}

type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func GetErrorResponse(errMsg string, code int, data any, id any) *Response {
	return &Response{
		JsonRpc: JsonRpcVersion,
		Error: &ErrorResponse{
			Code:    code,
			Message: errMsg,
			Data:    data,
		},
		Id: id,
	}
}
