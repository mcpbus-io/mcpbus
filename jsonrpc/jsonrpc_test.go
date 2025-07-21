package jsonrpc

import (
	"encoding/json"
	"testing"
)

func TestRawMessage_Validate(t *testing.T) {
	tests := []struct {
		name    string
		msg     RawMessage
		want    int
		wantErr bool
	}{
		{
			name: "valid request",
			msg: RawMessage{
				JsonRpc: JsonRpcVersion,
				Id:      toPtr(any("1")),
				Method:  toPtr("test"),
			},
			want:    MSG_TYPE_REQUEST,
			wantErr: false,
		},
		{
			name: "valid notification",
			msg: RawMessage{
				JsonRpc: JsonRpcVersion,
				Method:  toPtr("test"),
			},
			want:    MSG_TYPE_NOTIFY,
			wantErr: false,
		},
		{
			name: "valid response with result",
			msg: RawMessage{
				JsonRpc: JsonRpcVersion,
				Id:      toPtr(any("1")),
				Result:  json.RawMessage(`{"key":"value"}`),
			},
			want:    MSG_TYPE_RESPONSE,
			wantErr: false,
		},
		{
			name: "valid response with error",
			msg: RawMessage{
				JsonRpc: JsonRpcVersion,
				Id:      toPtr(any("1")),
				Error:   json.RawMessage(`{"code":-32700,"message":"Parse error"}`),
			},
			want:    MSG_TYPE_RESPONSE,
			wantErr: false,
		},
		{
			name: "invalid JSON-RPC version",
			msg: RawMessage{
				JsonRpc: "1.0",
				Id:      toPtr(any("1")),
				Method:  toPtr("test"),
			},
			want:    MSG_TYPE_ERROR,
			wantErr: true,
		},
		{
			name: "invalid ID type",
			msg: RawMessage{
				JsonRpc: JsonRpcVersion,
				Id:      toPtr(any(true)),
				Method:  toPtr("test"),
			},
			want:    MSG_TYPE_ERROR,
			wantErr: true,
		},
		{
			name: "invalid float ID",
			msg: RawMessage{
				JsonRpc: JsonRpcVersion,
				Id:      toPtr(any(1.5)),
				Method:  toPtr("test"),
			},
			want:    MSG_TYPE_ERROR,
			wantErr: true,
		},
		{
			name: "invalid response missing ID",
			msg: RawMessage{
				JsonRpc: JsonRpcVersion,
				Result:  json.RawMessage(`{"key":"value"}`),
			},
			want:    MSG_TYPE_ERROR,
			wantErr: true,
		},
		{
			name: "invalid response with both result and error",
			msg: RawMessage{
				JsonRpc: JsonRpcVersion,
				Id:      toPtr(any("1")),
				Result:  json.RawMessage(`{"key":"value"}`),
				Error:   json.RawMessage(`{"code":-32700,"message":"Parse error"}`),
			},
			want:    MSG_TYPE_ERROR,
			wantErr: true,
		},
		{
			name: "invalid request with result",
			msg: RawMessage{
				JsonRpc: JsonRpcVersion,
				Id:      toPtr(any("1")),
				Method:  toPtr("test"),
				Result:  json.RawMessage(`{"key":"value"}`),
			},
			want:    MSG_TYPE_ERROR,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.msg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("RawMessage.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("RawMessage.Validate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func toPtr[T any](v T) *T {
	return &v
}
