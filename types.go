package miio

import (
	"encoding/json"
	"errors"
)

const (
	//DefaultPort 默认的端口号
	DefaultPort = 54321

	MaxFrameLength = 10240

	HeadLength = 32
)

var (
	ErrorTokenInvalid = errors.New("token invalid")
	ErrorPacket       = errors.New("packet invalid")

	PacketMagic uint16 = 8497

	HelloToken = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
)

type (
	CommandRequest struct {
		ID     int    `json:"id"`
		Method string `json:"method"`
		Params any    `json:"params"`
	}

	CommandError struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}

	CommandResponse struct {
		ID          int             `json:"id"`
		Method      string          `json:"method"`
		Result      json.RawMessage `json:"result"`
		Error       *CommandError   `json:"error"`
		ExecuteTime int             `json:"exe_time"`
	}
)

func (e *CommandError) Error() string {
	return e.Message
}

func NewCommandRequest(method string, params any) *CommandRequest {
	return &CommandRequest{
		Method: method,
		Params: params,
	}
}

func (req *CommandRequest) Bytes() ([]byte, error) {
	return json.Marshal(req)
}

func (res *CommandResponse) Decode(v any) (err error) {
	return json.Unmarshal(res.Result, v)
}
