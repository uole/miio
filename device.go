package miio

import (
	"context"
	"encoding/json"
	"github.com/uole/miio/types"
	"strconv"
)

type Device struct {
	address string
	token   string
	conn    *Conn
}

func (device *Device) ID() int {
	if device.conn == nil {
		return 0
	}
	return int(device.conn.deviceID)
}

// Dial dial device
func (device *Device) Dial(ctx context.Context) (err error) {
	return device.conn.Dial(ctx, device.address, device.token)
}

// Info get device information
func (device *Device) Info(ctx context.Context) (deviceInfo *types.DeviceInfo, err error) {
	var (
		res *CommandResponse
	)
	if res, err = device.conn.Execute(ctx, NewCommandRequest("miIO.info", nil)); err == nil {
		deviceInfo = &types.DeviceInfo{}
		err = res.Decode(deviceInfo)
	}
	return
}

// GetAttributes get device attributes
func (device *Device) GetAttributes(ctx context.Context, attrs ...string) (values []*types.DeviceAttribute, err error) {
	var (
		res *CommandResponse
	)
	if res, err = device.conn.Execute(ctx, NewCommandRequest("get_prop", attrs)); err == nil {
		values = make([]*types.DeviceAttribute, 0, len(attrs))
		ss := make([]string, 0)
		if err = res.Decode(&ss); err == nil {
			if len(ss) == len(attrs) {
				for i := 0; i < len(attrs); i++ {
					values = append(values, &types.DeviceAttribute{
						Attribute: attrs[i],
						Value:     ss[i],
					})
				}
			}
		}
	}
	return
}

// GetProperties get device properties
func (device *Device) GetProperties(ctx context.Context, ps ...*types.DeviceProperty) (err error) {
	var (
		res *CommandResponse
	)
	for _, p := range ps {
		if p.DID == "" {
			p.DID = strconv.FormatUint(uint64(device.conn.deviceID), 10)
		}
	}
	if res, err = device.conn.Execute(ctx, NewCommandRequest("get_properties", ps)); err != nil {
		return
	}
	items := make([]*types.DeviceProperty, 0)
	if err = json.Unmarshal(res.Result, &items); err != nil {
		return
	}
	for _, row := range items {
		for _, p := range ps {
			if p.SIID == row.SIID && p.PIID == row.PIID {
				p.Value = row.Value
				p.Code = row.Code
				break
			}
		}
	}
	return
}

// SetProperties set device properties
func (device *Device) SetProperties(ctx context.Context, ps ...*types.DeviceProperty) (err error) {
	var (
		res *CommandResponse
	)
	for _, p := range ps {
		if p.DID == "" {
			p.DID = strconv.FormatUint(uint64(device.conn.deviceID), 10)
		}
	}
	if res, err = device.conn.Execute(ctx, NewCommandRequest("set_properties", ps)); err == nil {
		return
	}
	items := make([]*types.DeviceProperty, 0)
	if err = json.Unmarshal(res.Result, &items); err != nil {
		return
	}
	for _, row := range items {
		for _, p := range ps {
			if p.SIID == row.SIID && p.PIID == row.PIID {
				if row.Value != nil {
					p.Value = row.Value
				}
				p.Code = row.Code
				break
			}
		}
	}
	return
}

// Action execute an action
func (device *Device) Action(ctx context.Context, action *types.DeviceAction) (buf []byte, err error) {
	var (
		res *CommandResponse
	)
	if action.DID == "" {
		action.DID = strconv.Itoa(int(device.conn.deviceID))
	}
	if res, err = device.conn.Execute(ctx, NewCommandRequest("action", action)); err != nil {
		return
	}
	buf = res.Result
	return
}

// Execute execute command
func (device *Device) Execute(ctx context.Context, method string, args ...string) (buf []byte, err error) {
	var (
		res *CommandResponse
	)
	if res, err = device.conn.Execute(ctx, NewCommandRequest(method, args)); err != nil {
		return
	}
	buf = res.Result
	return
}

// Close stop device connection
func (device *Device) Close() (err error) {
	return device.conn.Close()
}

func NewDevice(address string, token string) *Device {
	return &Device{
		address: address,
		token:   token,
		conn:    &Conn{},
	}
}
