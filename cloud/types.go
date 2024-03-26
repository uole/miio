package cloud

import (
	"encoding/json"
	"net/http"
)

type (
	loginSignResponse struct {
		ServiceParam   string      `json:"serviceParam"`
		Qs             string      `json:"qs"`
		Code           int         `json:"code"`
		Description    string      `json:"description"`
		SecurityStatus int         `json:"securityStatus"`
		Sign           string      `json:"_sign"`
		Sid            string      `json:"sid"`
		Result         string      `json:"result"`
		CaptchaUrl     interface{} `json:"captchaUrl"`
		Callback       string      `json:"callback"`
		Location       string      `json:"location"`
		Pwd            int         `json:"pwd"`
		Child          int         `json:"child"`
		Desc           string      `json:"desc"`
	}

	loginInternalResponse struct {
		Qs             string      `json:"qs"`
		Ssecurity      string      `json:"ssecurity"`
		Code           int         `json:"code"`
		PassToken      string      `json:"passToken"`
		Description    string      `json:"description"`
		SecurityStatus int         `json:"securityStatus"`
		Nonce          int64       `json:"nonce"`
		UserId         int64       `json:"userId"`
		CUserId        string      `json:"cUserId"`
		Result         string      `json:"result"`
		Psecurity      string      `json:"psecurity"`
		CaptchaUrl     interface{} `json:"captchaUrl"`
		Location       string      `json:"location"`
		Pwd            int         `json:"pwd"`
		Child          int         `json:"child"`
		Desc           string      `json:"desc"`
	}

	MiRoom struct {
		Id         string   `json:"id"`
		Name       string   `json:"name"`
		Bssid      string   `json:"bssid"`
		Parentid   string   `json:"parentid"`
		Dids       []string `json:"dids"`
		Icon       string   `json:"icon"`
		Background string   `json:"background"`
		Shareflag  int      `json:"shareflag"`
		CreateTime int      `json:"create_time"`
	}

	MiHome struct {
		Id                  string    `json:"id"`
		Name                string    `json:"name"`
		Bssid               string    `json:"bssid"`
		Icon                string    `json:"icon"`
		ShareFlag           int       `json:"shareflag"`
		PermitLevel         int       `json:"permit_level"`
		Status              int       `json:"status"`
		Background          string    `json:"background"`
		SmartRoomBackground string    `json:"smart_room_background"`
		Longitude           float64   `json:"longitude"`
		Latitude            float64   `json:"latitude"`
		CityId              int       `json:"city_id"`
		Address             string    `json:"address"`
		CreateTime          int       `json:"create_time"`
		RoomList            []*MiRoom `json:"roomlist"`
		Uid                 int       `json:"uid"`
		PopupFlag           int       `json:"popup_flag"`
		PopupTimeStamp      int       `json:"popup_time_stamp"`
		CarDid              string    `json:"car_did"`
	}

	homeListResponse struct {
		HomeList []*MiHome `json:"homelist"`
	}

	DeviceExtra struct {
		IsSetPinCode      int    `json:"isSetPincode"`
		PinCodeType       int    `json:"pincodeType"`
		FwVersion         string `json:"fw_version"`
		NeedVerifyCode    int    `json:"needVerifyCode"`
		IsPasswordEncrypt int    `json:"isPasswordEncrypt"`
	}

	DeviceVirtualModel struct {
		Model string `json:"model"`
		State int    `json:"state"`
		Url   string `json:"url"`
	}

	DeviceInfo struct {
		Did         string      `json:"did"`
		Token       string      `json:"token"`
		Longitude   string      `json:"longitude"`
		Latitude    string      `json:"latitude"`
		Name        string      `json:"name"`
		Pid         any         `json:"pid"`
		LocalIP     string      `json:"localip"`
		Mac         string      `json:"mac"`
		Ssid        string      `json:"ssid"`
		Bssid       string      `json:"bssid"`
		ParentId    string      `json:"parent_id"`
		ParentModel string      `json:"parent_model"`
		ShowMode    int         `json:"show_mode"`
		Model       string      `json:"model"`
		AdminFlag   int         `json:"adminFlag"`
		ShareFlag   int         `json:"shareFlag"`
		PermitLevel int         `json:"permitLevel"`
		IsOnline    bool        `json:"isOnline"`
		Desc        string      `json:"desc"`
		Extra       DeviceExtra `json:"extra"`
		Uid         int         `json:"uid"`
		PdId        int         `json:"pd_id"`
		Password    string      `json:"password"`
		P2PId       string      `json:"p2p_id"`
		Rssi        int         `json:"rssi"`
		FamilyId    int         `json:"family_id"`
		ResetFlag   int         `json:"reset_flag"`
		SpecType    string      `json:"spec_type"`
	}

	deviceListResponse struct {
		List          []*DeviceInfo         `json:"list"`
		VirtualModels []*DeviceVirtualModel `json:"virtualModels"`
	}

	homeDeviceListResponse struct {
		Devices []*DeviceInfo `json:"device_info"`
	}

	SceneHistoryMsg struct {
		At          string `json:"at"`
		DevConState bool   `json:"dev_con_state"`
		Error       int    `json:"error"`
		Flag        string `json:"flag"`
		Note        string `json:"note"`
		T           int    `json:"t"`
		TargetDesc  string `json:"targetDesc"`
		Time        int    `json:"time"`
		UsId        int64  `json:"us_id"`
	}

	SceneHistory struct {
		From        string             `json:"from"`
		HomeId      int64              `json:"homeId"`
		Msg         []*SceneHistoryMsg `json:"msg"`
		Name        string             `json:"name"`
		NoRecordLog bool               `json:"noRecordLog"`
		SceneType   int                `json:"sceneType"`
		Modtime     int64              `json:"time"`
		UserSceneId int64              `json:"userSceneId"`
	}

	sceneHistoryResponse struct {
		History []*SceneHistory `json:"history"`
	}

	SensorMessage struct {
		MsgId      int64  `json:"msg_id"`
		Uid        int    `json:"uid"`
		Type       int    `json:"type"`
		SenderUid  int    `json:"sender_uid"`
		Did        string `json:"did"`
		Title      string `json:"title"`
		Content    string `json:"content"`
		ImgUrl     string `json:"img_url"`
		IsNew      int    `json:"is_new"`
		Status     int    `json:"status"`
		Ctime      int    `json:"ctime"`
		LastModify int    `json:"last_modify"`
		HomeId     int    `json:"home_id"`
		HomeOwner  int    `json:"home_owner"`
	}

	sensorMessageResponse struct {
		Messages []*SensorMessage `json:"messages"`
	}

	userSecurity struct {
		DeviceID      string `json:"device_id"`       //设备ID
		Sign          string `json:"sign"`            //签名字符串
		Security      string `json:"security"`        //安全码
		UserID        int64  `json:"user_id"`         //用户ID
		CurrentUserID string `json:"current_user_id"` //当前用户ID
		AccessToken   string `json:"access_token"`    //访问的令牌
		ServiceToken  string `json:"service_token"`   //服务令牌
		Location      string `json:"location"`        //当前的跳转地址
		Timestamp     int64  `json:"timestamp"`       //获取的时间戳
	}

	Request struct {
		Method string `json:"method"`
		Path   string `json:"path"`
		Data   any    `json:"data"`
	}

	Response struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Error   error           `json:"error"`
		Result  json.RawMessage `json:"result"`
	}
)

func (r *Response) IsOK() bool {
	return r.Error == nil
}

func (r *Response) Decode(v any) (err error) {
	return json.Unmarshal(r.Result, v)
}

func newRequest(uri string, data any) *Request {
	return &Request{
		Method: http.MethodPost,
		Path:   uri,
		Data:   data,
	}
}
