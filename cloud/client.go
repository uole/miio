package cloud

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/uole/miio/types"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	country    string
	username   string
	password   string
	deviceID   string
	userAgent  string
	us         *userSecurity
	cookies    []*http.Cookie
	httpClient *http.Client
}

// getLoginSign get login sign
func (c *Client) getLoginSign(ctx context.Context) (err error) {
	var (
		uri string
		pos int
		buf []byte
		req *http.Request
		res *http.Response
	)
	uri = "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true"
	if req, err = http.NewRequest(http.MethodGet, uri, nil); err != nil {
		return
	}
	req.Header.Add("User-Agent", c.userAgent)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range c.cookies {
		req.AddCookie(cookie)
	}
	req.AddCookie(&http.Cookie{Name: "userId", Value: c.username})
	if res, err = c.httpClient.Do(req.WithContext(ctx)); err != nil {
		return
	}
	defer func() {
		_ = res.Body.Close()
	}()
	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("http response %s", res.Status)
		return
	}
	if buf, err = io.ReadAll(res.Body); err != nil {
		if !errors.Is(err, io.EOF) {
			return
		}
	}
	if pos = bytes.IndexByte(buf, '{'); pos > -1 {
		buf = buf[pos:]
	}
	ret := &loginSignResponse{}
	if err = json.Unmarshal(buf, ret); err == nil {
		c.us.Sign = ret.Sign
	}
	return
}

// loginInternal login internal
func (c *Client) loginInternal(ctx context.Context) (err error) {
	var (
		pos int
		buf []byte
		uri string
		req *http.Request
		res *http.Response
		qs  url.Values
	)
	uri = "https://account.xiaomi.com/pass/serviceLoginAuth2"
	qs = make(url.Values)
	hash := md5.New()
	hash.Write([]byte(c.password))
	qs.Set("sid", "xiaomiio")
	qs.Set("hash", strings.ToUpper(hex.EncodeToString(hash.Sum(nil))))
	qs.Set("callback", "https://sts.api.io.mi.com/sts")
	qs.Set("qs", "%3Fsid%3Dxiaomiio%26_json%3Dtrue")
	qs.Set("user", c.username)
	qs.Set("_sign", c.us.Sign)
	qs.Set("_json", "true")
	uri += "?" + qs.Encode()
	if req, err = http.NewRequest(http.MethodPost, uri, nil); err != nil {
		return
	}
	req.Header.Add("User-Agent", c.userAgent)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range c.cookies {
		req.AddCookie(cookie)
	}
	req.AddCookie(&http.Cookie{Name: "userId", Value: c.username})
	if res, err = c.httpClient.Do(req.WithContext(ctx)); err != nil {
		return
	}
	defer func() {
		_ = res.Body.Close()
	}()
	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("http response %s", res.Status)
		return
	}
	if buf, err = io.ReadAll(res.Body); err != nil {
		if !errors.Is(err, io.EOF) {
			return
		}
	}
	if pos = bytes.IndexByte(buf, '{'); pos > -1 {
		buf = buf[pos:]
	}
	ret := &loginInternalResponse{}
	if err = json.Unmarshal(buf, ret); err != nil {
		return
	}
	if ret.Code == 0 {
		c.us.Location = ret.Location
		c.us.AccessToken = ret.PassToken
		c.us.CurrentUserID = ret.CUserId
		c.us.UserID = ret.UserId
		c.us.Security = ret.Ssecurity
	}
	return
}

// getLoginServeToken get login server token
func (c *Client) getLoginServeToken(ctx context.Context) (err error) {
	var (
		req *http.Request
		res *http.Response
	)
	if req, err = http.NewRequest(http.MethodGet, c.us.Location, nil); err != nil {
		return
	}
	req.Header.Add("User-Agent", c.userAgent)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range c.cookies {
		req.AddCookie(cookie)
	}
	req.AddCookie(&http.Cookie{Name: "userId", Value: c.username})
	if res, err = c.httpClient.Do(req.WithContext(ctx)); err != nil {
		return
	}
	defer func() {
		_ = res.Body.Close()
	}()
	for _, cookie := range res.Cookies() {
		if cookie.Name == "serviceToken" {
			c.us.ServiceToken = cookie.Value
		}
	}
	c.us.Timestamp = time.Now().Unix()
	return
}

// buildRequestUri build client request uri
func (c *Client) buildRequestUri(uri string) string {
	var prefix string
	if c.country == "cn" {
		prefix = "https://api.io.mi.com/app"
	} else {
		prefix = "https://" + c.country + ".api.io.mi.com/app"
	}
	if len(uri) > 0 {
		if uri[0] != '/' {
			uri = "/" + uri
		}
	}
	return prefix + uri
}

// signatureNonce signature nonce
func (c *Client) signatureNonce(nonce string) (sign string, err error) {
	var (
		b1 []byte
		b2 []byte
	)
	if b1, err = base64.StdEncoding.DecodeString(c.us.Security); err != nil {
		return
	}
	if b2, err = base64.StdEncoding.DecodeString(nonce); err != nil {
		return
	}
	buf := sha256.Sum256(append(b1, b2...))
	sign = base64.StdEncoding.EncodeToString(buf[:])
	return
}

// sha1Signature signature values
func (c *Client) sha1Signature(method string, uri string, qs url.Values, signNonce string) string {
	values := make([]string, 0, 5)
	uri = strings.TrimPrefix(path.Clean(uri), "/app")
	values = append(values, strings.ToUpper(method), uri)
	for k, _ := range qs {
		values = append(values, fmt.Sprintf("%s=%s", k, qs.Get(k)))
	}
	values = append(values, signNonce)
	hash := sha1.New()
	hash.Write([]byte(strings.Join(values, "&")))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

// encodeQueryParams 编码请求
func (c *Client) encodeQueryParams(method string, uri string, qs url.Values) (string, url.Values) {
	var (
		err       error
		nonce     []byte
		noncestr  string
		signNonce string
	)
	nonce = make([]byte, 12)
	rand.New(rand.NewSource(time.Now().UnixNano())).Read(nonce)
	binary.BigEndian.PutUint32(nonce[8:], uint32(time.Now().UnixMilli()/60000))
	noncestr = base64.StdEncoding.EncodeToString(nonce)
	if signNonce, err = c.signatureNonce(noncestr); err != nil {
		return signNonce, qs
	}
	qs.Set("rc4_hash__", c.sha1Signature(method, uri, qs, signNonce))
	for k, _ := range qs {
		qs.Set(k, c.rc4Encrypt(signNonce, qs.Get(k)))
	}
	qs.Set("signature", c.sha1Signature(method, uri, qs, signNonce)) //这个必须放在第一位
	qs.Set("ssecurity", c.us.Security)
	qs.Set("_nonce", noncestr)
	return signNonce, qs
}

// rc4Encrypt encrypt
func (c *Client) rc4Encrypt(signNonce, payload string) (s string) {
	var (
		err    error
		buf    []byte
		cipher *rc4.Cipher
	)
	if buf, err = base64.StdEncoding.DecodeString(signNonce); err != nil {
		return
	}
	if cipher, err = rc4.NewCipher(buf); err != nil {
		return
	}
	buf = make([]byte, 1024)
	cipher.XORKeyStream(buf, buf)
	dst := make([]byte, len(payload))
	cipher.XORKeyStream(dst, []byte(payload))
	return base64.StdEncoding.EncodeToString(dst)
}

// rc4Decrypt decrypt
func (c *Client) rc4Decrypt(signNonce string, payload []byte) (dst []byte, err error) {
	var (
		n      int
		buf    []byte
		cipher *rc4.Cipher
	)
	if buf, err = base64.StdEncoding.DecodeString(signNonce); err != nil {
		return
	}
	if cipher, err = rc4.NewCipher(buf); err != nil {
		return
	}
	buf = make([]byte, 1024)
	cipher.XORKeyStream(buf, buf)
	dlen := base64.StdEncoding.DecodedLen(len(payload))
	buf = make([]byte, dlen)
	if n, err = base64.StdEncoding.Decode(buf, payload); err != nil {
		return
	}
	dst = make([]byte, len(buf[:n]))
	cipher.XORKeyStream(dst, buf[:n])
	return
}

// doRequest execute an crypto http request
func (c *Client) doRequest(ctx context.Context, r *Request) (ret *Response) {
	var (
		buf       []byte
		qs        url.Values
		req       *http.Request
		res       *http.Response
		signNonce string
	)
	if c.us == nil || c.us.Security == "" || c.us.ServiceToken == "" {
		ret.Error = errors.New("please log in to the system first")
		return
	}
	ret = &Response{}
	qs = make(url.Values)
	if r.Data != nil {
		if buf, ret.Error = json.Marshal(r.Data); ret.Error == nil {
			qs.Set("data", string(buf))
		}
	}
	signNonce, qs = c.encodeQueryParams(r.Method, r.Path, qs)
	reqUri := c.buildRequestUri(r.Path) + "?" + qs.Encode()
	if req, ret.Error = http.NewRequest(r.Method, reqUri, nil); ret.Error != nil {
		ret.Code = ErrorCreateRequest
		return
	}
	req.Header.Add("Accept-Encoding", "identity")
	req.Header.Add("User-Agent", c.userAgent)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	//下面2个头大小写敏感
	req.Header["x-xiaomi-protocal-flag-cli"] = []string{"PROTOCAL-HTTP2"}
	req.Header["MIOT-ENCRYPT-ALGORITHM"] = []string{"ENCRYPT-RC4"}

	req.AddCookie(&http.Cookie{Name: "userId", Value: strconv.FormatInt(c.us.UserID, 10)})
	req.AddCookie(&http.Cookie{Name: "yetAnotherServiceToken", Value: c.us.ServiceToken})
	req.AddCookie(&http.Cookie{Name: "serviceToken", Value: c.us.ServiceToken})
	req.AddCookie(&http.Cookie{Name: "locale", Value: "en_GB"})
	req.AddCookie(&http.Cookie{Name: "timezone", Value: "GMT+02:00"})
	req.AddCookie(&http.Cookie{Name: "is_daylight", Value: "1"})
	req.AddCookie(&http.Cookie{Name: "dst_offset", Value: "3600000"})
	req.AddCookie(&http.Cookie{Name: "channel", Value: "MI_APP_STORE"})
	if res, ret.Error = c.httpClient.Do(req.WithContext(ctx)); ret.Error != nil {
		ret.Code = ErrorHttpRequest
		ret.Error = fmt.Errorf("http request error: %s", ret.Error.Error())
		return
	}
	defer func() {
		_ = res.Body.Close()
	}()
	if res.StatusCode != http.StatusOK {
		ret.Code = res.StatusCode
		ret.Error = fmt.Errorf("http server response %d: %s", res.StatusCode, res.Status)
		return
	}
	if buf, ret.Error = io.ReadAll(res.Body); ret.Error != nil {
		ret.Code = ErrorInvalidResponse
		return
	}
	if buf, ret.Error = c.rc4Decrypt(signNonce, buf); ret.Error != nil {
		ret.Code = ErrorInvalidResponse
		return
	}
	if ret.Error = json.Unmarshal(buf, ret); ret.Error != nil {
		ret.Code = ErrorInvalidResponse
		return
	}
	if ret.Code != 0 {
		ret.Error = errors.New(ret.Message)
		return
	}
	return
}

// buildUserAgent build user agent
func (c *Client) buildUserAgent(deviceID string) string {
	return fmt.Sprintf("Android-7.1.1-1.0.0-ONEPLUS A3010-136-%s APP/xiaomi.smarthome APPV/62830", strings.ToUpper(deviceID))
}

// prepareLogin login prepare
func (c *Client) prepareLogin() {
	c.userAgent = c.buildUserAgent(c.deviceID)
	c.cookies = []*http.Cookie{
		{Name: "sdkVersion", Value: "accountsdk-18.8.15", Domain: "mi.com"},
		{Name: "sdkVersion", Value: "accountsdk-18.8.15", Domain: "xiaomi.com"},
		{Name: "deviceId", Value: c.deviceID, Domain: "mi.com"},
		{Name: "deviceId", Value: c.deviceID, Domain: "xiaomi.com"},
	}
}

// login login mi cloud
func (c *Client) login(ctx context.Context, force bool) (err error) {
	var (
		buf       []byte
		tokenFile string
		us        *userSecurity
	)
	if tokenFile, err = os.UserHomeDir(); err != nil {
		tokenFile = os.TempDir()
	}
	tokenFile = path.Join(tokenFile, ".miio.token")
	if buf, err = os.ReadFile(tokenFile); err == nil {
		us = &userSecurity{}
		if err = json.Unmarshal(buf, us); err == nil {
			// less 5 minute
			if !force || (force && time.Now().Unix()-us.Timestamp < 300) {
				c.us = us
				c.deviceID = c.us.DeviceID
				c.prepareLogin()
				return
			}
		}
	}
	buf = make([]byte, 6)
	rand.New(rand.NewSource(time.Now().UnixNano())).Read(buf)
	c.deviceID = strings.ToLower(base64.RawURLEncoding.EncodeToString(buf))
	c.prepareLogin()
	if err = c.getLoginSign(ctx); err != nil {
		return
	}
	if err = c.loginInternal(ctx); err != nil {
		return
	}
	if err = c.getLoginServeToken(ctx); err != nil {
		return
	}
	c.us.DeviceID = c.deviceID
	c.us.Timestamp = time.Now().Unix()
	if buf, err = json.MarshalIndent(c.us, "", "\t"); err == nil {
		err = os.WriteFile(tokenFile, buf, 0644)
	}
	return
}

// Login login mi cloud
func (c *Client) Login(ctx context.Context) (err error) {
	return c.login(ctx, false)
}

// HasNewMsg checking has new message
func (c *Client) HasNewMsg(ctx context.Context) bool {
	var ret *Response
	ret = c.Request(ctx, newRequest("/v2/message/v2/check_new_msg", map[string]any{"begin_at": time.Now().Unix() - 60}))
	if ret.IsOK() {
		b, _ := strconv.ParseBool(string(ret.Result))
		return b
	}
	return false
}

// GetHomes get mijia homes
func (c *Client) GetHomes(ctx context.Context) (homes []*MiHome, err error) {
	var (
		ret *Response
	)
	ret = c.Request(ctx, newRequest("/v2/homeroom/gethome", map[string]any{
		"fg":              true,
		"fetch_share":     true,
		"fetch_share_dev": true,
		"limit":           300,
		"app_ver":         7,
	}))
	if !ret.IsOK() {
		err = ret.Error
		return
	}
	res := &homeListResponse{}
	if err = ret.Decode(res); err == nil {
		homes = res.HomeList
	}
	return
}

// GetHomeDevices get mi home devices
func (c *Client) GetHomeDevices(ctx context.Context, homeID int64) (devices []*DeviceInfo, err error) {
	var (
		ret *Response
	)
	ret = c.Request(ctx, newRequest("/v2/home/home_device_list", map[string]any{
		"home_owner":         c.us.UserID,
		"home_id":            homeID,
		"fetch_share_dev":    true,
		"limit":              200,
		"support_smart_home": true,
	}))
	if !ret.IsOK() {
		err = ret.Error
		return
	}
	res := &homeDeviceListResponse{}
	if err = json.Unmarshal(ret.Result, res); err == nil {
		devices = res.Devices
	}
	return
}

// GetDevices get all devices
func (c *Client) GetDevices(ctx context.Context) (devices []*DeviceInfo, err error) {
	var (
		ret *Response
	)
	ret = c.Request(ctx, newRequest("/home/device_list", map[string]any{
		"getVirtualModel":    true,
		"getHuamiDevices":    1,
		"get_split_device":   true,
		"support_smart_home": true,
	}))
	if !ret.IsOK() {
		err = ret.Error
		return
	}
	res := &deviceListResponse{}
	if err = ret.Decode(res); err == nil {
		devices = res.List
	}
	return
}

// GetLastMessage get last message
func (c *Client) GetLastMessage(ctx context.Context) (messages []*SensorMessage, err error) {
	var (
		ret *Response
	)
	ret = c.Request(ctx, newRequest("/v2/message/v2/typelist", map[string]any{}))
	if !ret.IsOK() {
		err = ret.Error
		return
	}
	res := &sensorMessageResponse{}
	if err = json.Unmarshal(ret.Result, res); err == nil {
		messages = res.Messages
	}
	return
}

// GetSceneHistories get scene histories
func (c *Client) GetSceneHistories(ctx context.Context, homeID int64) (histories []*SceneHistory, err error) {
	var (
		ret *Response
	)
	ret = c.Request(ctx, newRequest("/scene/history", map[string]any{
		"home_id":   homeID,
		"uid":       c.us.UserID,
		"owner_uid": c.us.UserID,
		"command":   "history",
		"limit":     15,
	}))
	if !ret.IsOK() {
		err = ret.Error
		return
	}
	res := &sceneHistoryResponse{}
	if err = ret.Decode(res); err == nil {
		histories = res.History
	}
	return
}

// GetDeviceProperties get device properties
func (c *Client) GetDeviceProperties(ctx context.Context, ps ...*types.DeviceProperty) (err error) {
	var (
		ret *Response
	)
	ret = c.Request(ctx, newRequest("/miotspec/prop/get", map[string]any{
		"params": ps,
	}))
	if !ret.IsOK() {
		err = ret.Error
		return
	}
	items := make([]*types.DeviceProperty, 0)
	if err = json.Unmarshal(ret.Result, &items); err != nil {
		return
	}
	for _, row := range items {
		for _, p := range ps {
			if p.SIID == row.SIID && p.PIID == row.PIID {
				p.Value = row.Value
				p.Code = row.Code
				p.Modtime = row.Modtime
				break
			}
		}
	}
	return
}

// SetDeviceProperties set device properties
func (c *Client) SetDeviceProperties(ctx context.Context, ps ...*types.DeviceProperty) (err error) {
	var (
		ret *Response
	)
	ret = c.Request(ctx, newRequest("/miotspec/prop/set", map[string]any{
		"params": ps,
	}))
	if !ret.IsOK() {
		err = ret.Error
		return
	}
	items := make([]*types.DeviceProperty, 0)
	if err = json.Unmarshal(ret.Result, &items); err != nil {
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

// ExecuteDeviceAction execute action
func (c *Client) ExecuteDeviceAction(ctx context.Context, args types.DeviceAction) (err error) {
	var (
		ret *Response
	)
	ret = c.Request(ctx, newRequest("/miotspec/action", map[string]any{
		"params": args,
	}))
	if !ret.IsOK() {
		err = ret.Error
	}
	return
}

// Request do http request
func (c *Client) Request(ctx context.Context, r *Request) *Response {
	var (
		err       error
		attempted bool
		res       *Response
	)
__retry:
	if res = c.doRequest(ctx, r); !res.IsOK() {
		if !attempted && res.Code == http.StatusUnauthorized {
			if err = c.login(ctx, true); err == nil {
				attempted = true
				goto __retry
			}
		}
	}
	return res
}

func New(country string, username string, password string) *Client {
	c := &Client{
		country:  country,
		username: username,
		password: password,
		us:       &userSecurity{},
	}
	c.httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	return c
}
