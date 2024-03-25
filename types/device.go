package types

type (
	DeviceNetWork struct {
		IP      string `json:"localIp"`
		Mask    string `json:"mask"`
		Gateway string `json:"gw"`
	}

	DeviceInfo struct {
		UID         int            `json:"uid"`
		Mac         string         `json:"mac"`
		Life        int            `json:"life"`
		Model       string         `json:"model"`
		Token       string         `json:"token"`
		IpFlag      int            `json:"ipflag"`
		Version     string         `json:"miio_ver"`
		FireVer     string         `json:"fw_ver"`
		HardVersion string         `json:"hw_ver"`
		Network     *DeviceNetWork `json:"netif"`
	}

	DeviceAttribute struct {
		Attribute string `json:"attr"`
		Value     any    `json:"value"`
	}

	DeviceProperty struct {
		DID     string `json:"did"`
		SIID    int    `json:"siid"`
		PIID    int    `json:"piid"`
		Value   any    `json:"value,omitempty"`
		Code    int    `json:"code,omitempty"`
		Modtime int64  `json:"updateTime,omitempty"`
	}

	DeviceAction struct {
		DID  string `json:"did"`
		SIID int    `json:"siid"`
		AIID int    `json:"aiid"`
		In   []any  `json:"in"`
		Out  []any  `json:"out,omitempty"`
	}
)
