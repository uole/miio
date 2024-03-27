package main

import (
	"context"
	"encoding/json"
	"github.com/uole/miio"
	"github.com/uole/miio/devtool"
	"github.com/uole/miio/types"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

var (
	intRegexp   = regexp.MustCompile(`^\d+$`)
	floatRegexp = regexp.MustCompile(`^\d+\.\d+$`)
)

// parseValue parse string to true value
func parseValue(s string) any {
	var (
		nv  int64
		fv  float64
		bv  bool
		err error
	)
	if intRegexp.MatchString(s) {
		nv, _ = strconv.ParseInt(s, 10, 64)
		return nv
	} else if floatRegexp.MatchString(s) {
		fv, _ = strconv.ParseFloat(s, 64)
		return fv
	} else {
		if bv, err = strconv.ParseBool(s); err == nil {
			return bv
		} else {
			return strings.TrimFunc(s, func(r rune) bool {
				if r == '"' || r == '`' || r == '\'' {
					return true
				}
				return false
			})
		}
	}
}

// parseProperties parse properties value
func parseProperties(did, s string) []*types.DeviceProperty {
	ps := make([]*types.DeviceProperty, 0)
	ss := strings.Split(s, ",")
	for _, row := range ss {
		vs := strings.Split(row, "-")
		n := len(vs)
		if n <= 0 {
			continue
		}
		item := &types.DeviceProperty{}
		if n == 1 {
			item.SIID, _ = strconv.Atoi(vs[0])
			item.PIID = 1
		} else if n == 2 {
			item.SIID, _ = strconv.Atoi(vs[0])
			item.PIID, _ = strconv.Atoi(vs[1])
		} else if n == 3 {
			item.SIID, _ = strconv.Atoi(vs[0])
			item.PIID, _ = strconv.Atoi(vs[1])
			item.Value = parseValue(vs[2])
		}
		if item.SIID > 0 && item.PIID > 0 {
			if did != "" {
				item.DID = did
			}
			ps = append(ps, item)
		}
	}
	return ps
}

func deviceInfoCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Show device info",
		Long:  "Command is used to show device information",
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) (err error) {
		var (
			ip         string
			token      string
			device     *miio.Device
			buf        []byte
			deviceInfo *types.DeviceInfo
		)
		ip, _ = cmd.Flags().GetString("ip")
		token, _ = cmd.Flags().GetString("token")
		device = miio.NewDevice(ip, token)
		if err = device.Dial(cmd.Context()); err != nil {
			return
		}
		defer func() {
			_ = device.Close()
		}()
		if deviceInfo, err = device.Info(cmd.Context()); err != nil {
			return
		}
		if buf, err = json.MarshalIndent(deviceInfo, "", "\t"); err == nil {
			cmd.Println(string(buf))
		}
		return
	}
	return cmd
}

func setPropertiesCommand() *cobra.Command {
	var (
		did string
	)
	cmd := &cobra.Command{
		Use:   "set_properties",
		Short: "Set device properties",
		Long:  "Command is used to set device properties",
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) (err error) {
		var (
			ip     string
			token  string
			device *miio.Device
		)
		ip, _ = cmd.Flags().GetString("ip")
		token, _ = cmd.Flags().GetString("token")
		device = miio.NewDevice(ip, token)
		if err = device.Dial(cmd.Context()); err != nil {
			return
		}
		defer func() {
			_ = device.Close()
		}()
		ps := make([]*types.DeviceProperty, 0)
		for _, s := range args {
			ps = append(ps, parseProperties(did, s)...)
		}
		if err = device.SetProperties(cmd.Context(), ps...); err != nil {
			return
		}
		cmd.Printf("DEVICE %d SET PROPERTY RESULT:\n", device.ID())
		for _, p := range ps {
			cmd.Printf("SSID: %-6d PIID: %-6d VALUE: %v\n", p.SIID, p.PIID, p.Value)
		}
		return
	}
	cmd.Flags().StringVarP(&did, "did", "", "", "device id")
	return cmd
}

func getPropertiesCommand() *cobra.Command {
	var (
		did string
	)
	cmd := &cobra.Command{
		Use:   "get_properties",
		Short: "Get device properties",
		Long:  "Command is used to get device properties",
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) (err error) {
		var (
			ip     string
			token  string
			device *miio.Device
		)
		ip, _ = cmd.Flags().GetString("ip")
		token, _ = cmd.Flags().GetString("token")
		device = miio.NewDevice(ip, token)
		if err = device.Dial(cmd.Context()); err != nil {
			return
		}
		defer func() {
			_ = device.Close()
		}()
		ps := make([]*types.DeviceProperty, 0)
		did, _ = cmd.Flags().GetString("did")
		for _, s := range args {
			ps = append(ps, parseProperties(did, s)...)
		}
		if err = device.GetProperties(cmd.Context(), ps...); err != nil {
			return
		}
		cmd.Printf("DEVICE %d SET PROPERTY RESULT:\n", device.ID())
		for _, p := range ps {
			cmd.Printf("SSID: %-6d PIID: %-6d VALUE: %v\n", p.SIID, p.PIID, p.Value)
		}
		return
	}
	cmd.Flags().StringVarP(&did, "did", "", "", "device id")
	return cmd
}

func actionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "action",
		Short: "Do device action",
		Long:  "Command is used to do device action",
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) (err error) {
		var (
			ip     string
			token  string
			buf    []byte
			device *miio.Device
			action *types.DeviceAction
		)
		ip, _ = cmd.Flags().GetString("ip")
		token, _ = cmd.Flags().GetString("token")
		device = miio.NewDevice(ip, token)
		if err = device.Dial(cmd.Context()); err != nil {
			return
		}
		defer func() {
			_ = device.Close()
		}()
		action = &types.DeviceAction{
			In: make([]any, 0),
		}
		action.SIID, _ = cmd.Flags().GetInt("siid")
		action.AIID, _ = cmd.Flags().GetInt("aiid")
		for _, s := range args {
			action.In = append(action.In, parseValue(s))
		}
		if buf, err = device.Action(cmd.Context(), action); err != nil {
			return
		}
		cmd.Println(string(buf))
		return
	}
	cmd.Flags().Int("siid", 0, "service id")
	cmd.Flags().Int("aiid", 0, "action id")
	_ = cmd.MarkFlagRequired("ssid")
	_ = cmd.MarkFlagRequired("aiid")
	return cmd
}

func executeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "execute",
		Short: "Execute device command",
		Long:  "Command is used to execute device command",
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) (err error) {
		var (
			ip     string
			token  string
			buf    []byte
			method string
			device *miio.Device
		)
		ip, _ = cmd.Flags().GetString("ip")
		token, _ = cmd.Flags().GetString("token")
		method, _ = cmd.Flags().GetString("method")
		device = miio.NewDevice(ip, token)
		if err = device.Dial(cmd.Context()); err != nil {
			return
		}
		defer func() {
			_ = device.Close()
		}()
		if buf, err = device.Execute(cmd.Context(), method, args...); err != nil {
			return
		}
		cmd.Println(string(buf))
		return
	}
	cmd.Flags().String("method", "", "execute method")
	_ = cmd.MarkFlagRequired("method")
	return cmd
}

func parsePcapCommand() *cobra.Command {
	var (
		token    string
		filename string
	)
	cmd := &cobra.Command{
		Use:   "parse_pcap",
		Short: "Parse pcap filename",
		Long:  "Command is used to parse pcap filename",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			token, _ = cmd.Flags().GetString("token")
			filename, _ = cmd.Flags().GetString("filename")
			return devtool.ParsePcap(filename, token)
		},
	}
	cmd.Flags().String("filename", "", "pcap file name")
	_ = cmd.MarkFlagRequired("filename")
	return cmd
}

func waitingSignal(ctx context.Context, cancelFunc context.CancelFunc) {
	ch := make(chan os.Signal, 1)
	signals := []os.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGKILL}
	signal.Notify(ch, signals...)
	select {
	case <-ctx.Done():
	case <-ch:
		cancelFunc()
		close(ch)
	}
}

func main() {
	var (
		ctx        context.Context
		cancelFunc context.CancelFunc
	)
	ctx, cancelFunc = context.WithCancel(context.Background())
	cmd := &cobra.Command{
		Use:   "miio",
		Short: "miio terminal emulation",
		Long:  "miio an analog terminal that implements miio, capable of obtaining properties and sending instructions",
	}
	cmd.PersistentFlags().StringP("ip", "", os.Getenv("MIIO_DEVICE_IP"), "device address")
	cmd.PersistentFlags().StringP("token", "", os.Getenv("MIIO_DEVICE_TOKEN"), "device token")
	cmd.AddCommand(deviceInfoCommand(), setPropertiesCommand(), getPropertiesCommand(), actionCommand(), executeCommand(), parsePcapCommand())
	go waitingSignal(ctx, cancelFunc)
	_ = cmd.ExecuteContext(ctx)
	cancelFunc()
}
