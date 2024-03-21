# Getting started

Xiaomi IoT devices protocol

# Usage

### MiIO protocol

#### Example

```go

device := miio.NewDevice("address","token")
if err := device.Dial(context.Background());err != nil{
	return
}
defer device.Close()

if info,err := device.Info(context.Background());err == nil{
	fmt.Println(info)
}

```

#### Method

* **Info** Get device info
* **GetAttributes** Get device props
* **GetProperties** Get device properties
* **SetProperties** Set device properties
* **Action** Execute device action
* **Execute** Execute command


### Mi Cloud

#### Example

```go
client := cloud.New("country","username","password")

if err = client.Login(context.Background());err != nil {
	return
}
client.GetHomes(context.Background())
```

#### Method

* **Login** Login Mi cloud
* **GetHomes** Get mi homes
* **GetHomeDevices** Get home devices
* **GetDevices** Get all devices
* **GetLastMessage** Get last messages
* **GetSensorHistory** Get sensor histories
* **GetDeviceProps** Get device properties, like `miio` `GetProperties`
* **SetDeviceProps** Set device properties, like `miio` `SetProperties`
* **ExecuteDeviceAction** Execute device action, like `miio` `Action`
* **Request** do http request


### Command

build command 

```shell
go build -o bin/miio cmd/main.go
```

`miio` command help

```shell
$ miio --help

miio an analog terminal that implements miio, capable of obtaining properties and sending instructions

Usage:
  miio [command]

Available Commands:
  action         Do device action
  completion     Generate the autocompletion script for the specified shell
  execute        Execute device command
  get_properties Get device properties
  help           Help about any command
  info           Show device info
  parse_pcap     Parse pcap filename
  set_properties Set device properties

Flags:
  -h, --help           help for miio
      --ip string      device address
      --token string   device token

Use "miio [command] --help" for more information about a command.
```

## Protocl

Check full protocol specs [here](https://github.com/OpenMiHome/mihome-binary-protocol).