package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/larspensjo/config"
	"net"
	"os"
	"runtime"
	"time"
)

type myCfg struct {
	*config.Config
}

var (
	clientip [4]byte
	mac      net.HardwareAddr
	dns1     byte
	dns2     byte
	username string
	password string
)

var (
	udpConn *net.UDPConn
)

var err error
var handle *pcap.Handle
var end chan bool
var boardCastAddr net.HardwareAddr
var serverip [4]byte

var (
	challenge []byte
)

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
}

func (cfg *myCfg) getOption(section string, option string, empty bool) string {
	if cfg.HasOption(section, option) == false {
		if empty {
			return ""
		} else {
			fmt.Printf("Option [%s]%s not Found\n", section, option)
			os.Exit(0)
		}
	}
	result, err := cfg.String(section, option)
	checkError(err)
	return result
}

func (cfg *myCfg) save() {
	cfg.WriteFile("config.ini", os.FileMode(os.O_WRONLY), "goDrClient Config File")
}

func main() {

	end = make(chan bool)
	var c *config.Config

	_, err = os.Stat("config.ini")

	if err == nil {
		c, err = config.ReadDefault("config.ini")
		checkError(err)
	} else {
		c = config.NewDefault()
	}
	cfg := myCfg{c}

	username = cfg.getOption("user", "username", true)
	password = cfg.getOption("user", "password", true)
	if username == "" || password == "" {
		fmt.Print("Username: ")
		fmt.Scan(&username)
		cfg.AddOption("user", "username", username)
		fmt.Print("Password: ")
		fmt.Scan(&password)
		cfg.AddOption("user", "password", password)
	}

devSelect:
	dev := cfg.getOption("client", "dev", true)
	if dev == "" {
		devs, err := pcap.FindAllDevs()
		checkError(err)
		for n, d := range devs {
			fmt.Printf("[%d] %s\n", n+1, d.Description)
		}
		s := 0
		fmt.Scan(&s)
		if s >= 1 && s <= len(devs) {
			cfg.AddOption("client", "dev", devs[s-1].Name)
		}
		goto devSelect
	}
	cfg.save()
	var tmpInterface *net.Interface
	switch runtime.GOOS {
	case "windows":
		tmpInterface, err = net.InterfaceByName(dev[12:])
	default:
		tmpInterface, err = net.InterfaceByName(dev)
	}

	checkError(err)
	mac = tmpInterface.HardwareAddr
	//ipStr, _ := tmpInterface.Addrs()
	//fmt.Sscanf(ipStr[0].String(), "%d.%d.%d.%d", clientip[0], clientip[1], clientip[2], clientip[3])
	clientip = [4]byte{192, 168, 195, 95}
	serverip = [4]byte{192, 168, 127, 129}
	boardCastAddr = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	handle, err = pcap.OpenLive(dev, 1024, false, 30*time.Second)
	fmt.Println(dev)
	checkError(err)

	EAPAuth()

	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	go readNewPacket(packetSrc)

	udpServerAddr, err := net.ResolveUDPAddr("udp4", "192.168.127.129:61440")
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	udpConn, err = net.DialUDP("udp4", nil, udpServerAddr)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	defer udpConn.Close()
	go recvPing()

	<-end
}
