package main

import (
	"crypto/md5"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/larspensjo/config"
	"net"
	"os"
	"runtime"
	"time"
)

/* 发送EAPOL包 */
func sendEAPOL(Version byte, Type layers.EAPOLType, SrcMAC net.HardwareAddr, DstMAC net.HardwareAddr) {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{EthernetType: layers.EthernetTypeEAPOL, SrcMAC: SrcMAC, DstMAC: DstMAC},
		&layers.EAPOL{Version: 0x01, Type: layers.EAPOLTypeStart},
	)
	//var err error
	err := handle.WritePacketData(buffer.Bytes())
	if err != nil {
		fmt.Print(err)
		os.Exit(0)
	}
}

/* 发送EAP包 */
func sendEAP(Id uint8, Type layers.EAPType, TypeData []byte, Code layers.EAPCode, SrcMAC net.HardwareAddr, DstMAC net.HardwareAddr) {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{EthernetType: layers.EthernetTypeEAPOL, SrcMAC: SrcMAC, DstMAC: DstMAC},
		&layers.EAPOL{Version: 0x01, Type: layers.EAPOLTypeEAP, Length: uint16(len(TypeData) + 5)},
		&layers.EAP{Id: Id, Type: Type, TypeData: TypeData, Code: Code, Length: uint16(len(TypeData) + 5)},
	)
	// err error
	err := handle.WritePacketData(buffer.Bytes())
	if err != nil {
		fmt.Print(err)
		os.Exit(0)
	}
}

/* 读取新数据包 */
func readNewPacket(packetSrc *gopacket.PacketSource) {
	for packet := range packetSrc.Packets() {
		eapl := packet.Layer(layers.LayerTypeEAP)
		if eapl != nil {
			switch eapl.(*layers.EAP).Code {
			case 0x03: //Success
				fmt.Println("Success")
				//sendPingStart()
			case 0x01: //Request
				switch int8(eapl.(*layers.EAP).Type) {
				case 0x04: //EAP-MD5-CHALLENGE
					//fmt.Println(eapl.(*layers.EAP).TypeData)
					go responseMd5Challenge(eapl.(*layers.EAP).TypeData[1:17])
				case 0x02: //Notification
					fmt.Println("Failed")
					os.Exit(0)
				case 0x01: //Identity
					//fmt.Print("TRUE")
					go responseIndentity(eapl.(*layers.EAP).Id)
				}
			case 0x04: //Failure
				fmt.Println("Failed")
				fmt.Println("Retry...")
				EAPAuth()
			}

		}
	}

	end <- true
}

/* EAP认证开始 */
func EAPAuth() {
	fmt.Println(mac)
	fmt.Println("EAP Start...")
	sendEAPOL(0x01, layers.EAPOLTypeStart, mac, boardCastAddr)
}

/* EAP注销 */
func EAPLogoff() {
	sendEAPOL(0x01, layers.EAPOLTypeLogOff, mac, boardCastAddr)
	fmt.Println("Logoff...")
}

/* 回应身份(Indentity) */
func responseIndentity(id byte) {
	dataPack := []byte{}
	dataPack = append(dataPack, []byte(username)...)                     //用户名
	dataPack = append(dataPack, []byte{0x00, 0x44, 0x61, 0x00, 0x00}...) //未知
	dataPack = append(dataPack, ip[:]...)                                //客户端IP
	fmt.Println("Response Identity...")
	sendEAP(id, 0x01, dataPack, 2, mac, boardCastAddr)
}

/* 回应MD5-Challenge */
func responseMd5Challenge(m []byte) {
	mPack := []byte{}
	mPack = append(mPack, 0)
	mPack = append(mPack, []byte(password)...)
	mPack = append(mPack, m...)
	mCal := md5.New()
	mCal.Write(mPack)
	dataPack := []byte{}
	dataPack = append(dataPack, 16)
	dataPack = append(dataPack, mCal.Sum(nil)...)
	dataPack = append(dataPack, []byte(username)...)
	dataPack = append(dataPack, []byte{0x00, 0x44, 0x61, 0x26, 0x00}...)
	dataPack = append(dataPack, []byte(ip[:])...)
	challenge = mCal.Sum(nil) //用于后面心跳包
	fmt.Println("Response EAP-MD5-Challenge...")
	sendEAP(0, 0x04, dataPack, 2, mac, boardCastAddr)
}

type myCfg struct {
	*config.Config
}

var (
	ip       [4]byte
	mac      net.HardwareAddr
	dns1     byte
	dns2     byte
	username string
	password string
)

var err error
var handle *pcap.Handle
var end chan bool
var boardCastAddr net.HardwareAddr

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
		cfg.save()
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
	var tmpInterface *net.Interface
	switch runtime.GOOS {
	case "windows":
		tmpInterface, err = net.InterfaceByName(dev[12:])
	default:
		tmpInterface, err = net.InterfaceByName(dev)
	}

	checkError(err)
	mac = tmpInterface.HardwareAddr
	ipStr, _ := tmpInterface.Addrs()
	fmt.Sscanf(ipStr[0].String(), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	boardCastAddr = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	handle, err = pcap.OpenLive(dev, 1024, false, 30*time.Second)
	fmt.Println(dev)
	checkError(err)

	EAPAuth()

	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	go readNewPacket(packetSrc)

	<-end
}
