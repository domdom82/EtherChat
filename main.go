package main

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/jessevdk/go-flags"
	"net"
	"os"
	"strings"
	"sync"
)

var errNoChatMsg = errors.New("not a chat message")
var errNoEthernet = errors.New("no ethernet packet")
var errSelfMessage = errors.New("self message")

type Options struct {
	Interface string `short:"i" long:"interface" description:"Interface to listen on" required:"true"`
}

func main() {
	var opts Options

	p := flags.NewParser(&opts, flags.Default)
	_, err := p.Parse()
	if err != nil {
		os.Exit(1)
	}
	handle, err := pcap.OpenLive(opts.Interface, 65535, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	nic, err := net.InterfaceByName(opts.Interface)
	if err != nil {
		panic(err)
	}

	srcMac := nic.HardwareAddr

	wg := &sync.WaitGroup{}
	wg.Add(2)
	go readChat(handle, srcMac, wg)
	go writeChat(handle, srcMac, wg)

	wg.Wait()
}

func readChat(handle *pcap.Handle, srcMac net.HardwareAddr, wg *sync.WaitGroup) {
	defer wg.Done()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	for packet := range packets {
		msg, err := readChatMsg(packet, srcMac)
		if err != nil {
			continue
		}
		fmt.Printf("\r< %s", msg)
	}

}
func readChatMsg(packet gopacket.Packet, srcMac net.HardwareAddr) (msg string, err error) {
	var eth *layers.Ethernet

	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		eth, _ = ethernetLayer.(*layers.Ethernet)
	}

	if eth == nil {
		return "", errNoEthernet
	}

	msg = string(eth.LayerPayload())

	if !strings.HasPrefix(msg, "CHAT ") {
		return "", errNoChatMsg
	}

	if eth.SrcMAC.String() == srcMac.String() {
		return "", errSelfMessage
	}

	msg = strings.TrimPrefix(msg, "CHAT ")

	msgString := fmt.Sprintf("(%s) %s", eth.SrcMAC.String(), msg)

	return msgString, nil
}

func writeChat(handle *pcap.Handle, srcMac net.HardwareAddr, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		fmt.Printf("\r> ")
		r := bufio.NewReader(os.Stdin)
		message, err := r.ReadString('\n')
		if err != nil {
			break
		}
		// ignore empty messages
		if message == "\n" {
			continue
		}
		msgPkt, err := generateMessagePacket(message, srcMac)
		if err != nil {
			fmt.Println(err.Error())
			break
		}
		err = handle.WritePacketData(msgPkt.Data())

		if err != nil {
			fmt.Println(err.Error())
			break
		}
	}

}

func generateMessagePacket(msg string, srcMac net.HardwareAddr) (msgPkt gopacket.Packet, err error) {
	var eth = &layers.Ethernet{}

	msgString := fmt.Sprintf("CHAT %s", msg)
	msgPacket := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	var pktLayers []gopacket.SerializableLayer

	eth.EthernetType = layers.EthernetTypeLLC
	eth.SrcMAC = srcMac
	eth.DstMAC, err = net.ParseMAC("FF:FF:FF:FF:FF:FF")
	if err != nil {
		panic(err)
	}

	pktLayers = append(pktLayers, eth)
	pktLayers = append(pktLayers, gopacket.Payload(msgString))

	err = gopacket.SerializeLayers(msgPacket, opts, pktLayers...)
	if err != nil {
		return nil, err
	}

	msgPkt = gopacket.NewPacket(msgPacket.Bytes(), pktLayers[0].LayerType(), gopacket.Default)
	return msgPkt, nil
}
