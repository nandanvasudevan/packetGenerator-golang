package main

/*
#cgo CFLAGS: -I D:/Code/third-party/npcap-sdk-1.16/Include
#cgo LDFLAGS: -L D:/Code/third-party/npcap-sdk-1.16/Lib/x64 -lwpcap
#include <pcap.h>
*/
import "C"

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var infoLogger = log.New(os.Stdout, " INFO: ", log.LstdFlags)
var errorLogger = log.New(os.Stderr, "ERROR: ", log.LstdFlags|log.Lshortfile)

func defaultMac() net.HardwareAddr {
	return net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
}

func defaultIP() net.IP {
	return net.IPv4(255, 255, 255, 255)
}

func HardwareAddr() net.HardwareAddr {
	return net.HardwareAddr{0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
}

func IPv4() net.IP {
	return net.IPv4(0x0, 0x0, 0x0, 0x0)
}

func udpGenerator(ctx context.Context, handle *pcap.Handle, localIp net.IP, localHwAddr net.HardwareAddr, destIp net.IP, destHwAddr net.HardwareAddr) {
	infoLogger.Printf("Starting UDP generator to %s\n", destIp.String())

	var packetCount uint64 = 0

	eth := &layers.Ethernet{
		SrcMAC:       localHwAddr,
		DstMAC:       destHwAddr,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    localIp,
		DstIP:    destIp,
		Protocol: layers.IPProtocolUDP,
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(12345),
		DstPort: layers.UDPPort(9999),
	}
	// CRITICAL: UDP checksums require the IP header info
	udp.SetNetworkLayerForChecksum(ip)

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			infoLogger.Printf("Generated %d packets\n", packetCount)
			infoLogger.Println("Shutting down generator...")
			return
		case <-ticker.C:
			payload := []byte(fmt.Sprintf("GEN_PKT_%d", packetCount))
			packetCount++
			sendPacket(handle,
				eth,
				ip,
				udp,
				gopacket.Payload(payload))
		}
	}
}

func sendPacket(handle *pcap.Handle, layers ...gopacket.SerializableLayer) error {
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buffer, opts, layers...)

	if err != nil {
		return fmt.Errorf("sendPacket() Serialization failed. Error: %w", err)
	}

	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		return fmt.Errorf("sendPacket() WritePacketData failed. Error: %w", err)
	}

	return nil
}

func arpGetDestMac(handle *pcap.Handle, hardwareAddr net.HardwareAddr, ip net.IP, destIp net.IP) (resolvedMac net.HardwareAddr, err error) {
	infoLogger.Println("ARP request to get HW Addr for", destIp.String())

	eth := &layers.Ethernet{
		SrcMAC:       hardwareAddr,
		DstMAC:       defaultMac(),
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     uint8(len(defaultMac())),
		ProtAddressSize:   uint8(len(defaultIP().To4())),
		Operation:         layers.ARPRequest,
		SourceHwAddress:   hardwareAddr,
		SourceProtAddress: ip,
		DstHwAddress:      HardwareAddr(),
		DstProtAddress:    destIp.To4(),
	}

	dstHardwareChannel := make(chan net.HardwareAddr)

	go func() {
		source := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range source.Packets() {
			// 1. Search for ARP layer in this packet
			arpLayer := packet.Layer(layers.LayerTypeARP)

			if arpLayer != nil {
				arp := arpLayer.(*layers.ARP)

				// 2. Check if it is a reply from destIp
				if arp.Operation == layers.ARPReply && bytes.Equal(arp.SourceProtAddress, destIp.To4()) {
					// 3. Success! Extract the MAC and exit goroutine
					dstHardwareChannel <- net.HardwareAddr(arp.DstHwAddress)
					return
				}
			}
		}
	}()

	err = sendPacket(handle, eth, arp)

	if err != nil {
		return defaultMac(), fmt.Errorf("arpGetDestMac() No interfaces found! Error: %w", err)
	}

	select {
	case resolvedMac = <-dstHardwareChannel:
		infoLogger.Printf("Resolved MAC for %s: %s\n", destIp.String(), resolvedMac.String())
		return resolvedMac, nil
	case <-time.After(2 * time.Second):
		return defaultMac(), fmt.Errorf("arpGetDestMac() ARP request timeout!")
	}
}

func getLocalHwAddr(ifName string) (localHwAddr net.HardwareAddr, err error) {
	netIfs, err := net.Interfaces()
	if err != nil {
		return defaultMac(), fmt.Errorf("getLocalHwAddr() No interfaces found! Error: %w", err)
	}

	for _, netIf := range netIfs {
		if ifName == netIf.Name {
			localHwAddr = netIf.HardwareAddr
			infoLogger.Printf("MAC for %s: %s\n\n", ifName, localHwAddr.String())
		}
	}

	return localHwAddr, err
}

func getLocalIp() (deviceName string, localIp net.IP, err error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", defaultIP(), fmt.Errorf("getLocalIp() NPCAP not found! Please install it. Error: %w", err)
	}

	infoLogger.Println("Device count: ", len(devices))

	for _, device := range devices {
		if "Intel(R) Wi-Fi 6 AX201 160MHz" == device.Description {
			deviceName = device.Name
			infoLogger.Printf("            Name: %s\n", device.Name)
			infoLogger.Printf("     Description: %s\n", device.Description)
			infoLogger.Printf("              IP: %s\n", device.Addresses[0].IP.String())
			localIp = device.Addresses[0].IP
		}
	}

	return deviceName, localIp, nil
}

func run() (err error) {
	
	const ifName string = "Wi-Fi"
	var localHwAddrBytes net.HardwareAddr

	deviceName, localIp, err := getLocalIp()
	if err != nil {
		return fmt.Errorf("run() IP lookup failed. Error: %w", err)
	}

	localHwAddrBytes, err = getLocalHwAddr(ifName)
	if err != nil {
		return fmt.Errorf("run() MAC lookup failed. Error: %w", err)
	}

	handle, err := pcap.OpenLive(deviceName, 1024, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 3. Handle Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		infoLogger.Println("[Ctrl+C] Received, shutting down...")
		cancel() // Manually trigger the context cancellation
	}()

	destIp := net.IPv4(192, 168, 1, 1)
	destHwAddr, err := arpGetDestMac(handle, localHwAddrBytes, localIp, destIp)
	if err != nil {
		return fmt.Errorf("run() Could not locate MAC for %s", destIp)
	}

	udpGenerator(ctx, handle, localIp, localHwAddrBytes, destIp, destHwAddr)

	infoLogger.Println("Generator done.")

	return nil
}

func main() {
	err := run()

	if err != nil {
		errorLogger.Fatal(err)
	}
}
