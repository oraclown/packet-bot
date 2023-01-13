package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var filter = flag.String("filter", "", "BPF filter for capture")
var iface = flag.String("iface", "en0", "Select interface where to capture packets from")
var snaplen = flag.Int("snaplen", 1600, "Maximum size to read for each packet")
var promisc = flag.Bool("promisc", false, "Enable promiscuous mode")
var timeoutT = flag.Int("timeout", 30, "Connection timeout in seconds")

func main() {
	log.Println("Starting packet capture")
	defer log.Println("Stopping packet capture")

	flag.Parse()

	var timeout time.Duration = time.Duration(*timeoutT) * time.Second

	// Open device
	handle, err := pcap.OpenLive(*iface, int32(*snaplen), *promisc, timeout)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	// Apply filter if exists
	if *filter != "" {
		log.Println("applying filter", *filter)
		err := handle.SetBPFFilter(*filter)
		if err != nil {
			log.Fatalf("Error applying filter: %s - %v", *filter, err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
}
