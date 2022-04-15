package ads

import (
	"bufio"
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	DNS_QUEUE  = 0
	QUEUE_SIZE = 50
)

type AdBlock struct{}

type pktProcessFn func(gopacket.Packet) (int, bool)

//
func NewAds(ctx context.Context, adservers string) {
	addDnsDropTable()
	defer deleteDnsDropTable()

	// upload block list
	db := blockListUpdate(adservers)
	if db == nil {
		return
	}

	nfqctx, nfqCancel := context.WithCancel(ctx)
	defer nfqCancel()

	nfq := registerNFQ(nfqctx,
		func(pkt gopacket.Packet) (int, bool) {
			return processDNSPacket(pkt, db)
		})
	if nfq == nil {
		log.Print("unable to register nfq")
		return
	}
	defer nfq.Close()

	<-ctx.Done()
}

//
func blockListUpdate(adservers string) map[string]AdBlock {
	resp, err := http.Get(adservers)
	if err != nil {
		log.Print("Unable to sent GET req to ", adservers, " err:", err)
		return nil
	}
	if resp.StatusCode >= 300 {
		log.Print("Got ", resp.StatusCode, " not successful")
		return nil
	}

	db := make(map[string]AdBlock, 2000)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		url, blk, ok := urlFromLine_StevenBlack(line)
		if ok {
			db[url] = blk
		}
	}
	log.Printf("Added %d urls", len(db))

	return db
}

//
func registerNFQ(ctx context.Context, fn pktProcessFn) *nfqueue.Nfqueue {
	config := nfqueue.Config{
		NfQueue:      DNS_QUEUE,
		MaxPacketLen: 3000,
		MaxQueueLen:  QUEUE_SIZE,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
		Logger:       log.Default(),
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		log.Print("could not open nfqueue socket:", err)
		return nil
	}

	err = nf.RegisterWithErrorFunc(ctx,
		// HookFunc
		func(a nfqueue.Attribute) int {
			return hookFn(nf, a, fn)
		},
		// ErrorFunc
		func(e error) int {
			if err != nil {
				log.Print("ErrFN: ", err)
			}
			return 0
		})

	if err != nil {
		log.Print("could not register fn", err)
		return nil
	}

	return nf
}

// Nfqueue HookFunc
func hookFn(nf *nfqueue.Nfqueue, a nfqueue.Attribute, fn pktProcessFn) int {
	if a.PacketID == nil {
		log.Print("Unable to deref Packet details")
		return 0
	}

	id := *a.PacketID

	if a.Payload == nil {
		log.Print("Unable to deref Packet details")
		err := nf.SetVerdict(id, nfqueue.NfAccept)
		if err != nil {
			log.Print("SetVerdict err", err)
		}
		return 0
	}

	payload := *a.Payload
	var decoder gopacket.Decoder

	if payload[0]&0xf0 == 0x40 {
		decoder = layers.LayerTypeIPv4
	} else {
		decoder = layers.LayerTypeIPv6
	}

	pkt := gopacket.NewPacket(payload, decoder, gopacket.DecodeOptions{Lazy: true, NoCopy: true})

	verdict, mod := fn(pkt)
	if mod {
		//
	}

	if mod {
		err := nf.SetVerdictModPacket(id, verdict, pkt.Data())
		if err != nil {
			log.Print("SetVerdictModPacket err", err)
		}
	} else {
		err := nf.SetVerdict(id, verdict)
		if err != nil {
			log.Print("SetVerdict err", err)
		}
	}

	return 0
}

//
func processDNSPacket(pkt gopacket.Packet, db map[string]AdBlock) (int, bool) {
	modified := false
	log.Print("got a pkt")

	switch proto := pkt.ApplicationLayer().(type) {
	case *layers.DNS:
		for i, ans := range proto.Answers {
			url := strings.TrimSpace(string(ans.Name))
			log.Println("Question", i, ":", url)

			if isBlockedURL(url, db) {
				log.Println("Blocked ", url)
			}

			if ans.IP.To4() != nil {
				ans.IP = net.IPv4zero
				modified = true
			}
		}

		if modified {
			// update packet len and checksums since it was changed
			pkt.TransportLayer().(*layers.UDP).SetNetworkLayerForChecksum(pkt.NetworkLayer())
			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{
				ComputeChecksums: true,
				FixLengths:       true,
			}

			if err := gopacket.SerializePacket(buffer, options, pkt); err != nil {
				log.Print("Serializing modified packet failed", err)
				return nfqueue.NfDrop, false
			}
		}
	}

	return nfqueue.NfAccept, modified
}

//
func isBlockedURL(url string, db map[string]AdBlock) bool {
	_, ok := db[url]
	return ok
}

//
func urlFromLine_StevenBlack(line string) (string, AdBlock, bool) {
	line = strings.TrimSpace(line)

	if strings.HasPrefix(line, "0.0.0.0 ") {
		url := strings.TrimPrefix(line, "0.0.0.0 ")
		return url, AdBlock{}, true
	}

	return "", AdBlock{}, false
}

//
//func urlFromLine_EasyList(line string) (string, AdBlock, bool) {
func _(line string) (string, AdBlock, bool) {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "||") {
		line = strings.TrimPrefix(line, "||")
		if strings.HasSuffix(line, "^") {
			url := strings.TrimSuffix(line, "^")
			return url, AdBlock{}, true
		}
		if strings.HasSuffix(line, "^$third-party") {
			url := strings.TrimSuffix(line, "^$third-party")
			return url, AdBlock{}, true
		}
	}

	return "", AdBlock{}, false
}
