package ads

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

//
func addDnsDropTable() {
	conf := fmt.Sprintf(`
table inet dns_drop {
}
delete table inet dns_drop
table inet dns_drop {
	chain c_pre {
		type filter hook prerouting priority filter; policy accept;
		meta l4proto udp udp sport 53 queue num %[1]d bypass
	}
}
`, DNS_QUEUE)

	runNft(conf)
}

//
func deleteDnsDropTable() {
	runNft(`
delete table inet dns_drop
`)
}

//
func runNft(config string) {
	f, err := os.CreateTemp("", "ads-*.nft")
	if err != nil {
		log.Print("Error creating a temp file", err)
		return
	}
	defer f.Close()

	_, err = f.Write([]byte(config))
	if err != nil {
		log.Print("Error writing config", err)
		return
	}
	f.Close()

	cmd := exec.Command("nft", "-f", f.Name())

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Print("Error running nft", config,
			"\n---- ouput:", string(output),
			"\n---- error:", err)
		return
	}
}
