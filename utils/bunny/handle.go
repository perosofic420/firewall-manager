package bunny

import (
	"os"
	"log"
	"time"
	"context"
	"os/exec"
	"sync/atomic"
	"path/filepath"
	"encoding/json/v2"

	"firewall_manager/utils/compare"
	commands_ipset "firewall_manager/utils/commands/ipset"
)

func handle() {
	//path to cached IPs, used if the app fails to grab them
	currentDir, err := os.Getwd()
	if err != nil {
		log.Println(err)
		return
	}
	bunnyV4Path := filepath.Join(currentDir, "bunny-v4.json")
	bunnyV6Path := filepath.Join(currentDir, "bunny-v6.json")

	//request ips
	v4IPs, err := GetV4IPs()
	if err == nil {
		//save to disk on success
		data, err := json.Marshal(v4IPs)
		if err != nil {
			log.Println(err)
			return
		}

		if err := os.WriteFile(bunnyV4Path, data, 0644); err != nil {
			log.Println(err)
			return
		}
	} else {
		//failed to grab, check disk for fallback
		file, err := os.ReadFile(bunnyV4Path)
		if err == nil {
			if err := json.Unmarshal(file, &v4IPs, json.MatchCaseInsensitiveNames(true)); err != nil {
				log.Println(err)
				return
			}
		} else {
			//fall back to cdn
			v4IPs, err = GetFallbackV4IPs()
			if err != nil {
				log.Println(err)
				return
			}
		}
	}

	v6IPs, err := GetV6IPs()
	if err == nil {
		//save to disk on success
		data, err := json.Marshal(v6IPs)
		if err != nil {
			log.Println(err)
			return
		}

		if err := os.WriteFile(bunnyV6Path, data, 0644); err != nil {
			log.Println(err)
			return
		}
	} else {
		//failed to grab, check disk for fallback
		file, err := os.ReadFile(bunnyV6Path)
		if err == nil {
			if err := json.Unmarshal(file, &v6IPs, json.MatchCaseInsensitiveNames(true)); err != nil {
				log.Println(err)
				return
			}
		} else {
			//fall back to cdn
			v6IPs, err = GetFallbackV6IPs()
			if err != nil {
				log.Println(err)
				return
			}
		}
	}

	//create ipsets
	createBunnyV4IpsetCmdStr := commands_ipset.FormCreate("bunny-v4", false)
	createBunnyV4IpsetCmd := exec.Command("sh", "-c", createBunnyV4IpsetCmdStr)
	if err := createBunnyV4IpsetCmd.Run(); err != nil {
		log.Println(err)
		return
	}

	createBunnyV6IpsetCmdStr := commands_ipset.FormCreate("bunny-v6", true)
	createBunnyV6IpsetCmd := exec.Command("sh", "-c", createBunnyV6IpsetCmdStr)
	if err := createBunnyV6IpsetCmd.Run(); err != nil {
		log.Println(err)
		return
	}

	//get current ipset list
	currentBunnyV4IPs, err := commands_ipset.GetIPsFromIpset("bunny-v4")
	if err != nil {
		log.Println(err)
		return
	}
	currentBunnyV6IPs, err := commands_ipset.GetIPsFromIpset("bunny-v6")
	if err != nil {
		log.Println(err)
		return
	}

	//compare IPs, add/delete as needed
	addedV4IPs, removedV4IPs := compare.IPs(currentBunnyV4IPs, v4IPs)
	addedV6IPs, removedV6IPs := compare.IPs(currentBunnyV6IPs, v6IPs)

	for _, ip := range(removedV4IPs) {
		deleteIpCmdStr := commands_ipset.FormDelete("bunny-v4", ip)
		deleteIpCmd := exec.Command("sh", "-c", deleteIpCmdStr)
		if err := deleteIpCmd.Run(); err != nil {
			log.Println(err)
		}
	}
	for _, ip := range(removedV6IPs) {
		deleteIpCmdStr := commands_ipset.FormDelete("bunny-v6", ip)
		deleteIpCmd := exec.Command("sh", "-c", deleteIpCmdStr)
		if err := deleteIpCmd.Run(); err != nil {
			log.Println(err)
		}
	}

	for _, ip := range(addedV4IPs) {
		addIpCmdStr := commands_ipset.FormAdd("bunny-v4", ip)
		addIpCmd := exec.Command("sh", "-c", addIpCmdStr)
		if err := addIpCmd.Run(); err != nil {
			log.Println(err)
		}
	}
	for _, ip := range(addedV6IPs) {
		addIpCmdStr := commands_ipset.FormAdd("bunny-v6", ip)
		addIpCmd := exec.Command("sh", "-c", addIpCmdStr)
		if err := addIpCmd.Run(); err != nil {
			log.Println(err)
		}
	}
}

var ipSetsStarted int32

func HandleIPSets(ctx context.Context) {
	//guard so this can't be ran more than once
	if !atomic.CompareAndSwapInt32(&ipSetsStarted, 0, 1) {
		log.Println("bunny.HandleIPSets already running, ignoring duplicate start")
		return
	}

	//handle ipsets
	handle()
	
	//setup ticker to handle them every 5 minutes
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			handle()
		}
	}
}
