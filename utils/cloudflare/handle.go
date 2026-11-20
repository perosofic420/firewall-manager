package cloudflare

import (
	"os"
	"log"
	"time"
	"os/exec"
	"context"
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
	cfV4Path := filepath.Join(currentDir, "cloudflare-v4.json")
	cfV6Path := filepath.Join(currentDir, "cloudflare-v6.json")

	//request ips
	v4IPs, err := GetV4IPs()
	if err == nil {
		//save to disk on success
		data, err := json.Marshal(v4IPs)
		if err != nil {
			log.Println(err)
			return
		}

		if err := os.WriteFile(cfV4Path, data, 0644); err != nil {
			log.Println(err)
			return
		}
	} else {
		//failed to grab, check disk for fallback
		file, err := os.ReadFile(cfV4Path)
		if err == nil {
			if err := json.Unmarshal(file, &v4IPs, json.MatchCaseInsensitiveNames(true)); err != nil {
				log.Println(err)
				return
			}
		} else {
			log.Println(err)
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

		if err := os.WriteFile(cfV6Path, data, 0644); err != nil {
			log.Println(err)
			return
		}
	} else {
		//failed to grab, check disk for fallback
		file, err := os.ReadFile(cfV6Path)
		if err == nil {
			if err := json.Unmarshal(file, &v6IPs, json.MatchCaseInsensitiveNames(true)); err != nil {
				log.Println(err)
				return
			}
		} else {
			log.Println(err)
			//fall back to cdn
			v6IPs, err = GetFallbackV6IPs()
			if err != nil {
				log.Println(err)
				return
			}
		}
	}
	
	//create ipsets
	createCfV4IpsetCmdStr := commands_ipset.FormCreate("cloudflare-v4", false)
	createCfV4IpsetCmd := exec.Command("sh", "-c", createCfV4IpsetCmdStr)
	if err := createCfV4IpsetCmd.Run(); err != nil {
		log.Println(err)
		return
	}
	
	createCfV6IpsetCmdStr := commands_ipset.FormCreate("cloudflare-v6", true)
	createCfV6IpsetCmd := exec.Command("sh", "-c", createCfV6IpsetCmdStr)
	if err := createCfV6IpsetCmd.Run(); err != nil {
		log.Println(err)
		return
	}

	//get current ipset list
	currentCfV4IPs, err := commands_ipset.GetIPsFromIpset("cloudflare-v4")
	if err != nil {
		log.Println(err)
		return
	}
	currentCfV6IPs, err := commands_ipset.GetIPsFromIpset("cloudflare-v6")
	if err != nil {
		log.Println(err)
		return
	}

	//compare IPs, add/delete as needed
	addedV4IPs, removedV4IPs := compare.IPs(currentCfV4IPs, v4IPs)
	addedV6IPs, removedV6IPs := compare.IPs(currentCfV6IPs, v6IPs)

	for _, ip := range(removedV4IPs) {
		deleteIpCmdStr := commands_ipset.FormDelete("cloudflare-v4", ip)
		deleteIpCmd := exec.Command("sh", "-c", deleteIpCmdStr)
		if err := deleteIpCmd.Run(); err != nil {
			log.Println(err)
		}
	}
	for _, ip := range(removedV6IPs) {
		deleteIpCmdStr := commands_ipset.FormDelete("cloudflare-v6", ip)
		deleteIpCmd := exec.Command("sh", "-c", deleteIpCmdStr)
		if err := deleteIpCmd.Run(); err != nil {
			log.Println(err)
		}
	}

	for _, ip := range(addedV4IPs) {
		addIpCmdStr := commands_ipset.FormAdd("cloudflare-v4", ip)
		addIpCmd := exec.Command("sh", "-c", addIpCmdStr)
		if err := addIpCmd.Run(); err != nil {
			log.Println(err)
		}
	}
	for _, ip := range(addedV6IPs) {
		addIpCmdStr := commands_ipset.FormAdd("cloudflare-v6", ip)
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
		log.Println("cloudflare.HandleIPSets already running, ignoring duplicate start")
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
