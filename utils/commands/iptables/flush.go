package iptables

import (
	"log"
	"os/exec"
)

func FlushIptables() {
	commandList := []string{
		//set default policies to ACCEPT first
        "iptables -P INPUT ACCEPT",
        "iptables -P FORWARD ACCEPT",
        "iptables -P OUTPUT ACCEPT",
        "ip6tables -P INPUT ACCEPT",
        "ip6tables -P FORWARD ACCEPT",
        "ip6tables -P OUTPUT ACCEPT",
        
        //flush all existing rules
        "iptables -t filter -F",
        "iptables -t nat -F",
        "iptables -t mangle -F",
        "iptables -t raw -F",
        "ip6tables -t filter -F",
        "ip6tables -t nat -F",
        "ip6tables -t mangle -F",
        "ip6tables -t raw -F",

        "iptables -t filter -X",
        "iptables -t nat -X",
        "iptables -t mangle -X",
        "iptables -t raw -X",
        "ip6tables -t filter -X",
        "ip6tables -t nat -X",
        "ip6tables -t mangle -X",
        "ip6tables -t raw -X",
	}

	for _, cmdStr := range(commandList) {
		log.Printf("Executing command: %s", cmdStr)
		
		cmd := exec.Command("sh", "-c", cmdStr)
		if err := cmd.Run(); err != nil {
			log.Println(err)
		}
	}
}
