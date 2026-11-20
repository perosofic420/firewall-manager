package iptables

import (
	"fmt"
)

func FormCommand(protocol string, port int, policy string, ipset_v4_name string, ipset_v6_name string) (*IptableCommands, error) {
	//verify protocol 
	if (protocol != "udp" && protocol != "tcp") {
		return nil, fmt.Errorf("Invalid protocol")
	}

	var command *IptableCommands

	switch policy {
	case "cloudflare_only": {
		//set command
		iptCmd := IptableCommands{
			V4: fmt.Sprintf("iptables -A INPUT -p %s -m %s --dport %d -m set --match-set cloudflare-v4 src -j ACCEPT", protocol, protocol, port),
			V6: fmt.Sprintf("ip6tables -A INPUT -p %s -m %s --dport %d -m set --match-set cloudflare-v6 src -j ACCEPT", protocol, protocol, port),
		}
		command = &iptCmd
		break
	}
	case "bunny_only": {
		//set command
		iptCmd := IptableCommands{
			V4: fmt.Sprintf("iptables -A INPUT -p %s -m %s --dport %d -m set --match-set bunny-v4 src -j ACCEPT", protocol, protocol, port),
			V6: fmt.Sprintf("ip6tables -A INPUT -p %s -m %s --dport %d -m set --match-set bunny-v6 src -j ACCEPT", protocol, protocol, port),
		}
		command = &iptCmd
		break
	}
	case "allow_all": {
		//set command
		iptCmd := IptableCommands{
			V4: fmt.Sprintf("iptables -A INPUT -p %s -m %s --dport %d -j ACCEPT", protocol, protocol, port),
			V6: fmt.Sprintf("ip6tables -A INPUT -p %s -m %s --dport %d -j ACCEPT", protocol, protocol, port),
		}
		command = &iptCmd
		break
	}
	case "deny_all": {
		//set command
		iptCmd := IptableCommands{
			V4: fmt.Sprintf("iptables -A INPUT -p %s -m %s --dport %d -j DROP", protocol, protocol, port),
			V6: fmt.Sprintf("ip6tables -A INPUT -p %s -m %s --dport %d -j DROP", protocol, protocol, port),
		}
		command = &iptCmd
		break
	}
	case "filter_by_ipset": {
		//set command
		iptCmd := IptableCommands{
			V4: fmt.Sprintf("iptables -A INPUT -p %s -m %s --dport %d -m set --match-set %s src -j ACCEPT", protocol, protocol, port, ipset_v4_name),
			V6: fmt.Sprintf("ip6tables -A INPUT -p %s -m %s --dport %d -m set --match-set %s src -j ACCEPT", protocol, protocol, port, ipset_v6_name),
		}
		command = &iptCmd
		break
	}
	default: {
		return nil, fmt.Errorf("Invalid policy")
		break
	}
	}

	return command, nil
}
