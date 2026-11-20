package iptables

import "fmt"

func GetDefaultPolicyCommands(policy string) ([]IptableCommands, error) {
	switch policy {
	case "allow_all":
		return []IptableCommands{
			{
				V4: "iptables -P INPUT ACCEPT",
				V6: "ip6tables -P INPUT ACCEPT",
			},
			{
				V4: "iptables -P OUTPUT ACCEPT",
				V6: "ip6tables -P OUTPUT ACCEPT",
			},
		}, nil

	case "deny_all":
		return []IptableCommands{
			{
				V4: "iptables -P INPUT DROP",
				V6: "ip6tables -P INPUT DROP",
			},
			{
				V4: "iptables -P OUTPUT ACCEPT",
				V6: "ip6tables -P OUTPUT ACCEPT",
			},
		}, nil

	case "reject_all":
		return []IptableCommands{
			{
				V4: "iptables -P INPUT REJECT",
				V6: "ip6tables -P INPUT REJECT",
			},
			{
				V4: "iptables -P OUTPUT ACCEPT",
				V6: "ip6tables -P OUTPUT ACCEPT",
			},
		}, nil

	default:
		return nil, fmt.Errorf("invalid default policy: %s", policy)
	}
}
