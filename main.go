package main

import (
	"os"
	"log"
	"fmt"
	"regexp"
	"context"
	"syscall"
	"os/exec"
	"os/signal"
	"encoding/json/v2"

	"firewall_manager/utils/config"
	"firewall_manager/utils/commands"
	"firewall_manager/utils/cloudflare"
	"firewall_manager/utils/bunny"
	commands_ipset "firewall_manager/utils/commands/ipset"
	commands_iptables "firewall_manager/utils/commands/iptables"
	commands_docker "firewall_manager/utils/commands/docker"
)

//docker
var dockerRegex = regexp.MustCompile(`^(-N|-A|-I|-P|-j).*DOCKER(-[A-Z0-9-]+)?`)
var dockerBridge0Regex = regexp.MustCompile(`docker0`)

//kubernetes
var kubeRegex = regexp.MustCompile(`^(-N|-A|-I|-P|-j).*KUBE(-[A-Z0-9-]+)?`)
var flannelRegex = regexp.MustCompile(`^(-N|-A|-I|-P|-j).*FLANNEL(-[A-Z0-9-]+)?`)
var cniRegex = regexp.MustCompile(`^(-N|-A|-I|-P|-j).*CNI(-[A-Z0-9-]+)?`)

func main() {
    //make sure dependencies are installed
	err := commands.VerifyDependencies()
	if err != nil {
		log.Fatal(err)
		return
	}

	//get context
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	//handle adding the ipsets
	go cloudflare.HandleIPSets(ctx)
	go bunny.HandleIPSets(ctx)

	//form command list
	ipsetCommandList := []string{}//seperate from iptables ; to make matching rules simpiler
	commandList := []string{
        //drop invalid state
        "iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP",
        "ip6tables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -j DROP",
        "ip6tables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -j DROP",
        
        //allow loopback
        "iptables -A INPUT -i lo -j ACCEPT",
        "ip6tables -A INPUT -i lo -j ACCEPT",
        "iptables -A OUTPUT -o lo -j ACCEPT",
        "ip6tables -A OUTPUT -o lo -j ACCEPT",
        //allow local subnet
        "iptables -A INPUT -s 127.0.0.0/8 -j ACCEPT",
        "ip6tables -A INPUT -s ::1/128 -j ACCEPT",

        //allow established/related connections
        "iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        "ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        "iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        "ip6tables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",

		//allow ICMPv6
		"ip6tables -A INPUT -p ipv6-icmp -j ACCEPT",
	}

	//function to check cmd and insert if it doesn't exist
	appendCommandIfDoesntExist := func(command string) {
		for _, c := range(commandList) {
			if c == command {
				return
			}
		}
		//cmd not found
		commandList = append(commandList, command)
	}

	//get config
	configData, err := config.GetConfig()
	if err != nil {
		log.Fatal(err)
		return
	}

	//process ssh rules
	if configData.SSH.Enabled {
		if configData.SSH.Policy == "filter_by_ipset" {
			ipsetCreateSshV4 := commands_ipset.FormCreate("ssh-v4", false)
			ipsetCommandList = append(ipsetCommandList, ipsetCreateSshV4)

			ipsetCreateSshV6 := commands_ipset.FormCreate("ssh-v6", true)
			ipsetCommandList = append(ipsetCommandList, ipsetCreateSshV6)

			for _, ip := range(configData.SSH.IPSetV4) {
				ipsetAddSshV4 := commands_ipset.FormAdd("ssh-v4", ip)
				ipsetCommandList = append(ipsetCommandList, ipsetAddSshV4)
			}
			for _, ip := range(configData.SSH.IPSetV6) {
				ipsetAddSshV6 := commands_ipset.FormAdd("ssh-v6", ip)
				ipsetCommandList = append(ipsetCommandList, ipsetAddSshV6)
			}

			commandData, err := commands_iptables.FormCommand("tcp", configData.SSH.Port, configData.SSH.Policy, "ssh-v4", "ssh-v6")
			if err != nil {
				log.Fatal(err)
				return
			}
			commandList = append(commandList, commandData.V4)
			commandList = append(commandList, commandData.V6)
		} else {
			commandData, err := commands_iptables.FormCommand("tcp", configData.SSH.Port, configData.SSH.Policy, "", "")
			if err != nil {
				log.Fatal(err)
				return
			}
			commandList = append(commandList, commandData.V4)
			commandList = append(commandList, commandData.V6)
		}
	}

	//process http rules
	if configData.HTTP.Enabled {
		if configData.HTTP.Policy == "filter_by_ipset" {
			ipsetCreateHttpV4 := commands_ipset.FormCreate("http-v4", false)
			ipsetCommandList = append(ipsetCommandList, ipsetCreateHttpV4)

			ipsetCreateHttpV6 := commands_ipset.FormCreate("http-v6", true)
			ipsetCommandList = append(ipsetCommandList, ipsetCreateHttpV6)

			for _, ip := range(configData.HTTP.IPSetV4) {
				ipsetAddHttpV4 := commands_ipset.FormAdd("http-v4", ip)
				ipsetCommandList = append(ipsetCommandList, ipsetAddHttpV4)
			}
			for _, ip := range(configData.HTTP.IPSetV6) {
				ipsetAddHttpV6 := commands_ipset.FormAdd("http-v6", ip)
				ipsetCommandList = append(ipsetCommandList, ipsetAddHttpV6)
			}

			commandData, err := commands_iptables.FormCommand("tcp", configData.HTTP.Port, configData.HTTP.Policy, "http-v4", "http-v6")
			if err != nil {
				log.Fatal(err)
				return
			}
			commandList = append(commandList, commandData.V4)
			commandList = append(commandList, commandData.V6)
		} else {
			commandData, err := commands_iptables.FormCommand("tcp", configData.HTTP.Port, configData.HTTP.Policy, "", "")
			if err != nil {
				log.Fatal(err)
				return
			}
			commandList = append(commandList, commandData.V4)
			commandList = append(commandList, commandData.V6)
		}
	}
	
	//process https rules
	if configData.HTTPS.Enabled {
		if configData.HTTPS.Policy == "filter_by_ipset" {
			ipsetCreateHttpsV4 := commands_ipset.FormCreate("https-v4", false)
			ipsetCommandList = append(ipsetCommandList, ipsetCreateHttpsV4)

			ipsetCreateHttpsV6 := commands_ipset.FormCreate("https-v6", true)
			ipsetCommandList = append(ipsetCommandList, ipsetCreateHttpsV6)

			for _, ip := range(configData.HTTPS.IPSetV4) {
				ipsetAddHttpsV4 := commands_ipset.FormAdd("https-v4", ip)
				ipsetCommandList = append(ipsetCommandList, ipsetAddHttpsV4)
			}
			for _, ip := range(configData.HTTPS.IPSetV6) {
				ipsetAddHttpsV6 := commands_ipset.FormAdd("https-v6", ip)
				ipsetCommandList = append(ipsetCommandList, ipsetAddHttpsV6)
			}

			commandData, err := commands_iptables.FormCommand("tcp", configData.HTTPS.Port, configData.HTTPS.Policy, "https-v4", "https-v6")
			if err != nil {
				log.Fatal(err)
				return
			}
			commandList = append(commandList, commandData.V4)
			commandList = append(commandList, commandData.V6)
		} else {
			commandData, err := commands_iptables.FormCommand("tcp", configData.HTTPS.Port, configData.HTTPS.Policy, "", "")
			if err != nil {
				log.Fatal(err)
				return
			}
			commandList = append(commandList, commandData.V4)
			commandList = append(commandList, commandData.V6)
		}
	}

    //get any existing docker rules and add them to the commands list
	dockerIptables, err := commands_iptables.GetAllByPattern(dockerRegex, "", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	dockerIp6tables, err := commands_iptables.GetAllByPattern(dockerRegex, "", true)
	if err != nil {
		log.Fatal(err)
		return
	}
	dockerIptablesRaw, err := commands_iptables.GetAllByPattern(dockerRegex, "raw", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	dockerIp6tablesRaw, err := commands_iptables.GetAllByPattern(dockerRegex, "raw", true)
	if err != nil {
		log.Fatal(err)
		return
	}
	dockerIptablesNat, err := commands_iptables.GetAllByPattern(dockerRegex, "nat", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	dockerIptablesMangle, err := commands_iptables.GetAllByPattern(dockerRegex, "mangle", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	dockerIp6tablesMangle, err := commands_iptables.GetAllByPattern(dockerRegex, "mangle", true)
	if err != nil {
		log.Fatal(err)
		return
	}

	for _, rule := range(dockerIptables) {
		command := fmt.Sprintf("iptables %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(dockerIp6tables) {
		command := fmt.Sprintf("ip6tables %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(dockerIptablesRaw) {
		command := fmt.Sprintf("iptables -t raw %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(dockerIp6tablesRaw) {
		command := fmt.Sprintf("ip6tables -t raw %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(dockerIptablesNat) {
		command := fmt.Sprintf("iptables -t nat %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(dockerIptablesMangle) {
		command := fmt.Sprintf("iptables -t mangle %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(dockerIp6tablesMangle) {
		command := fmt.Sprintf("ip6tables -t mangle %s", rule)
		appendCommandIfDoesntExist(command)
	}
	
    //get rules releated to docker bridges by ID
	networkIDs, err := commands_docker.GetNetworkIDs()
	if err == nil {
		for _, id := range(networkIDs) {
			pattern, err := regexp.Compile(regexp.QuoteMeta(id))
			if err != nil {
				log.Println("invalid pattern for network ID", id, err)
				continue
			}

			dockerIptables, err := commands_iptables.GetAllByPattern(pattern, "", false)
			if err != nil {
				log.Fatal(err)
				return
			}
			dockerIp6tables, err := commands_iptables.GetAllByPattern(pattern, "", true)
			if err != nil {
				log.Fatal(err)
				return
			}
			dockerIptablesRaw, err := commands_iptables.GetAllByPattern(pattern, "raw", false)
			if err != nil {
				log.Fatal(err)
				return
			}
			dockerIp6tablesRaw, err := commands_iptables.GetAllByPattern(pattern, "raw", true)
			if err != nil {
				log.Fatal(err)
				return
			}
			dockerIptablesNat, err := commands_iptables.GetAllByPattern(pattern, "nat", false)
			if err != nil {
				log.Fatal(err)
				return
			}
			dockerIptablesMangle, err := commands_iptables.GetAllByPattern(pattern, "mangle", false)
			if err != nil {
				log.Fatal(err)
				return
			}
			dockerIp6tablesMangle, err := commands_iptables.GetAllByPattern(pattern, "mangle", true)
			if err != nil {
				log.Fatal(err)
				return
			}
			
			for _, rule := range(dockerIptables) {
				command := fmt.Sprintf("iptables %s", rule)
				appendCommandIfDoesntExist(command)
			}
			for _, rule := range(dockerIp6tables) {
				command := fmt.Sprintf("ip6tables %s", rule)
				appendCommandIfDoesntExist(command)
			}
			for _, rule := range(dockerIptablesRaw) {
				command := fmt.Sprintf("iptables -t raw %s", rule)
				appendCommandIfDoesntExist(command)
			}
			for _, rule := range(dockerIp6tablesRaw) {
				command := fmt.Sprintf("ip6tables -t raw %s", rule)
				appendCommandIfDoesntExist(command)
			}
			for _, rule := range(dockerIptablesNat) {
				command := fmt.Sprintf("iptables -t nat %s", rule)
				appendCommandIfDoesntExist(command)
			}
			for _, rule := range(dockerIptablesMangle) {
				command := fmt.Sprintf("iptables -t mangle %s", rule)
				appendCommandIfDoesntExist(command)
			}
			for _, rule := range(dockerIp6tablesMangle) {
				command := fmt.Sprintf("ip6tables -t mangle %s", rule)
				appendCommandIfDoesntExist(command)
			}
		}
	}
	
    //get nat rules for the default docker0 bridge
	dockerBridge0Iptables, err := commands_iptables.GetAllByPattern(dockerBridge0Regex, "nat", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	for _, rule := range(dockerBridge0Iptables) {
		command := fmt.Sprintf("iptables -t nat %s", rule)
		appendCommandIfDoesntExist(command)
	}

    //get any kubernetes/kube/flannel/cni rules and add them to the commands list, same as we do with docker
	kubeIptables, err := commands_iptables.GetAllByPattern(kubeRegex, "", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	kubeIp6tables, err := commands_iptables.GetAllByPattern(kubeRegex, "", true)
	if err != nil {
		log.Fatal(err)
		return
	}
	kubeIptablesRaw, err := commands_iptables.GetAllByPattern(kubeRegex, "raw", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	kubeIp6tablesRaw, err := commands_iptables.GetAllByPattern(kubeRegex, "raw", true)
	if err != nil {
		log.Fatal(err)
		return
	}
	kubeIptablesNat, err := commands_iptables.GetAllByPattern(kubeRegex, "nat", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	kubeIptablesMangle, err := commands_iptables.GetAllByPattern(kubeRegex, "mangle", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	kubeIp6tablesMangle, err := commands_iptables.GetAllByPattern(kubeRegex, "mangle", true)
	if err != nil {
		log.Fatal(err)
		return
	}

	for _, rule := range(kubeIptables) {
		command := fmt.Sprintf("iptables %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(kubeIp6tables) {
		command := fmt.Sprintf("ip6tables %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(kubeIptablesRaw) {
		command := fmt.Sprintf("iptables -t raw %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(kubeIp6tablesRaw) {
		command := fmt.Sprintf("ip6tables -t raw %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(kubeIptablesNat) {
		command := fmt.Sprintf("iptables -t nat %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(kubeIptablesMangle) {
		command := fmt.Sprintf("iptables -t mangle %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(kubeIp6tablesMangle) {
		command := fmt.Sprintf("ip6tables -t mangle %s", rule)
		appendCommandIfDoesntExist(command)
	}

	flannelIptables, err := commands_iptables.GetAllByPattern(flannelRegex, "", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	flannelIp6tables, err := commands_iptables.GetAllByPattern(flannelRegex, "", true)
	if err != nil {
		log.Fatal(err)
		return
	}
	flannelIptablesRaw, err := commands_iptables.GetAllByPattern(flannelRegex, "raw", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	flannelIp6tablesRaw, err := commands_iptables.GetAllByPattern(flannelRegex, "raw", true)
	if err != nil {
		log.Fatal(err)
		return
	}
	flannelIptablesNat, err := commands_iptables.GetAllByPattern(flannelRegex, "nat", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	flannelIptablesMangle, err := commands_iptables.GetAllByPattern(flannelRegex, "mangle", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	flannelIp6tablesMangle, err := commands_iptables.GetAllByPattern(flannelRegex, "mangle", true)
	if err != nil {
		log.Fatal(err)
		return
	}
	
	for _, rule := range(flannelIptables) {
		command := fmt.Sprintf("iptables %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(flannelIp6tables) {
		command := fmt.Sprintf("ip6tables %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(flannelIptablesRaw) {
		command := fmt.Sprintf("iptables -t raw %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(flannelIp6tablesRaw) {
		command := fmt.Sprintf("ip6tables -t raw %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(flannelIptablesNat) {
		command := fmt.Sprintf("iptables -t nat %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(flannelIptablesMangle) {
		command := fmt.Sprintf("iptables -t mangle %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(flannelIp6tablesMangle) {
		command := fmt.Sprintf("ip6tables -t mangle %s", rule)
		appendCommandIfDoesntExist(command)
	}

	cniIptables, err := commands_iptables.GetAllByPattern(cniRegex, "", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	cniIp6tables, err := commands_iptables.GetAllByPattern(cniRegex, "", true)
	if err != nil {
		log.Fatal(err)
		return
	}
	cniIptablesRaw, err := commands_iptables.GetAllByPattern(cniRegex, "raw", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	cniIp6tablesRaw, err := commands_iptables.GetAllByPattern(cniRegex, "raw", true)
	if err != nil {
		log.Fatal(err)
		return
	}
	cniIptablesNat, err := commands_iptables.GetAllByPattern(cniRegex, "nat", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	cniIptablesMangle, err := commands_iptables.GetAllByPattern(cniRegex, "mangle", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	cniIp6tablesMangle, err := commands_iptables.GetAllByPattern(cniRegex, "mangle", true)
	if err != nil {
		log.Fatal(err)
		return
	}

	for _, rule := range(cniIptables) {
		command := fmt.Sprintf("iptables %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(cniIp6tables) {
		command := fmt.Sprintf("ip6tables %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(cniIptablesRaw) {
		command := fmt.Sprintf("iptables -t raw %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(cniIp6tablesRaw) {
		command := fmt.Sprintf("ip6tables -t raw %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(cniIptablesNat) {
		command := fmt.Sprintf("iptables -t nat %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(cniIptablesMangle) {
		command := fmt.Sprintf("iptables -t mangle %s", rule)
		appendCommandIfDoesntExist(command)
	}
	for _, rule := range(cniIp6tablesMangle) {
		command := fmt.Sprintf("ip6tables -t mangle %s", rule)
		appendCommandIfDoesntExist(command)
	}

    //process extras
	for _, extra := range(configData.Extras) {
		switch value := extra.(type) {
		case string: {
			appendCommandIfDoesntExist(value)
			break
		}

		case map[string]any: {
			fmt.Println("JSON object:", value)
			data, err := json.Marshal(value)
			if err != nil {
				log.Fatal(err)
				return
			}
			var extraData config.ExtraConfigSettings
			if err := json.Unmarshal(data, &extraData, json.MatchCaseInsensitiveNames(true)); err != nil {
				log.Fatal(err)
				return
			}
			if extraData.Policy == "filter_by_ipset" {
				ipsetCreateV4 := commands_ipset.FormCreate(extraData.IPSetV4.Name, false)
				ipsetCommandList = append(ipsetCommandList, ipsetCreateV4)
				
				for _, ip := range(extraData.IPSetV4.List) {
					ipsetAddV4 := commands_ipset.FormAdd(extraData.IPSetV4.Name, ip)
					ipsetCommandList = append(ipsetCommandList, ipsetAddV4)
				}

				ipsetCreateV6 := commands_ipset.FormCreate(extraData.IPSetV6.Name, false)
				ipsetCommandList = append(ipsetCommandList, ipsetCreateV6)

				for _, ip := range(extraData.IPSetV6.List) {
					ipsetAddV6 := commands_ipset.FormAdd(extraData.IPSetV6.Name, ip)
					ipsetCommandList = append(ipsetCommandList, ipsetAddV6)
				}

				commandData, err := commands_iptables.FormCommand(extraData.Protocol, extraData.Port, extraData.Policy, extraData.IPSetV4.Name, extraData.IPSetV6.Name)
				if err != nil {
					log.Fatal(err)
					return
				}
				appendCommandIfDoesntExist(commandData.V4)
				appendCommandIfDoesntExist(commandData.V6)
			} else {
				commandData, err := commands_iptables.FormCommand(extraData.Protocol, extraData.Port, extraData.Policy, "", "")
				if err != nil {
					log.Fatal(err)
					return
				}
				appendCommandIfDoesntExist(commandData.V4)
				appendCommandIfDoesntExist(commandData.V6)
			}
			break
		}

		default: {
			log.Fatal(fmt.Errorf("Unexpected type: %T\n", value))
			return
			break
		}
		}
	}

    //process default policy
	defaultPolicyCmds, err := commands_iptables.GetDefaultPolicyCommands(configData.DefaultPolicy)
	if err != nil {
		log.Fatal(err)
		return
	}
	
    //compare current rules against evaluated cmds
	currentIptables, err := commands_iptables.GetAll("", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	currentIp6tables, err := commands_iptables.GetAll("", true)
	if err != nil {
		log.Fatal(err)
		return
	}
	currentIptablesRaw, err := commands_iptables.GetAll("raw", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	currentIp6tablesRaw, err := commands_iptables.GetAll("raw", true)
	if err != nil {
		log.Fatal(err)
		return
	}
	currentIptablesNat, err := commands_iptables.GetAll("nat", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	currentIptablesMangle, err := commands_iptables.GetAll("mangle", false)
	if err != nil {
		log.Fatal(err)
		return
	}
	currentIp6tablesMangle, err := commands_iptables.GetAll("mangle", true)
	if err != nil {
		log.Fatal(err)
		return
	}

	//this is gonna be heavy
	//go through commandList
	//go through all current rules
	//if cmd is found in any, continue to next in the list
	//if any aren't found toggle rules changed and break out
	rulesChanged := false
	for _, command := range(commandList) {
		commandFound := false 
		for _, rule := range(currentIptables) {
			ruleCmd := fmt.Sprintf("iptables %s", rule)
			if ruleCmd == command {
				commandFound = true
			}
		}
		for _, rule := range(currentIp6tables) {
			ruleCmd := fmt.Sprintf("ip6tables %s", rule)
			if ruleCmd == command {
				commandFound = true
			}
		}
		for _, rule := range(currentIptablesRaw) {
			ruleCmd := fmt.Sprintf("iptables -t raw %s", rule)
			if ruleCmd == command {
				commandFound = true
			}
		}
		for _, rule := range(currentIp6tablesRaw) {
			ruleCmd := fmt.Sprintf("ip6tables -t raw %s", rule)
			if ruleCmd == command {
				commandFound = true
			}
		}
		for _, rule := range(currentIptablesNat) {
			ruleCmd := fmt.Sprintf("iptables -t nat %s", rule)
			if ruleCmd == command {
				commandFound = true
			}
		}
		for _, rule := range(currentIptablesMangle) {
			ruleCmd := fmt.Sprintf("iptables -t mangle %s", rule)
			if ruleCmd == command {
				commandFound = true
			}
		}
		for _, rule := range(currentIp6tablesMangle) {
			ruleCmd := fmt.Sprintf("ip6tables -t mangle %s", rule)
			if ruleCmd == command {
				commandFound = true
			}
		}
		if !commandFound {
			rulesChanged = true
			break
		}
	}

	//if rules changed, setup firewall
	if rulesChanged {
		//flush first
		commands_iptables.FlushIptables()
		
		//set default policies
		for _, command := range(defaultPolicyCmds) {
			log.Printf("Executing command: %s", command.V4)
			log.Printf("Executing command: %s", command.V6)

			v4Cmd := exec.Command("sh", "-c", command.V4)
			if err := v4Cmd.Run(); err != nil {
				log.Println(err)
			}
			v6Cmd := exec.Command("sh", "-c", command.V6)
			if err := v6Cmd.Run(); err != nil {
				log.Println(err)
			}
		}
		//setup ipsets
		for _, command := range(ipsetCommandList) {
			log.Printf("Executing command: %s", command)

			cmd := exec.Command("sh", "-c", command)
			if err := cmd.Run(); err != nil {
				log.Println(err)
			}
		}
		//setup iptables
		for _, command := range(commandList) {
			log.Printf("Executing command: %s", command)
			
			cmd := exec.Command("sh", "-c", command)
			if err := cmd.Run(); err != nil {
				log.Println(err)
			}
		}
	} else {
		log.Println("Current iptables match the evaluated commands, skipping...")
	}

	//block here until the context is cancelled (SIGINT/SIGTERM),
	<-ctx.Done()
	log.Println("Shutting down...")
}
