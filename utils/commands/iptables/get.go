package iptables

import (
	"bytes"
	"bufio"
	"regexp"
	"os/exec"
)

func GetAll(table string, ipv6 bool) ([]string, error) {
	cmdName := "iptables"
	if ipv6 {
		cmdName = "ip6tables"
	}

	args := []string{"-S"}
	if table != "" {
		args = []string{"-t", table, "-S"}
	}

	cmd := exec.Command(cmdName, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	var lines []string
	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

func GetAllByPattern(pattern *regexp.Regexp, table string, ipv6 bool) ([]string, error) {
	iptableLines, err := GetAll(table, ipv6)
	if err != nil {
		return nil, err
	}

	var matched []string
	for _, line := range(iptableLines) {
		if pattern.MatchString(line) {
			matched = append(matched, line)
		}
	}

	return matched, nil
}
