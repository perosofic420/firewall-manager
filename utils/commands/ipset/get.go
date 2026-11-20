package ipset

import (
	"bytes"
	"bufio"
	"os/exec"
)

func GetIPsFromIpset(name string) ([]string, error) {
	cmdName := "ipset"
	args := []string{"list", name}

	cmd := exec.Command(cmdName, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	foundMembersSection := false
	var lines []string
	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		line := scanner.Text()
		if foundMembersSection && line != "" {
			lines = append(lines, line)
		} else if (!foundMembersSection && line == "Members:") {
			foundMembersSection = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}
