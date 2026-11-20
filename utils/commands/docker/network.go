package docker

import (
	"bytes"
	"bufio"
	"os/exec"
)

func GetNetworkIDs() ([]string, error) {
	cmdName := "docker"

	args := []string{"network", "ls", "-q"}

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