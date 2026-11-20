package commands

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func VerifyDependencies() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmds := [][]string{
		{"iptables", "--version"},
		{"ip6tables", "--version"},
		{"ipset", "--version"},
	}

	var errs []error
	for _, args := range cmds {
		path, err := exec.LookPath(args[0])
		if err != nil {
			errs = append(errs, fmt.Errorf("%s not found in PATH: %w", args[0], err))
			continue
		}

		cmd := exec.CommandContext(ctx, path, args[1:]...)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out

		if err := cmd.Run(); err != nil {
			detail := strings.TrimSpace(out.String())
			if detail != "" {
				errs = append(errs, fmt.Errorf("%s failed: %w (%s)", strings.Join(args, " "), err, detail))
			} else {
				errs = append(errs, fmt.Errorf("%s failed: %w", strings.Join(args, " "), err))
			}
		}
	}

	return errors.Join(errs...)
}
