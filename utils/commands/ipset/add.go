package ipset

import "fmt"

func FormAdd(name string, ip string) (string) {
	return fmt.Sprintf("ipset add %s %s --exist", name, ip)
}
