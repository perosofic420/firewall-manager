package ipset

import "fmt"

func FormCreate(name string, v6 bool) (string) {
	if v6 {
		return fmt.Sprintf("ipset create %s hash:net family inet6 --exist", name)
	}
	return fmt.Sprintf("ipset create %s hash:net family inet --exist", name)
}
