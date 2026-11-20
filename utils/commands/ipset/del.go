package ipset

import "fmt"

func FormDelete(name string, ip string) (string) {
	return fmt.Sprintf("ipset del %s %s", name, ip)
}
