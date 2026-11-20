package ipset

import "fmt"

func FormList(name string) (string) {
	return fmt.Sprintf("ipset list %s", name)
}
