package compare

func IPs(current []string, updated []string) (added []string, removed []string) {
	currentSet := make(map[string]struct{}, len(current))
	updatedSet := make(map[string]struct{}, len(updated))

	for _, ip := range current {
		currentSet[ip] = struct{}{}
	}

	for _, ip := range updated {
		updatedSet[ip] = struct{}{}
	}

	for ip := range updatedSet {
		if _, exists := currentSet[ip]; !exists {
			added = append(added, ip)
		}
	}

	for ip := range currentSet {
		if _, exists := updatedSet[ip]; !exists {
			removed = append(removed, ip)
		}
	}

	return added, removed
}
