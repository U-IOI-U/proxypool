package tool

func CheckInList(list []string, item string) bool {
	for _, i := range list {
		if item == i {
			return true
		}
	}
	return false
}

func CheckVmessUUID(uuid string) bool {
	if len(uuid) != 36 {
		return false
	}
	return true
}

func CheckVlessUUID(uuid string) bool {
	if len(uuid) == 0 {
		return false
	}
	return true
}

func CheckPort(port int) bool {
	if port <= 0 || port > 65535 {
		return false
	}
	return true
}
