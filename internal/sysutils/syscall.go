package sysutils

import "runtime"

func SyscallName(base string) string {
	switch runtime.GOARCH {
	case "amd64":
		return "__x64_sys_" + base
	case "arm64":
		return "__arm64_sys_" + base
	default:
		return "sys_" + base
	}
}
