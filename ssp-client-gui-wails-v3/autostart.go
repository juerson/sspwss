package main

import (
	"os"

	"golang.org/x/sys/windows/registry"
)

// ==============================================================================
// 开机自启 —— HKCU\...\CurrentVersion\Run
// （值名固定 "SSP Workers Client"，数据为带引号的 exe 完整路径，无参数）
// ==============================================================================

const (
	runKeyPath         = `Software\Microsoft\Windows\CurrentVersion\Run`
	autoStartValueName = "SSP Workers Client"
)

func setAutoStart(enabled bool) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = key.Close() }()

	if !enabled {
		return key.DeleteValue(autoStartValueName)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return key.SetStringValue(autoStartValueName, `"`+exe+`"`)
}
