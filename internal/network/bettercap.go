package network

import (
	"fmt"
	"io"
	"os/exec"
	"sync"
)

var (
	bettercapCmd *exec.Cmd
	bettercapOut io.ReadCloser
	mitmMu       sync.Mutex
)

func StartMITM(iface string) (io.ReadCloser, error) {
	mitmMu.Lock()
	defer mitmMu.Unlock()

	if bettercapCmd != nil {
		return nil, fmt.Errorf("bettercap is already running")
	}

	args := []string{"-no-colors", "-eval", "arp.spoof on; net.sniff on"}

	if iface != "" && iface != "any" {
		args = append([]string{"-iface", iface}, args...)
	}

	cmd := exec.Command("bettercap", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get bettercap stdout: %w", err)
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start bettercap: %w (is it installed?)", err)
	}

	bettercapOut = stdout
	bettercapCmd = cmd
	return stdout, nil
}

func StopMITM() error {
	mitmMu.Lock()
	defer mitmMu.Unlock()

	if bettercapCmd == nil {
		return nil
	}

	if err := bettercapCmd.Process.Kill(); err != nil {
		return fmt.Errorf("failed to kill bettercap: %w", err)
	}

	bettercapCmd.Wait()
	bettercapCmd = nil
	if bettercapOut != nil {
		bettercapOut.Close()
		bettercapOut = nil
	}
	return nil
}

func IsMITMActive() bool {
	mitmMu.Lock()
	defer mitmMu.Unlock()
	return bettercapCmd != nil
}
