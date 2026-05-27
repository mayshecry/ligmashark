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

// StartMITM launches bettercap with ARP spoofing enabled.
// It requires bettercap to be installed in the system PATH.
// Note: Bettercap usually requires root/sudo privileges to perform ARP spoofing.
func StartMITM(iface string) (io.ReadCloser, error) {
	mitmMu.Lock()
	defer mitmMu.Unlock()

	if bettercapCmd != nil {
		return nil, fmt.Errorf("bettercap is already running")
	}

	// We use -eval to enable arp spoofing and net sniffing immediately.
	// This makes the machine act as a gateway for other devices on the LAN.
	args := []string{"-eval", "arp.spoof on; net.sniff on"}

	// If a specific interface is provided (and it's not the 'any' pseudo-interface), use it.
	if iface != "" && iface != "any" {
		args = append([]string{"-iface", iface}, args...)
	}

	cmd := exec.Command("bettercap", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get bettercap stdout: %w", err)
	}
	cmd.Stderr = cmd.Stdout // Capture all output

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start bettercap: %w (is it installed?)", err)
	}

	bettercapOut = stdout
	bettercapCmd = cmd
	return stdout, nil
}

// StopMITM kills the bettercap process and waits for it to exit.
func StopMITM() error {
	mitmMu.Lock()
	defer mitmMu.Unlock()

	if bettercapCmd == nil {
		return nil
	}

	// Send SIGKILL to ensure the process stops immediately.
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

// IsMITMActive returns true if the bettercap process is currently managed by Ligmashark.
func IsMITMActive() bool {
	mitmMu.Lock()
	defer mitmMu.Unlock()
	return bettercapCmd != nil
}
