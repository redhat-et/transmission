package osinfo

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

const (
	ipv4RouteFile = "/proc/net/route"
	machineIdSalt = "7f16ba539046995e2264d3a33526c53f"
)

func GetArch() string {
	arch_replacer := strings.NewReplacer("amd64", "x86_64", "arm64", "aarch64")
	return arch_replacer.Replace(runtime.GOARCH)
}

// Converts a hex-encoded IP address into a net.IP address
func parseHexIP(hexIP string) (net.IP, error) {
	bytes, err := hex.DecodeString(hexIP)
	if err != nil {
		return nil, err
	}
	if len(bytes) == net.IPv4len {
		return net.IP([]byte{bytes[3], bytes[2], bytes[1], bytes[0]}), nil
	}
	if len(bytes) == net.IPv6len {
		return net.IP(bytes), nil
	}
	return nil, fmt.Errorf("invalid IP address length: %d", len(bytes))
}

func GetDefaultInterfaceName() (string, error) {
	routes, err := ioutil.ReadFile(ipv4RouteFile)
	if err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(bytes.NewReader(routes))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "Iface" {
			continue
		}

		destIP, err := parseHexIP(fields[1])
		if err != nil {
			return "", err
		}
		if destIP.Equal(net.IPv4zero) {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("no default interface found")
}

func GetDefaultMACAddress() (string, error) {
	intfName, err := GetDefaultInterfaceName()
	if err != nil {
		return "", fmt.Errorf("getting default network interface name: %w", err)
	}

	intf, err := net.InterfaceByName(intfName)
	if err != nil {
		return "", fmt.Errorf("getting default network interface: %w", err)
	}

	return strings.ReplaceAll(intf.HardwareAddr.String(), ":", "-"), nil
}

func GetMachineID() (string, error) {
	machineID, err := ioutil.ReadFile("/etc/machine-id")
	if err != nil {
		return "", fmt.Errorf("reading machine ID failed: %w", err)
	}
	hashedMachineId := sha256.Sum256([]byte([]byte(machineIdSalt + string(machineID))))
	return hex.EncodeToString(hashedMachineId[:])[:32], nil
}

func GetSubscriptionID() (string, error) {
	if os.Geteuid() != 0 {
		return "", fmt.Errorf("need to run with EUID 0 to fetch subscription-manager ID")
	}

	stdouterr, err := exec.Command("subscription-manager", "identity").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("fetching subscription-manager ID failed: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(stdouterr))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) == 2 && fields[0] == "system identity" {
			return strings.TrimSpace(fields[1]), nil
		}
	}
	return "", fmt.Errorf("parsing subscription-manager ID failed: %w", scanner.Err())
}

func GetInsightsID() (string, error) {
	insightsID, err := ioutil.ReadFile("/etc/insights-client/machine-id")
	if err != nil {
		return "", fmt.Errorf("reading Insights ID failed: %w", err)
	}
	return strings.TrimSpace(string(insightsID)), nil
}
