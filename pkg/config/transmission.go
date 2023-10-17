package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/redhat-et/transmission/pkg/osinfo"
	"github.com/redhat-et/transmission/pkg/util"
)

func GetTransmissionURL() (string, error) {
	rawURL, err := getTransmissionURL()
	if err != nil {
		return "", fmt.Errorf("looking up Tranmission URL: %v", err)
	}
	rawURL, err = renderTransmissionURL(rawURL)
	if err != nil {
		return "", fmt.Errorf("rendering Transmission URL: %v", err)
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func getTransmissionURL() (string, error) {
	cmdlineUrl, err := getTransmissionUrlFromKernelCmdline()
	if err != nil {
		return "", err
	}
	if len(cmdlineUrl) > 0 {
		return cmdlineUrl, nil
	}

	for _, p := range []string{"/usr/lib/transmission-url", "/etc/transmission-url", "./transmission-url"} {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			continue
		}

		buf, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(buf)), nil
	}
	return "", nil
}

func getTransmissionUrlFromKernelCmdline() (string, error) {
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", fmt.Errorf("reading /proc/cmdline failed: %w", err)
	}
	for _, arg := range strings.Split(string(cmdline), " ") {
		fields := strings.Split(arg, "=")
		if len(fields) == 2 && fields[0] == "transmission.url" {
			return strings.TrimSpace(fields[1]), nil
		}
	}
	return "", nil
}

func renderTransmissionURL(urlTemplate string) (string, error) {
	urlTemplate = strings.ReplaceAll(urlTemplate, "${arch}", osinfo.GetArch())
	urlTemplate = strings.ReplaceAll(urlTemplate, "${mac}", util.DefaultIfError(osinfo.GetDefaultMACAddress, "unknown"))
	urlTemplate = strings.ReplaceAll(urlTemplate, "${uuid}", util.DefaultIfError(osinfo.GetMachineID, "unknown"))
	urlTemplate = strings.ReplaceAll(urlTemplate, "${subscriptionid}", util.DefaultIfError(osinfo.GetSubscriptionID, "unknown"))
	urlTemplate = strings.ReplaceAll(urlTemplate, "${insightsid}", util.DefaultIfError(osinfo.GetInsightsID, "unknown"))
	return urlTemplate, nil
}
