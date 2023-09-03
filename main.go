package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/redhat-et/transmission/pkg/daemon"
	"github.com/redhat-et/transmission/pkg/osinfo"
	"github.com/redhat-et/transmission/pkg/provider/git"
	"github.com/redhat-et/transmission/pkg/util"
)

func getTransmissionUrlFromKernelCmdline() (string, error) {
	cmdline, err := ioutil.ReadFile("/proc/cmdline")
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

func getTransmissionURL() (string, error) {
	cmdlineUrl, err := getTransmissionUrlFromKernelCmdline()
	if err != nil {
		return "", err
	}
	if cmdlineUrl != "" {
		return cmdlineUrl, nil
	}
	for _, p := range []string{"/usr/lib/transmission-url", "/etc/transmission-url", "./transmission-url"} {
		if _, err := os.Stat(p); err == nil {
			file, err := os.Open(p)
			if err != nil {
				return "", err
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				return strings.TrimSpace(scanner.Text()), nil
			}
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

func updateBanner(url string) error {
	action := "No Transmission URL configured"
	if len(url) > 0 {
		action = fmt.Sprintf("Using %s to configure this device\n\n", url)
	}
	return ioutil.WriteFile("/run/transmission-banner", []byte(action), 0644)
}

func main() {

	flag.Parse()
	flag.Lookup("logtostderr").Value.Set("true")
	defer glog.Flush()

	url, err := getTransmissionURL()
	if err != nil {
		glog.Fatalf("looking up Tranmission URL: %w", err)
	}
	url, err = renderTransmissionURL(url)
	if err != nil {
		glog.Fatalf("rendering Transmission URL: %w", err)
	}

	updateBanner(url)

	if len(url) == 0 {
		glog.Infoln("Transmission URL not configured, exiting")
		os.Exit(0)
	}

	dn, err := daemon.New(nil)
	if err != nil {
		glog.Fatalln(err)
	}
	dn.SetRootDir(filepath.Join(util.DefaultIfError(os.Getwd, "./"), "fakeroot"))
	dn.InitDirs()

	glog.Infof("Running update, URL is %s", url)

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
	defer cancel()

	cfgProvider := git.New(dn.GetStagingDirPath(), url, "main", "/")
	hasUpdates, err := cfgProvider.FetchConfig(ctx, dn.GetDesiredConfigSetPath())
	if err != nil {
		glog.Errorln(err)
		os.Exit(1)
	}
	if !hasUpdates {
		glog.Infoln("No updates, exiting")
		os.Exit(0)
	}

	err = dn.UpdateConfig(dn.GetCurrentConfigSetPath(), dn.GetDesiredConfigSetPath(), false)
	if err != nil {
		glog.Errorln(err)
	}
}
