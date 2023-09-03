package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/golang/glog"

	"github.com/redhat-et/transmission/pkg/ignition"

	ign3types "github.com/coreos/ignition/v2/config/v3_4/types"
)

var (
	address       = ":9000"
	emptyIgnition = ign3types.Config{
		Ignition: ign3types.Ignition{
			Version: ign3types.MaxVersion.String(),
		},
	}
	config = ""
)

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [ignition_file]\n", os.Args[0])
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	glog.Infof("request: %s", r.URL)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, config)
}

func main() {
	flag.Usage = usage
	flag.Parse()
	flag.Lookup("logtostderr").Value.Set("true")
	defer glog.Flush()

	ign := emptyIgnition
	if len(os.Args) > 1 {
		var err error
		ign, err = ignition.Load(os.Args[1])
		if err != nil {
			glog.Errorf("loading ignition config: %w", err)
			os.Exit(1)
		}
	}

	buf, err := json.Marshal(ign)
	if err != nil {
		glog.Errorf("failed to marshal ignition object: %w", err)
		os.Exit(1)
	}
	config = string(buf[:])

	http.HandleFunc("/config", configHandler)
	glog.Infof("Listening on %s", address)
	glog.Fatal(http.ListenAndServe(address, nil))
}
