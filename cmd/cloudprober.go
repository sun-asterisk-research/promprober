package main

import (
	"context"
	"flag"
	"io/ioutil"
	"os"

	"github.com/cloudprober/cloudprober"
	"github.com/cloudprober/cloudprober/config"
	"github.com/cloudprober/cloudprober/probes"
	"github.com/cloudprober/cloudprober/web"
	"github.com/sirupsen/logrus"
	"github.com/sun-asterisk-research/cloudprober/probes/http"
	httppb "github.com/sun-asterisk-research/cloudprober/probes/http/proto"
)

var (
	configFile = flag.String("config_file", "", "Config file")
)

const (
	defaultConfigFile = "/etc/cloudprober.cfg"
)

func configFileToString(fileName string) string {
	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		logrus.Fatalf("Failed to read the config file: %v", err)
	}

	return string(b)
}

func getConfig() string {
	if *configFile != "" {
		return configFileToString(*configFile)
	}

	if _, err := os.Stat(defaultConfigFile); !os.IsNotExist(err) {
		return configFileToString(defaultConfigFile)
	}

	logrus.Warningf("Config file %s not found. Using default config.", defaultConfigFile)

	return config.DefaultConfig()
}

func main() {
	flag.Parse()

	// probes.RegisterUserDefined("http", &http.Probe{})
	probes.RegisterProbeType(int(httppb.E_HttpProbe.TypeDescriptor().Number()), func() probes.Probe { return &http.Probe{} })

	err := cloudprober.InitFromConfig(getConfig())
	if err != nil {
		logrus.Fatalf("Could not load config: %v", err)
	}

	logrus.SetLevel(logrus.DebugLevel)

	web.Init()

	cloudprober.Start(context.Background())

	select {}
}
