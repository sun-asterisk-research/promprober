package main

import (
	"flag"

	"github.com/sirupsen/logrus"
	"github.com/sun-asterisk-research/promprober/prober"
)

var (
	configFile = flag.String("config_file", "/etc/cloudprober.cfg", "Config file")
)

func main() {
	flag.Parse()

	logrus.SetLevel(logrus.DebugLevel)

	prober.Start(*configFile)

	select {}
}
