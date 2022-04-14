package prober

import (
	"github.com/cloudprober/cloudprober/probes"
	"github.com/sun-asterisk-research/promprober/probes/http"
	httppb "github.com/sun-asterisk-research/promprober/probes/http/proto"
)

func registerProbes() {
	probes.RegisterProbeType(int(httppb.E_HttpProbe.TypeDescriptor().Number()), func() probes.Probe { return &http.Probe{} })
}
