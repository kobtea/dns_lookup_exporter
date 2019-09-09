package main

import (
	"github.com/kobtea/dns_lookup_exporter/pkg/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
	"gopkg.in/alecthomas/kingpin.v2"
	"io/ioutil"
	"net"
	"net/http"
)

const (
	namespace = "dns_lookup"
)

var (
	listenAddress = kingpin.Flag("web.listen-address", "Address to listen on for web interface and telemetry").Default(":9999").String()
	metricsPath   = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
	configFile    = kingpin.Flag("config", "Path to config file").Default("").String()
)

type collector struct {
	namespace string
	config    *config.Config
	ips       *prometheus.GaugeVec
}

func newCollector(namespace string, conf *config.Config) (*collector, error) {
	return &collector{
		namespace: namespace,
		config:    conf,
		ips: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "ips",
			Help:      "number of IPs",
		}, []string{"domain", "ipv"})}, nil
}

func (collector collector) Describe(ch chan<- *prometheus.Desc) {
	collector.ips.Describe(ch)
}

func (collector collector) Collect(ch chan<- prometheus.Metric) {
	for _, domain := range collector.config.Static.Targets {
		if addrs, err := net.LookupHost(domain); err != nil {
			log.Error(err)
		} else {
			var ipv4s, ipv6s int
			for _, addr := range addrs {
				if ip := net.ParseIP(addr); ip == nil {
					log.Errorf("failed to parse address: %s", addr)
				} else {
					if res := ip.To4(); res != nil {
						ipv4s += 1
					} else {
						ipv6s += 1
					}
				}
			}
			collector.ips.With(prometheus.Labels{"domain": domain, "ipv": "4"}).Set(float64(ipv4s))
			collector.ips.With(prometheus.Labels{"domain": domain, "ipv": "4"}).Collect(ch)
			collector.ips.With(prometheus.Labels{"domain": domain, "ipv": "6"}).Set(float64(ipv6s))
			collector.ips.With(prometheus.Labels{"domain": domain, "ipv": "6"}).Collect(ch)
		}
	}
}

func main() {
	log.AddFlags(kingpin.CommandLine)
	kingpin.Version(version.Print("dns_lookup_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	conf := &config.Config{}
	if *configFile != "" {
		buf, err := ioutil.ReadFile(*configFile)
		if err != nil {
			log.Fatal("failed to read config file")
		}
		conf, err = config.Parse(buf)
		if err != nil {
			log.Fatal("invalid config format")
		}
	}
	collector, err := newCollector(namespace, conf)
	if err != nil {
		log.Fatal(err)
	}
	prometheus.MustRegister(collector)

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>DNS Lookup Exporter</title></head>
             <body>
             <h1>DNS Lookup Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})
	log.Infoln("listening on", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
