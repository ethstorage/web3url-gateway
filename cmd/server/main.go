package main

import (
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"
)

var (
	verbosity                     = flag.Int("verbosity", 4, "verbosity (0 = panic, 1 = fatal, 2 = error, 3 = warn, 4 = info, 5 = debug, 6 = trace")
	configurationFile             = flag.String("config", "config.toml", "configuration file")
	versionCheck                  = flag.Bool("version", false, "print version of web3url server")
	dbToken                       = flag.String("dbToken", "", "influxDB auth token")
	cacheDurationMinutes          = flag.Int("cacheDurationMinutes", 60, "cache duration in minutes; default to 60")
	nameAddrCache                 *localCache
	writeAPI                      api.WriteAPIBlocking
	certificateFile               = stringFlags{}
	keyFile                       = stringFlags{}
	port                          = stringFlags{value: "80"}
	defaultChain                  = stringFlags{value: "1"}
	homePage                      = stringFlags{value: "/home.w3q/"}
	cors                          = stringFlags{value: "*"}
	nsInfos, chainInfos, nsChains arrayFlags
	config                        Web3Config
	majorVersion                  = "0"
	minorVersion                  = "2"
	patchVersion                  = "0"
	releaseInfo                   = "beta"
	commitInfo                    string
)

// versionInfo returns the semantic versioning info of the running server
func versionInfo() string {
	return fmt.Sprintf("%s.%s.%s-%s+%s", majorVersion, minorVersion, patchVersion, releaseInfo, commitInfo)
}

func initConfig() {
	flag.Var(&chainInfos, "setChain", "chainID,chainName,rpc")
	flag.Var(&nsInfos, "setNS", "chainId,suffix,nsType,nsAddress")
	flag.Var(&nsChains, "setNSChain", "suffix,defaultChainID")
	flag.Var(&port, "port", "server port")
	flag.Var(&keyFile, "key", "key file")
	flag.Var(&defaultChain, "defaultChain", "default chain id")
	flag.Var(&homePage, "homePage", "home page address")
	flag.Var(&cors, "cors", "comma separated list of domains from which to accept cross origin requests")
	flag.Parse()
	// read from config file
	config = Web3Config{}
	config.NSDefaultChains = make(map[string]string)
	config.ChainConfigs = make(map[string]ChainConfig)
	config.Name2Chain = make(map[string]string)
	config.Verbosity = *verbosity
	err := loadConfig(*configurationFile, &config)
	if err != nil {
		log.Fatalf("Cannot load config: %v\n", err)
	}
	// read arguments from command line and overwrite corresponding settings in config file
	if certificateFile.set {
		config.CertificateFile = certificateFile.value
	}
	if keyFile.set {
		config.KeyFile = keyFile.value
	}
	if port.set {
		config.ServerPort = port.value
	}
	if defaultChain.set {
		config.DefaultChain = defaultChain.value
	}
	if homePage.set {
		config.HomePage = homePage.value
	}
	if cors.set {
		config.CORS = cors.value
	}
	for _, c := range chainInfos {
		ss := strings.Split(c, ",")
		if len(ss) != 3 {
			log.Fatalf("Expect 3 fields in chainInfo but got %v\n", len(ss))
			return
		}
		config.ChainConfigs[ss[0]] = ChainConfig{
			ChainID:  ss[0],
			RPC:      ss[2],
			NSConfig: make(map[string]NameServiceInfo),
		}
		config.Name2Chain[ss[1]] = ss[0]
	}
	for _, ns := range nsInfos {
		ss := strings.Split(ns, ",")
		if len(ss) != 4 {
			log.Fatalf("Expect 4 fields in nsInfo but got %v\n:%v", len(ss), ss)
			return
		}
		if _, ok := nsTypeMapping[ss[2]]; !ok {
			log.Fatalf("Unknown nsType %v\n", ss[2])
			return
		}
		if _, ok := config.ChainConfigs[ss[0]]; !ok {
			log.Fatalf("Unsupport chainID %v\n", ss[0])
			return
		}
		config.ChainConfigs[ss[0]].NSConfig[ss[1]] = NameServiceInfo{
			NSType: nsTypeMapping[ss[2]],
			NSAddr: ss[3],
		}
	}
	for _, nc := range nsChains {
		ss := strings.Split(nc, ",")
		if len(ss) != 2 {
			log.Fatalf("Expect 2 fields in nsChain but got %v\n", len(ss))
		}
		config.NSDefaultChains[ss[0]] = ss[1]
	}
}

func initStats() {
	if len(*dbToken) > 0 {
		client := influxdb2.NewClient("http://localhost:8086", *dbToken)
		writeAPI = client.WriteAPIBlocking("web3q", "bucket0")
		defer client.Close()
		nameAddrCache.setTracer(writeAPI)
	}
}

func main() {
	if *versionCheck {
		fmt.Println("web3url server version", versionInfo())
		return
	}
	// cleanup per hour
	nameAddrCache = newLocalCache(time.Duration(*cacheDurationMinutes)*time.Minute, 10*time.Minute)
	initConfig()
	initStats()
	log.SetLevel(log.Level(config.Verbosity))
	log.SetFormatter(&log.TextFormatter{TimestampFormat: "2006-01-02 15:04:05", FullTimestamp: true})
	log.Infof("config: %+v\n", config)
	http.HandleFunc("/", handle)
	http.HandleFunc("/_version", func(w http.ResponseWriter, req *http.Request) {
		_, err := fmt.Fprintf(w, "web3url server version %s", versionInfo())
		if err != nil {
			log.Errorf("Cannot write version info: %v\n", err)
			return
		}
	})

	log.Infof("Serving on http://localhost:%v\n", config.ServerPort)
	if config.CertificateFile == "" || config.KeyFile == "" {
		log.Info("Running server in unsecure mode...")
		err := http.ListenAndServe(":"+config.ServerPort, nil)
		if err != nil {
			log.Fatalf("Cannot start server: %v\n", err)
			return
		}
	} else {
		err := http.ListenAndServeTLS(":"+config.ServerPort, config.CertificateFile, config.KeyFile, nil)
		if err != nil {
			log.Fatalf("Cannot start server: %v\n", err)
		}
	}
}
