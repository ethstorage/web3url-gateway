package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"
	"github.com/ethereum/go-ethereum/common"
	"github.com/web3-protocol/web3protocol-go"
	golanglru2 "github.com/hashicorp/golang-lru/v2/expirable"
)

var (
	verbosity                     = flag.Int("verbosity", 4, "verbosity (0 = panic, 1 = fatal, 2 = error, 3 = warn, 4 = info, 5 = debug, 6 = trace")
	configurationFile             = flag.String("config", "config.toml", "configuration file")
	versionCheck                  = flag.Bool("version", false, "print version of web3url server")
	dbToken                       = flag.String("dbToken", "", "influxDB auth token")
	cacheDurationMinutes          = flag.Int("cacheDurationMinutes", 60, "cache duration in minutes; default to 60")
	writeAPI                      api.WriteAPIBlocking
	certificateFile               = stringFlags{}
	keyFile                       = stringFlags{}
	port                          = stringFlags{value: "80"}
	defaultChain                  = stringFlags{value: "1"}
	homePage                      = stringFlags{value: "/home.w3q/"}
	cors                          = stringFlags{value: "*"}
	nsInfos, chainInfos, nsChains arrayFlags
	config                        Web3Config
	web3protocolClient            *web3protocol.Client
	pageCache                     *golanglru2.LRU[PageCacheKey,PageCacheEntry]
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
	config.NSDefaultChains = make(map[string]int)
	config.ChainConfigs = make(map[int]ChainConfig)
	config.Name2Chain = make(map[string]int)
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
		defaultChainId, err := strconv.Atoi(defaultChain.value)
		if err != nil {
			log.Fatalf("Unable to parse %v as an integer\n", defaultChain.value)
			return
		}
		config.DefaultChain = defaultChainId
	}
	if homePage.set {
		config.HomePage = homePage.value
	}
	if cors.set {
		config.CORS = cors.value
	}
	// Page cache size: not use the default of unlimited, will only end in crashed servers
	if config.PageCache.MaxEntries == 0 {
		config.PageCache.MaxEntries = 1000
	}
	for _, c := range chainInfos {
		ss := strings.Split(c, ",")
		if len(ss) != 3 {
			log.Fatalf("Expect 3 fields in chainInfo but got %v\n", len(ss))
			return
		}
		chainId, err := strconv.Atoi(ss[0])
		if err != nil {
			log.Fatalf("Unable to parse %v as an integer\n", ss[0])
			return
		}
		config.ChainConfigs[chainId] = ChainConfig{
			ChainID:  chainId,
			RPC:      ss[2],
			NSConfig: make(map[string]NameServiceInfo),
		}
		config.Name2Chain[ss[1]] = chainId
	}
	for _, ns := range nsInfos {
		ss := strings.Split(ns, ",")
		if len(ss) != 4 {
			log.Fatalf("Expect 4 fields in nsInfo but got %v\n:%v", len(ss), ss)
			return
		}
		if ss[2] != web3protocol.DomainNameServiceENS && ss[2] != web3protocol.DomainNameServiceW3NS {
			log.Fatalf("Unknown nsType %v\n", ss[2])
			return
		}
		chainId, err := strconv.Atoi(ss[0])
		if err != nil {
			log.Fatalf("Unable to parse %v as an integer\n", ss[0])
			return
		}
		if _, ok := config.ChainConfigs[chainId]; !ok {
			log.Fatalf("Unsupport chainID %v\n", ss[0])
			return
		}
		config.ChainConfigs[chainId].NSConfig[ss[1]] = NameServiceInfo{
			NSType: web3protocol.DomainNameService(ss[2]),
			NSAddr: ss[3],
		}
	}
	for _, nc := range nsChains {
		ss := strings.Split(nc, ",")
		if len(ss) != 2 {
			log.Fatalf("Expect 2 fields in nsChain but got %v\n", len(ss))
		}
		chainId, err := strconv.Atoi(ss[1])
		if err != nil {
			log.Fatalf("Unable to parse %v as an integer\n", ss[1])
			return
		}
		config.NSDefaultChains[ss[0]] = chainId
	}
}

func initWeb3protocolClient() {
	// Prepare config
	web3pConfig := web3protocol.Config{
		Chains:             map[int]web3protocol.ChainConfig{},
		DomainNameServices: map[web3protocol.DomainNameService]web3protocol.DomainNameServiceConfig{},
	}

	for _, chainConfig := range config.ChainConfigs {
		// Config the chain
		web3pChainConfig := web3protocol.ChainConfig{
			ChainId:            chainConfig.ChainID,
			RPC:                chainConfig.RPC,
			DomainNameServices: map[web3protocol.DomainNameService]web3protocol.DomainNameServiceChainConfig{},
		}

		// Config the domain name service in chain, and deduce global infos about the domain name service
		for suffix, nsConfig := range chainConfig.NSConfig {
			web3pChainConfig.DomainNameServices[nsConfig.NSType] = web3protocol.DomainNameServiceChainConfig{
				Id:              nsConfig.NSType,
				ResolverAddress: common.HexToAddress(nsConfig.NSAddr),
			}

			if _, ok := web3pConfig.DomainNameServices[nsConfig.NSType]; !ok {
				web3pConfig.DomainNameServices[nsConfig.NSType] = web3protocol.DomainNameServiceConfig{
					Id:     nsConfig.NSType,
					Suffix: suffix,
				}
			}
		}

		// Add to list of chains
		web3pConfig.Chains[web3pChainConfig.ChainId] = web3pChainConfig
	}

	// Fill short names in chain configs
	for shortName, chainId := range config.Name2Chain {
		web3pChainConfig, ok := web3pConfig.Chains[chainId]
		if !ok {
			log.Fatalf("Chain short name %v is defined, but his chain is not\n", shortName)
			return
		}
		web3pChainConfig.ShortName = shortName
		web3pConfig.Chains[chainId] = web3pChainConfig
	}

	// Fill default chains in domain name service configs
	for suffix, defaultChainId := range config.NSDefaultChains {
		domainNameService := web3pConfig.GetDomainNameServiceBySuffix(suffix)
		if domainNameService == "" {
			log.Fatalf("A default chain id is specified for domain name service whose extension is %v, but no chain use this domain name service\n", suffix)
			return
		}
		web3pDomainNameServiceConfig := web3pConfig.DomainNameServices[domainNameService]
		web3pDomainNameServiceConfig.DefaultChainId = defaultChainId
		web3pConfig.DomainNameServices[domainNameService] = web3pDomainNameServiceConfig
	}

	// Setup name address cache
	web3pConfig.NameAddrCacheDurationInMinutes = *cacheDurationMinutes

	// Create the web3:// client
	web3protocolClient = web3protocol.NewClient(&web3pConfig)

	// Set the verbosity level
	web3protocolClient.Logger.SetLevel(log.Level(config.Verbosity))
	web3protocolClient.Logger.SetFormatter(&log.TextFormatter{TimestampFormat: "2006-01-02 15:04:05", FullTimestamp: true})

	// Init the LRU page cache
	pageCache = golanglru2.NewLRU[PageCacheKey,PageCacheEntry](config.PageCache.MaxEntries, nil, time.Duration(config.PageCache.CacheDuration) * time.Second)
}

func initStats() {
	if len(*dbToken) > 0 {
		client := influxdb2.NewClient("http://localhost:8086", *dbToken)
		writeAPI = client.WriteAPIBlocking("web3q", "bucket0")
		defer client.Close()
		web3protocolClient.DomainNameResolutionCache.SetTracer(writeAPI)
	}
}

func main() {
	if *versionCheck {
		fmt.Println("web3url server version", versionInfo())
		return
	}
	initConfig()
	initWeb3protocolClient()
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

	if config.RunAsHttp {
		log.Infof("Serving on http://localhost:%v\n", config.ServerPort)
		log.Info("Running server in unsecure mode...")
		err := http.ListenAndServe(":"+config.ServerPort, nil)
		if err != nil {
			log.Fatalf("Cannot start server: %v\n", err)
			return
		}
	} else {
		log.Infof("Serving on https mode ")
		server := &http.Server{
			Addr: ":https",
			TLSConfig: &tls.Config{
				GetCertificate: GetCertificate,
				NextProtos:     []string{http2.NextProtoTLS, "http/1.1"},
				MinVersion:     tls.VersionTLS12,
			},
			MaxHeaderBytes: 32 << 20,
		}

		go http.ListenAndServe(":http", certManager.HTTPHandler(nil)) // 支持 http-01

		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("Cannot start server: %v\n", err)
		}
		// err := http.ListenAndServeTLS(":"+config.ServerPort, config.CertificateFile, config.KeyFile, nil)
		// if err != nil {
		// log.Fatalf("Cannot start server: %v\n", err)
		// }
	}
}
