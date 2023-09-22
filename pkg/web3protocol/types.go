package web3protocol

type Config struct {
	Name2Chain      map[string]int
	ChainConfigs    map[int]ChainConfig
	NameAddrCacheDurationInMinutes int
}

type ChainConfig struct {
	ChainID  int
	RPC      string
	NSConfig map[string]NameServiceInfo
}

type NameServiceInfo struct {
	NSType DomainNameService
	NSAddr string
}

type ResolveMode string

const (
	ResolveModeAuto = "auto"
	ResolveModeManual = "manual"
	ResolveModeResourceRequests = "5219"
)


type Web3Error struct {
	HttpCode int
	err  string
}

func (e *Web3Error) Error() string {
	return e.err
}