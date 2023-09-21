package web3protocol

type Config struct {
	NSDefaultChains map[string]string
	Name2Chain      map[string]string
	ChainConfigs    map[string]ChainConfig
	NameAddrCacheDurationInMinutes int
}

type ChainConfig struct {
	ChainID  string
	RPC      string
	NSConfig map[string]NameServiceInfo
}

type NameServiceInfo struct {
	NSType NameServiceType
	NSAddr string
}

type NameServiceType int

const (
	SimpleNameService NameServiceType = iota
	Web3QNameService
	EthereumNameService
)

var NsTypeMapping = map[string]NameServiceType{
	"W3NS": Web3QNameService,
	"ENS":  EthereumNameService,
	"SNS":  SimpleNameService,
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