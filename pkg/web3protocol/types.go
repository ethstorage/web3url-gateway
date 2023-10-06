package web3protocol

type Config struct {
    NSDefaultChains map[string]int
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


type Web3Error struct {
    HttpCode int
    err  string
}

func (e *Web3Error) Error() string {
    return e.err
}