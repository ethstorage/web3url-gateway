package web3protocol

import (
    "context"
    "sync"
    "time"

    "github.com/ethereum/go-ethereum/common"
    influxdb2 "github.com/influxdata/influxdb-client-go/v2"
    "github.com/influxdata/influxdb-client-go/v2/api"
    // log "github.com/sirupsen/logrus"
)

type solvedAddr struct {
    nsChainAndName string
    targetChain    int
    addr           common.Address
}

type cachedAddr struct {
    solvedAddr
    expire int64
}

type localCache struct {
    addrs           map[string]cachedAddr
    lifetime        time.Duration
    cleanupInterval time.Duration
    mu              sync.RWMutex
    tracer          api.WriteAPIBlocking
}

func newLocalCache(lifetime, cleanupInterval time.Duration) *localCache {
    lc := &localCache{
        addrs:           make(map[string]cachedAddr),
        lifetime:        lifetime,
        cleanupInterval: cleanupInterval,
    }
    go func() {
        lc.cleanupLoop()
    }()
    // log.Infof("[cache] new lifetime=%v, cleanupInterval=%v", lifetime, cleanupInterval)
    return lc
}

func (lc *localCache) add(nsChainAndName string, addr common.Address, targetChain int) {
    lc.mu.Lock()
    defer lc.mu.Unlock()
    lc.addrs[nsChainAndName] = cachedAddr{
        solvedAddr{
            nsChainAndName: nsChainAndName,
            targetChain:    targetChain,
            addr:           addr,
        },
        time.Now().Add(lc.lifetime).Unix(),
    }
    lc.trace(nsChainAndName, "add")
    // log.Debugf("[cache] add %s\n", nsChainAndName)
}

func (lc *localCache) get(nsChainAndName string) (common.Address, int, bool) {
    lc.mu.Lock()
    defer lc.mu.Unlock()
    ca, ok := lc.addrs[nsChainAndName]
    if !ok {
        return common.Address{}, 0, false
    }
    lc.trace(nsChainAndName, "hit")
    // log.Debugf("[cache] hit %s\n", nsChainAndName)
    return ca.addr, ca.targetChain, true
}

func (lc *localCache) cleanupLoop() {
    t := time.NewTicker(lc.cleanupInterval)
    defer t.Stop()
    for {
        <-t.C
        lc.mu.Lock()
        // log.Infof("[cache] size=%v \n", len(lc.addrs))
        for key, ca := range lc.addrs {
            // log.Infof("[cache] key=%s\n", key)
            if ca.expire <= time.Now().Unix() {
                delete(lc.addrs, key)
                lc.trace(key, "delete")
                // log.Infof("[cache] cleanup %s\n", key)
            }
        }
        // log.Infof("[cache] size=%v \n", len(lc.addrs))
        lc.mu.Unlock()
    }
}

func (lc *localCache) setTracer(writeAPI api.WriteAPIBlocking) {
    lc.tracer = writeAPI
}

func (lc *localCache) trace(key, tipe string) {
    if lc.tracer != nil {
        point := influxdb2.NewPointWithMeasurement("cache_stats").
            AddTag("key", key).
            AddTag("type", tipe).
            AddField("size", len(lc.addrs)).
            SetTime(time.Now())
        if er := lc.tracer.WritePoint(context.Background(), point); er != nil {
            // log.Errorln("db err", er)
        }
    }
}
