./server \
    -setNS 3334,w3q,w3ns,0xD379B91ac6a93AF106802EB076d16A54E3519CED  \
    -setChain 3334,w3q-g,https://galileo.web3q.io:8545  \
    -setNSChain w3q,3334 \
    -setNSChain eth,5 \
    -cacheDurationMinutes 10 \
    "$@"