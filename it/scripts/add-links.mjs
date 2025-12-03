import dotenv from "dotenv";
import { ethers } from "ethers";
import { FlatDirectory } from "ethstorage-sdk";
dotenv.config();

const TIMEOUT = process.env.TIMEOUT || 180000; // 3 minutes
const BLOB_BASE_FEE_CAP = process.env.BLOB_BASE_FEE_CAP || 100000000000; // 10 gwei
const L1_RPC = process.env.L1_RPC || "http://65.108.230.142:8545";


const provider = new ethers.JsonRpcProvider(L1_RPC);

export async function addLinks() {

    if (!process.env.PRIVATE_KEY || process.env.PRIVATE_KEY.length === 0) {
        throw new Error("PRIVATE_KEY is not set.");
    }

    console.log("Adding new links...");
    const results = [];
    const errors = [];

    if (await isBlobBaseFeeOK()) {
        const configs = [
            { rpc: L1_RPC, type: 2, chainId: 3333, shortName: "es-t" },
            { rpc: "https://rpc.mainnet.l2.quarkchain.io:8545", type: 1, chainId: 100011, shortName: "qkc-l2" },
            { rpc: "https://rpc.delta.testnet.l2.quarkchain.io:8545", type: 1, chainId: 110011, shortName: "qkc-l2-t" },
            { rpc: "https://base-sepolia.drpc.org", type: 1, chainId: 84532, shortName: "basesep" },
            { rpc: "https://optimism-sepolia-public.nodies.app", type: 1, chainId: 11155420, shortName: "opsep" }
        ];

        const settled = await Promise.allSettled(
            configs.map(config => addLink(config.rpc, config.type, config.chainId, config.shortName))
        );

        settled.forEach((result, index) => {
            if (result.status === 'fulfilled') {
                results.push(...result.value);
            } else {
                const errMsg = formatAddLinkErr(result.reason);
                console.error(errMsg);
                errors.push(`${errMsg} on chain ${configs[index].chainId}`);
            }
        });
    }
    
    provider.destroy();
    
    return { links: results, errors };
}

export async function addLink(rpc, type, chainId, shortName) {
    console.log("Adding link for", rpc, chainId);
    const pk = process.env.PRIVATE_KEY;
    // Balance before
    const linkProvider = new ethers.JsonRpcProvider(rpc);
    try {
        const wallet = new ethers.Wallet(pk, linkProvider);
        const address = await wallet.getAddress();
        const startBalance = await linkProvider.getBalance(address);

        let contractAddress;

        // Use existing flatDirectory for mainnet QuarkChain L2 to save cost
        if (chainId === 100011) {
            contractAddress = "0x9132bE118aD6cEBd9ce4B0FfFb682E84cE889B94";
            console.log("Using existing flatDirectory contract:", contractAddress, "on chainId:", chainId);
        } else {
            let deployDirectory;
            try {
                deployDirectory = await withTimeout(
                    FlatDirectory.create({
                        rpc: rpc,
                        privateKey: pk,
                    }),
                    TIMEOUT,
                    "FlatDirectory.create"
                );

                contractAddress = await withTimeout(
                    deployDirectory.deploy(),
                    TIMEOUT,
                    "flatDirectory.deploy"
                );
            } finally {
                await deployDirectory?.close?.();
            }

            if (!contractAddress) {
                console.error("Error: no contract address found at", rpc, "chainId:", chainId);
                throw new Error("Failed to deploy flatDirectory.");
            }
            // check contract code every 5 seconds for up to 1 minute
            let code = "0x";
            let attempts = 0;
            const maxAttempts = 12;

            while ((code === "0x" || code === "0x0") && attempts < maxAttempts) {
                console.log("Waiting for flatDirectory deployment...", "chainId:", chainId, "attempt:", attempts + 1);
                await new Promise(resolve => setTimeout(resolve, 5000));
                code = await linkProvider.getCode(contractAddress);
                attempts++;
            }

            if (code === "0x" || code === "0x0") {
                console.error("Error: no contract code found at", contractAddress, "on", rpc, "chainId:", chainId);
                throw new Error("Failed to deploy flatDirectory.");
            }
        }

        const flatDirectory = await withTimeout(
            FlatDirectory.create({
                rpc: rpc,
                privateKey: pk,
                address: contractAddress,
            }),
            TIMEOUT,
            "FlatDirectory.create"
        );

        const dateTime = new Date().toLocaleString('zh-CN').split(' ');
        const dateKey = dateTime[0];

        await withTimeout(
            flatDirectory.upload({
                key: dateKey,
                content: Buffer.from(`hello link checker - at ${dateTime[1]}`),
                type: type,
                callback: {
                    onProgress: function (progress, count, isChange) {
                        console.log(`Progress: ${progress}%, count: ${count}, isChange: ${isChange}`);
                    },
                    onFail: function (err) {
                        console.log("Upload failed", "chainId", chainId, "error", err);
                    },
                    onFinish: function (totalUploadChunks, totalUploadSize, totalStorageCost) {
                        console.log("Upload finished.", "chainId:", chainId);
                    },
                },
            }),
            TIMEOUT,
            "flatDirectory.upload"
        );

        await flatDirectory.close();

        // Balance after and table summary
        const endBalance = await linkProvider.getBalance(address);
        const costWei = startBalance - endBalance;
        const beforeEth = ethers.formatEther(startBalance);
        const afterEth = ethers.formatEther(endBalance);
        const costEth = ethers.formatEther(costWei);
        console.log("==== Balance Summary ====", "address:", address);
        console.table([
            {
                Chain: chainId,
                "Before": beforeEth,
                "After": afterEth,
                "Cost": costEth,
            },
        ]);

        return [
            `https://${contractAddress}.${chainId}.w3link.io/${dateKey}`,
            `https://${contractAddress}.${chainId}.web3gateway.dev/${dateKey}`,
            `https://${contractAddress}.${shortName}.w3link.io/${dateKey}`,
            `https://${contractAddress}.${shortName}.web3gateway.dev/${dateKey}`,
        ];
    } finally {
        linkProvider.destroy();
    }
}


function formatAddLinkErr(reason) {
    const rawMessage = (() => {
        if (!reason) {
            return "";
        }
        if (typeof reason === "string") {
            return reason;
        }
        if (reason?.message && typeof reason.message === "string") {
            return reason.message;
        }
        try {
            return JSON.stringify(reason);
        } catch {
            return String(reason);
        }
    })();

    console.log("Raw error message:", rawMessage);

    const nestedMessageMatch = rawMessage.match(/"message"\s*:\s*"([^"]+)"/);
    const sanitized = nestedMessageMatch
        ? nestedMessageMatch[1]
        : rawMessage;

    const message = sanitized || "unknown error";
    return `add link failed: ${JSON.stringify(message)}`;
}


function withTimeout(promise, ms, label) {
    let timeoutId;
    const timeoutPromise = new Promise((_, reject) => {
        timeoutId = setTimeout(() => reject(new Error(`${label} timeout after ${ms}ms`)), ms);
    });

    return Promise.race([promise, timeoutPromise]).finally(() => {
        if (timeoutId) {
            clearTimeout(timeoutId);
        }
    });
}


async function isBlobBaseFeeOK() {
    const response = await provider.send("eth_blobBaseFee", []);
    if (!response || response === '0x0' || response === 0) {
        console.error("Blob base fee is not available.");
        return false;
    }
    const blobBaseFee = parseInt(response, 16);
    console.log("Blob base fee:", blobBaseFee / 1e9, "Gwei");
    if (blobBaseFee > BLOB_BASE_FEE_CAP) {
        console.log("Blob base fee is too high!");
        return false;
    }
    return true;
}
