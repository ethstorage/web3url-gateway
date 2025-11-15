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
    const tasks = [];
    if (await isBlobBaseFeeOK()) {
        tasks.push(addLink("https://rpc.delta.testnet.l2.quarkchain.io:8545", 1, 110011, "qkc-l2-t"));
        tasks.push(addLink("https://optimism-sepolia-public.nodies.app", 1, 11155420, "opsep"));
        tasks.push(addLink(L1_RPC, 2, 3333, "es-t"));
    }

    const results = await Promise.allSettled(tasks);
    const links = [];
    for (const r of results) {
        if (r.status === "fulfilled") {
            if (Array.isArray(r.value)) {
                links.push(...r.value);
            } else {
                links.push(r.value);
            }
        } else {
            throw new Error(formatAddLinkErr(r.reason));
        }
    }
    return links;
}

export async function addLink(rpc, type, chainId, shortName) {
    console.log("Adding link for", rpc, chainId);
    const pk = process.env.PRIVATE_KEY;
    // Balance before
    const linkProvider = new ethers.JsonRpcProvider(rpc);
    const wallet = new ethers.Wallet(pk, linkProvider);
    const address = await wallet.getAddress();
    const startBalance = await linkProvider.getBalance(address);

    const flatDirectory = await withTimeout(
        FlatDirectory.create({
            rpc: rpc,
            privateKey: pk,
        }),
        TIMEOUT,
        "FlatDirectory.create"
    );

    const contractAddress = await withTimeout(
        flatDirectory.deploy(),
        TIMEOUT,
        "flatDirectory.deploy"
    );

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

    await withTimeout(
        flatDirectory.upload({
            key: "test.txt",
            content: Buffer.from("hello link checker"),
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
        `https://${contractAddress}.${chainId}.w3link.io/test.txt`,
        `https://${contractAddress}.${chainId}.web3gateway.dev/test.txt`,
        `https://${contractAddress}.${shortName}.w3link.io/test.txt`,
        `https://${contractAddress}.${shortName}.web3gateway.dev/test.txt`,
    ];
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
    return Promise.race([
        promise,
        new Promise((_, reject) =>
            setTimeout(() => reject(new Error(`${label} timeout after ${ms}ms`)), ms)
        ),
    ]);
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
