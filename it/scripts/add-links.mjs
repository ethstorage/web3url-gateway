import dotenv from "dotenv";
import { FlatDirectory } from "ethstorage-sdk";
dotenv.config();

export async function addLinks() {
    console.log("Adding new links...");
    const links = await Promise.all([
        // addLink("https://rpc.gamma.testnet.l2.quarkchain.io:8545", 1, 110011, "qkc-l2-t"),
        addLink("https://rpc.beta.testnet.l2.quarkchain.io:8545", 2, 3337, "es-d"),
    ]);
    return links.flat();
}

export async function addLink(rpc, type, chainId, shortName) {
    console.log("Adding link for", rpc, chainId);
    if (!process.env.PRIVATE_KEY || process.env.PRIVATE_KEY.length === 0) {
        throw new Error("PRIVATE_KEY is not set.");
    }
    const flatDirectory = await FlatDirectory.create({
        rpc: rpc,
        privateKey: process.env.PRIVATE_KEY,
    });
    const contractAddress = await flatDirectory.deploy();

    await flatDirectory.upload({
        key: "test.txt",
        content: Buffer.from("hello link checker"),
        type: type,
        callback: {
            onProgress: function (progress, count, isChange) {
                console.log(`Progress: ${progress}%, count: ${count}, isChange: ${isChange}`);
            },
            onFail: function (err) {
                console.log(err);
            },
            onFinish: function (totalUploadChunks, totalUploadSize, totalStorageCost) {
                console.log("totalUploadChunks", totalUploadChunks);
                console.log("totalUploadSize", totalUploadSize);
                console.log("totalStorageCost", totalStorageCost);
            }
        },
    });
    await flatDirectory.close();

    return [
        `https://${contractAddress}.${chainId}.w3link.io/test.txt`,
        `https://${contractAddress}.${chainId}.web3gateway.dev/test.txt`,
        `https://${contractAddress}.${shortName}.w3link.io/test.txt`,
        `https://${contractAddress}.${shortName}.web3gateway.dev/test.txt`,
    ];
}

