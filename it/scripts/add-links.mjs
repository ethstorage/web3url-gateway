import dotenv from "dotenv";
import { FlatDirectory } from "ethstorage-sdk";
dotenv.config();

export async function addLinks() {
    console.log("Adding new links...");
    const flatDirectory = await FlatDirectory.create({
        rpc: "https://rpc.beta.testnet.l2.quarkchain.io:8545",
        privateKey: process.env.PRIVATE_KEY,
    });
    const contractAddress = await flatDirectory.deploy();

    await flatDirectory.upload({
        key: "test.txt",
        content: Buffer.from("hello link checker"),
        type: 2,
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
    return [
        `https://${contractAddress}.3337.w3link.io/test.txt`,
        `https://${contractAddress}.3337.web3gateway.dev/test.txt`
    ];
}

