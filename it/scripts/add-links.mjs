import dotenv from "dotenv";
import { ethers } from "ethers";
import { FlatDirectory } from "ethstorage-sdk";
dotenv.config();

const TIMEOUT = process.env.TIMEOUT || 180000; // 3 minutes
const BLOB_BASE_FEE_CAP = process.env.BLOB_BASE_FEE_CAP || 100000000000; // 10 Gwei
const L1_RPC_MAINNET = process.env.L1_RPC_MAINNET;
const L1_RPC_SEP = process.env.L1_RPC_SEP || "http://65.108.230.142:8545";
const DEPLOY_GAS_PRICE_CAP_GWEI = 1;
const FIXED_DECIMALS = 9;
const PREDEPLOYED_CONTRACTS = {
    3333: "0x2f3D6e07213168D0DA0A74AFA824C4075E79a678",
    110011: "0x024d62c3E57692e366310ee50e5D9d845Ec09f3F",
    11155420: "0xF756F3153Ac23Ebd0bec22b8637E83E28B059b33",
    84532: "0x06F85a74A01Af29EacdCD5ef4f64CB3c5703323c",
    100011: "0x9132bE118aD6cEBd9ce4B0FfFb682E84cE889B94",
};



export async function addLinks() {

    if (!process.env.PRIVATE_KEY || process.env.PRIVATE_KEY.length === 0) {
        throw new Error("PRIVATE_KEY is not set.");
    }

    console.log("Adding new links...");
    const configs = [];
    const results = [];
    const errors = [];
    const summaries = [];
    const l1FeeRows = [];

    const sepoliaFeeInfo = await fetchL1GasInfo(L1_RPC_SEP, "Sepolia");
    if (sepoliaFeeInfo) {
        l1FeeRows.push({
            network: "Sepolia",
            blobFee: sepoliaFeeInfo.blobBaseFeeGwei,
            gasPrice: sepoliaFeeInfo.l1GasPriceGwei,
        });
        if (sepoliaFeeInfo.ok && sepoliaFeeInfo.blobBaseFee <= BLOB_BASE_FEE_CAP) {
            configs.push(
                { rpc: L1_RPC_SEP, type: 2, chainId: 3333, shortName: "es-t" },
                { rpc: "https://rpc.delta.testnet.l2.quarkchain.io:8545", type: 1, chainId: 110011, shortName: "qkc-l2-t" },
                { rpc: "https://optimism-sepolia-public.nodies.app", type: 1, chainId: 11155420, shortName: "opsep" },
                { rpc: "https://base-sepolia-rpc.publicnode.com", type: 1, chainId: 84532, shortName: "basesep" },
            );
        }
    }

    const mainnetFeeInfo = await fetchL1GasInfo(L1_RPC_MAINNET, "Mainnet");
    if (mainnetFeeInfo) {
        l1FeeRows.push({
            network: "Mainnet",
            blobFee: mainnetFeeInfo.blobBaseFeeGwei,
            gasPrice: mainnetFeeInfo.l1GasPriceGwei,
        });
        if (mainnetFeeInfo.ok && mainnetFeeInfo.blobBaseFee <= BLOB_BASE_FEE_CAP) {
            configs.push(
                { rpc: "https://rpc.mainnet.l2.quarkchain.io:8545", type: 1, chainId: 100011, shortName: "qkc-l2" },
            );
        }
    }

    const l1InfoTable = formatL1GasInfo(l1FeeRows);
    if (l1InfoTable) {
        console.log("==== L1 Gas Price Info ====");
        console.table(l1FeeRows);
    }

    if (configs.length > 0) {
        const settled = await Promise.allSettled(
            configs.map(config =>
                retryAsync(
                    () => addLink(config.rpc, config.type, config.chainId, config.shortName),
                    {
                        maxAttempts: 3,
                        delayMs: 2000,
                        label: `addLink chain ${config.chainId}`,
                    }
                )
            )
        );
        settled.forEach((result, index) => {
            if (result.status === 'fulfilled') {
                const { links: linkList = [], summary } = result.value || {};
                if (linkList.length) {
                    results.push(...linkList);
                }
                if (summary) {
                    summaries.push(summary);
                }
            } else {
                const errMsg = formatAddLinkErr(result.reason);
                console.error(`${errMsg} on chain ${configs[index].chainId}, status: ${result.status}`);
                errors.push(`${errMsg} on chain ${configs[index].chainId}`);
                const fallbackSummary = result.reason?.summary ?? {
                    chainId: configs[index].chainId,
                    shortName: configs[index].shortName,
                    type: configs[index].type,
                    gasPrice: result.reason?.gasPrice ?? '--',
                    deployCost: '--',
                    uploadCost: '--',
                    cost: '(tx failed)',
                    after: '--',
                };
                fallbackSummary.cost = fallbackSummary.cost || '(tx failed)';
                fallbackSummary.deployCost = fallbackSummary.deployCost ?? '--';
                fallbackSummary.uploadCost = fallbackSummary.uploadCost ?? '--';
                fallbackSummary.gasPrice = fallbackSummary.gasPrice ?? '--';
                fallbackSummary.after = fallbackSummary.after ?? '--';
                summaries.push(fallbackSummary);
            }
        });
    }

    let summaryTable = '';
    if (summaries.length) {
        console.log("==== Cost Summary ====");
        console.table(summaries);
        summaryTable = formatCostSummary(summaries);
        if (summaryTable) {
            console.log('Cost summary table:\n' + summaryTable);
        }
    }
    return { links: results, errors, l1InfoTable, summaryTable };
}

export async function addLink(rpc, type, chainId, shortName) {
    console.log("Adding link for", rpc, chainId);
    const pk = process.env.PRIVATE_KEY;
    const linkProvider = new ethers.JsonRpcProvider(rpc);
    const summary = {
        chainId,
        shortName,
        type,
        gasPrice: '--',
        deployCost: '--',
        uploadCost: '--',
        cost: '--',
        after: '--',
    };

    try {
        const wallet = new ethers.Wallet(pk, linkProvider);
        const address = await wallet.getAddress();
        const startBalance = await linkProvider.getBalance(address);

        const feeData = await linkProvider.getFeeData();
        const gasPriceWei = feeData.maxFeePerGas ?? feeData.gasPrice ?? 0n;
        const gasPriceGwei = gasPriceWei ? `${formatGweiFixed(gasPriceWei)} Gwei` : 'n/a';
        const gasPriceGweiValue = gasPriceWei ? Number(ethers.formatUnits(gasPriceWei, 'gwei')) : 0;
        summary.gasPrice = gasPriceGwei;

        let contractAddress;
        let balanceBeforeUpload = startBalance;
        let deployCostWei = 0n;
        let skippedDeployment = false;

        const predeployed = PREDEPLOYED_CONTRACTS[chainId];
        const shouldSkipDeploy = gasPriceGweiValue > DEPLOY_GAS_PRICE_CAP_GWEI;

        const usePredeployed = (reason, deployCostOverride) => {
            if (!predeployed) {
                throw new Error(`${reason} but no predeployed FlatDirectory is configured for chain ${chainId}.`);
            }
            skippedDeployment = true;
            contractAddress = predeployed;
            if (deployCostOverride) {
                summary.deployCost = deployCostOverride;
            } else if (summary.deployCost === '--') {
                summary.deployCost = '0.0 (predeployed)';
            }
            console.log(`${reason} Using predeployed contract ${contractAddress} on chain ${chainId}.`);
        };

        if (shouldSkipDeploy) {
            usePredeployed(`Gas price ${gasPriceGweiValue} gwei exceeds cap ${DEPLOY_GAS_PRICE_CAP_GWEI} gwei.`);
        } else {
            let deployDirectory;
            try {
                deployDirectory = await withTimeout(
                    FlatDirectory.create({
                        rpc,
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
            } catch (err) {
                console.error(`FlatDirectory deployment failed on chain ${chainId}:`, err?.message || err);
                const postFailureBalance = await linkProvider.getBalance(address);
                deployCostWei = startBalance > postFailureBalance ? startBalance - postFailureBalance : deployCostWei;
                balanceBeforeUpload = postFailureBalance;
                const overrideCost = deployCostWei > 0n
                    ? `${formatEtherFixed(deployCostWei)} (failed deploy)`
                    : '0.0 (predeployed)';
                usePredeployed('Deployment failed.', overrideCost);
            } finally {
                await deployDirectory?.close?.();
            }

            if (!skippedDeployment) {
                const postDeployBalance = await linkProvider.getBalance(address);
                deployCostWei = startBalance > postDeployBalance ? startBalance - postDeployBalance : 0n;
                balanceBeforeUpload = postDeployBalance;
                summary.deployCost = formatEtherFixed(deployCostWei);
            }
        }

        if (!contractAddress) {
            throw new Error(`No flatDirectory contract available for chain ${chainId}.`);
        }

        const flatDirectory = await withTimeout(
            FlatDirectory.create({
                rpc,
                privateKey: pk,
                address: contractAddress,
            }),
            TIMEOUT,
            "FlatDirectory.create"
        );

        const beijingTime = new Date().toLocaleString('zh-CN', {
            timeZone: 'Asia/Shanghai',
        });

        const [dateKey, timePart] = beijingTime.split(' ');
        console.log(dateKey, timePart);

        let uploadError;
        try {
            await withTimeout(
                flatDirectory.upload({
                    key: dateKey,
                    content: Buffer.from(`hello link checker - at ${dateKey} ${timePart}`),
                    type,
                    callback: {
                        onProgress: function (progress, count, isChange) {
                            console.log(`Progress: ${progress}%, count: ${count}, isChange: ${isChange}`);
                        },
                        onFail: function (err) {
                            console.log("Upload failed", "chainId", chainId, "error", err);
                        },
                        onFinish: function (totalUploadChunks, totalUploadSize, totalStorageCost) {
                            console.log("Upload finished", "totalUploadSize:", totalUploadSize, "totalStorageCost:", totalStorageCost, "chainId:", chainId);
                        },
                    },
                }),
                TIMEOUT,
                "flatDirectory.upload"
            );
        } catch (err) {
            uploadError = err;
        } finally {
            await flatDirectory.close?.();
        }

        const endBalance = await linkProvider.getBalance(address);
        const uploadCostWei = balanceBeforeUpload > endBalance ? balanceBeforeUpload - endBalance : 0n;
        const afterEth = formatEtherFixed(endBalance);

        const deployCostEth = skippedDeployment ? '0.0 (predeployed)' : formatEtherFixed(deployCostWei);
        const uploadCostEth = formatEtherFixed(uploadCostWei);
        const totalCostWei = deployCostWei + uploadCostWei;
        const baseCostEth = formatEtherFixed(totalCostWei);
        const displayCost = skippedDeployment
            ? `${baseCostEth}`
            : baseCostEth;

        summary.deployCost = summary.deployCost === '--' ? deployCostEth : summary.deployCost;
        summary.uploadCost = uploadCostEth;
        summary.cost = displayCost;
        summary.after = afterEth;

        if (uploadError) {
            const enriched = new Error(uploadError?.message || String(uploadError));
            enriched.summary = summary;
            throw enriched;
        }

        return {
            links: [
                `https://${contractAddress}.${chainId}.w3link.io/${dateKey}`,
                `https://${contractAddress}.${chainId}.web3gateway.dev/${dateKey}`,
                `https://${contractAddress}.${shortName}.w3link.io/${dateKey}`,
                `https://${contractAddress}.${shortName}.web3gateway.dev/${dateKey}`,
            ],
            summary,
        };
    } catch (err) {
        err.summary = err.summary ?? summary;
        throw err;
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

function formatCostSummary(rows) {
    if (!Array.isArray(rows) || rows.length === 0) {
        return '';
    }
    const headers = ['Chain ID', 'Short', 'Type', 'Gas Price', 'Deploy Cost', 'Upload Cost', 'Total Cost', 'Balance'];
    const bodyRows = rows.map(row => [
        row.chainId ?? '',
        row.shortName ?? '',
        row.type ?? '',
        row.gasPrice ?? '',
        row.deployCost ?? '',
        row.uploadCost ?? '',
        row.cost ?? '',
        row.after ?? '',
    ]);
    return renderHtmlTable(headers, bodyRows);
}

function formatL1GasInfo(rows) {
    if (!Array.isArray(rows) || rows.length === 0) {
        return '';
    }
    const headers = ['L1 Network', 'Blob Base Fee', 'Gas Price'];
    const bodyRows = rows.map(row => [
        row.network ?? '',
        row.blobFee ?? '',
        row.gasPrice ?? 'n/a',
    ]);
    return renderHtmlTable(headers, bodyRows);
}

function renderHtmlTable(headers, rows) {
    if (!Array.isArray(headers) || headers.length === 0 || !Array.isArray(rows)) {
        return '';
    }
    const tableStyle = 'style="border-collapse: collapse; width: 100%; font-family: SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px;"';
    const headerCellStyle = 'style="border: 1px solid #d0d7de; padding: 6px 8px; background: #f6f8fa; text-align: left;"';
    const cellStyle = 'style="border: 1px solid #d0d7de; padding: 6px 8px; text-align: left;"';
    const thead = `<thead><tr>${headers.map(text => `<th ${headerCellStyle}>${escapeHtml(text)}</th>`).join('')}</tr></thead>`;
    const tbodyRows = rows
        .map(row => `<tr>${row.map(value => `<td ${cellStyle}>${escapeHtml(value ?? '')}</td>`).join('')}</tr>`)
        .join('');
    const tbody = `<tbody>${tbodyRows}</tbody>`;
    return `<table ${tableStyle}>${thead}${tbody}</table>`;
}

function escapeHtml(value) {
    const str = value == null ? '' : String(value);
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function zeroFixed(fractionDigits = FIXED_DECIMALS) {
    return `0.${'0'.repeat(fractionDigits)}`;
}

function formatNumberFixed(value, fractionDigits = FIXED_DECIMALS) {
    const num = Number(value);
    if (!Number.isFinite(num)) {
        if (value === null || value === undefined) {
            return zeroFixed(fractionDigits);
        }
        return String(value);
    }
    return num.toFixed(fractionDigits);
}

function formatEtherFixed(weiValue, fractionDigits = FIXED_DECIMALS) {
    if (weiValue == null) {
        return zeroFixed(fractionDigits);
    }
    return formatNumberFixed(ethers.formatEther(weiValue), fractionDigits);
}

function formatGweiFixed(weiValue, fractionDigits = FIXED_DECIMALS) {
    if (weiValue == null) {
        return zeroFixed(fractionDigits);
    }
    return formatNumberFixed(ethers.formatUnits(weiValue, 'gwei'), fractionDigits);
}

function formatGweiFromWeiNumber(value, fractionDigits = FIXED_DECIMALS) {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
        return 'n/a';
    }
    const gwei = value / 1e9;
    return `${gwei.toFixed(fractionDigits)} Gwei`;
}

async function retryAsync(fn, { maxAttempts = 3, delayMs = 1000, label = 'operation' } = {}) {
    let attempt = 0;
    let lastError;
    while (attempt < maxAttempts) {
        attempt++;
        try {
            return await fn();
        } catch (err) {
            lastError = err;
            const message = err?.message || String(err);
            console.warn(`${label} attempt ${attempt} failed: ${message}`);
            if (attempt >= maxAttempts) {
                break;
            }
            await new Promise(resolve => setTimeout(resolve, delayMs));
        }
    }
    throw lastError;
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


async function fetchL1GasInfo(l1RPC, chainName) {
    if (!l1RPC || l1RPC.length === 0) {
        console.error("L1 RPC is not set for", chainName);
        return { ok: false, chainName, blobBaseFee: Number.POSITIVE_INFINITY, blobBaseFeeGwei: 'rpc missing' };
    }
    const provider = new ethers.JsonRpcProvider(l1RPC);
    try {
        const blobFeeResponse = await provider.send("eth_blobBaseFee", []);
        const gasPriceResponse = await provider.send("eth_gasPrice", []);

        if (!blobFeeResponse || blobFeeResponse === '0x0' || blobFeeResponse === 0) {
            console.error("Blob base fee is not available for", chainName);
            return { ok: false, chainName, blobBaseFee: Number.POSITIVE_INFINITY, blobBaseFeeGwei: 'n/a' };
        }
        const blobBaseFee = Number.parseInt(blobFeeResponse, 16);
        const blobBaseFeeGwei = formatGweiFromWeiNumber(blobBaseFee);

        let l1GasPrice = Number.POSITIVE_INFINITY;
        let l1GasPriceGwei = 'n/a';
        if (gasPriceResponse) {
            try {
                l1GasPrice = Number.parseInt(gasPriceResponse, 16);
                l1GasPriceGwei = formatGweiFromWeiNumber(l1GasPrice);
            } catch (err) {
                console.warn('Failed to parse L1 gas price for', chainName, err);
            }
        }
        return { ok: true, chainName, blobBaseFee, blobBaseFeeGwei, l1GasPrice, l1GasPriceGwei };
    } catch (err) {
        console.error("Failed to fetch blob base fee for", chainName, err);
        return { ok: false, chainName, blobBaseFee: Number.POSITIVE_INFINITY, blobBaseFeeGwei: 'error' };
    } finally {
        provider.destroy?.();
    }
}
