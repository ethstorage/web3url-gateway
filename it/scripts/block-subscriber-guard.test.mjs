import assert from 'node:assert/strict';
import test from 'node:test';
import { ethers } from 'ethers';
import { installLatestBlockSubscriber, LatestBlockSubscriber } from './block-subscriber-guard.mjs';

const flush = () => new Promise(resolve => setImmediate(resolve));

class ProviderStub {
    blockNumber;
    emitted = [];
    #timer = 0;

    constructor(blockNumber) {
        this.blockNumber = blockNumber;
    }

    async getBlockNumber() {
        return this.blockNumber;
    }

    async emit(event, blockNumber) {
        this.emitted.push([event, blockNumber]);
    }

    _setTimeout() {
        return ++this.#timer;
    }

    _clearTimeout() {}
}

test('installs the guarded subscriber for JSON-RPC block events', () => {
    installLatestBlockSubscriber();
    installLatestBlockSubscriber();

    const provider = new ethers.JsonRpcProvider();
    const subscriber = provider._getSubscriber({ type: 'block' });

    assert.ok(subscriber instanceof LatestBlockSubscriber);
    provider.destroy();
});

test('emits only the latest block after a large forward jump', async () => {
    const provider = new ProviderStub(0);
    const subscriber = new LatestBlockSubscriber(provider);

    subscriber.start();
    await flush();
    subscriber.pause();

    provider.blockNumber = 47_225_444;
    subscriber.resume();
    await flush();
    subscriber.stop();

    assert.deepEqual(provider.emitted, [['block', 47_225_444]]);
});

test('ignores a block number regression and resumes from the previous height', async () => {
    const provider = new ProviderStub(47_225_440);
    const subscriber = new LatestBlockSubscriber(provider);

    subscriber.start();
    await flush();
    subscriber.pause();

    provider.blockNumber = 0;
    subscriber.resume();
    await flush();
    subscriber.pause();

    provider.blockNumber = 47_225_444;
    subscriber.resume();
    await flush();
    subscriber.stop();

    assert.deepEqual(provider.emitted, [['block', 47_225_444]]);
});
