import { ethers } from 'ethers';

const installed = Symbol.for('web3url-gateway.latest-block-subscriber');

// ethers replays every skipped height. A faulty RPC regression can therefore
// turn the next normal height into millions of queued block events.
export class LatestBlockSubscriber {
    #provider;
    #poller = null;
    #interval = 4000;
    #blockNumber = -2;

    constructor(provider) {
        this.#provider = provider;
    }

    get pollingInterval() {
        return this.#interval;
    }

    set pollingInterval(value) {
        this.#interval = value;
    }

    async #poll() {
        try {
            const blockNumber = await this.#provider.getBlockNumber();
            if (this.#blockNumber === -2) {
                this.#blockNumber = blockNumber;
            } else if (blockNumber > this.#blockNumber) {
                const previousBlock = this.#blockNumber;
                const skippedEvents = blockNumber - previousBlock - 1;
                await this.#provider.emit('block', blockNumber);
                this.#blockNumber = blockNumber;
                if (skippedEvents > 0) {
                    console.info(`[block-subscriber-guard] Coalesced block gap: last=${previousBlock}, current=${blockNumber}, emitted=${blockNumber}, skipped=${skippedEvents} intermediate block events.`);
                }
            } else if (blockNumber < this.#blockNumber) {
                console.warn(`[block-subscriber-guard] Ignoring RPC block height regression: last=${this.#blockNumber}, received=${blockNumber}; keeping last height.`);
            }
        } catch {
            // Match ethers' polling subscriber: retry on the next interval.
        }

        if (this.#poller !== null) {
            this.#poller = this.#provider._setTimeout(this.#poll.bind(this), this.#interval);
        }
    }

    start() {
        if (this.#poller !== null) return;
        this.#poller = this.#provider._setTimeout(this.#poll.bind(this), this.#interval);
        this.#poll();
    }

    stop() {
        if (this.#poller === null) return;
        this.#provider._clearTimeout(this.#poller);
        this.#poller = null;
    }

    pause(dropWhilePaused) {
        this.stop();
        if (dropWhilePaused) this.#blockNumber = -2;
    }

    resume() {
        this.start();
    }
}

export function installLatestBlockSubscriber() {
    // ethstorage-sdk creates its JsonRpcProvider instances internally.
    const prototype = ethers.JsonRpcProvider.prototype;
    if (prototype[installed]) return;

    const getSubscriber = prototype._getSubscriber;
    Object.defineProperty(prototype, installed, { value: true });
    prototype._getSubscriber = function (subscription) {
        if (subscription.type === 'block') {
            const subscriber = new LatestBlockSubscriber(this);
            subscriber.pollingInterval = this.pollingInterval;
            return subscriber;
        }
        return getSubscriber.call(this, subscription);
    };
}
