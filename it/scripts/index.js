import { links } from '../data/links.mjs';
import { addLinks } from './add-links.mjs';
import { checkAllLinks } from './check-links.mjs';

async function run() {
    let newLinks = [];
    let addLinkErrors = [];

    try {
        const { links: created, errors } = await addLinks();
        newLinks = created;
        addLinkErrors = errors;
        console.log('New links', created);
        if (errors.length) {
            console.log('addLink errors:\n' + errors.join('\n'));
        }
        if (created.length === 0) {
            console.log('No new links added');
        }
    } catch (e) {
        // only catches unexpected top-level failures (e.g. PRIVATE_KEY missing)
        console.error('addLinks hard failure:', e.message);
        addLinkErrors.push(e.message);
    }

    const allLinks = [...links, ...newLinks];
    const newFailures = await checkAllLinks(allLinks);

    if (newFailures.size > 0) {
        console.log('Failed links: \n', Array.from(newFailures, ([k, v]) => `${k} -> ${v}`).join('\n'));
    } else {
        console.log('All links are OK');
    }
}
await run();