import { links } from '../data/links.mjs';
import { addLinks } from './add-links.mjs';
import { checkAllLinks } from './check-links.mjs';

async function run() {

    const { links: newLinks, errors: addLinkErrors } = await addLinks();
    if (addLinkErrors.length > 0) {
        console.error('Add link errors:', addLinkErrors.join('\n'));
    }
    console.log('New links', newLinks);
    if (newLinks.length === 0) {
        console.log('No new links added');
        return;
    }
    const allLinks = [...links, ...newLinks];
    const newFailures = await checkAllLinks(allLinks);
    if (newFailures.size > 0) {
        console.log('Failed links: \n', Array.from(newFailures, ([key, value]) => `${key} -> ${value}`).join('\n'));
    } else {
        console.log('All links are OK');
    }
}

await run();