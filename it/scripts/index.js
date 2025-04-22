import { links } from '../data/links.mjs';
import { addLinks } from './add-links.mjs';
import { checkAllLinks } from './check-links.mjs';

async function run() {
    const results = await checkAllLinks(links);
    if (results.success) {
        console.log('All links are OK');
    } else {
        console.log('results', JSON.stringify(results.failures, null, 2));
    }

    const newLinks = await addLinks();
    console.log('new links', newLinks);

    const newResults = await checkAllLinks(newLinks);
    if (newResults.success) {
        console.log('New links are OK');
    } else {
        console.log('results', JSON.stringify(newResults.failures, null, 2));
    }
}

run();