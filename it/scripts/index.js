import { links } from '../data/links.mjs';
import { addLinks } from './add-links.mjs';
import { checkAllLinks } from './check-links.mjs';

async function run() {
    const results = await checkAllLinks(links);
    if (results.failures.length > 0) {
        console.log('Failed links: \n', results.failures.map(f => `- ${f.url}: ${f.error}`).join('\n'));
    } else {
        console.log('All links are OK');
    }

    const newLinks = await addLinks();
    console.log('new links', newLinks);

    const newResults = await checkAllLinks(newLinks);
    if (newResults.failures.length > 0) {
        console.log('results', results.all.map(a => `- ${a.url}`).join('\n'));
    } else {
        console.log('New links are OK');
    }
}

run();