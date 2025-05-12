import { links } from '../data/links.mjs';
import { addLinks } from './add-links.mjs';
import { checkAllLinks } from './check-links.mjs';

async function run() {
    let failures = await checkAllLinks(links);
    if (failures.size > 0) {
        console.log('Failed links: \n', Array.from(failures, ([key, value]) => `${key} -> ${value}`).join('\n'));
    } else {
        console.log('All links are OK: totally', links.length);
    }

    const newLinks = await addLinks();
    console.log('New links', newLinks);

    failures = await checkAllLinks(newLinks);
    if (failures.size > 0) {
        console.log('Failed links: \n', Array.from(failures, ([key, value]) => `${key} -> ${value}`).join('\n'));
    } else {
        console.log('New links are OK');
    }
}

await run();