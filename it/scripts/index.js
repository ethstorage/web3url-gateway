import { addLinks } from './add-links.mjs';
import { checkAllLinks } from './check-links.mjs';

async function run() {
    const failures = await checkAllLinks(links);
    if (failures.size > 0) {
        console.log('Failed links: \n', Array.from(failures, ([key, value]) => `${key} -> ${value}`).join('\n'));
    } else {
        console.log('All links are OK: totally', links.length);
    }

    const newLinks = await addLinks();
    console.log('New links', newLinks);

    const newFailures = await checkAllLinks(newLinks);
    if (newFailures.size > 0) {
        console.log('Failed new links: \n', Array.from(newFailures, ([key, value]) => `${key} -> ${value}`).join('\n'));
    } else {
        console.log('New links are OK');
    }
}

await run();