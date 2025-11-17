import { links } from '../data/links.mjs';
import { addLinks } from './add-links.mjs';
import { checkAllLinks } from './check-links.mjs';

async function run() {
    let newLinks = [];
    let addLinksError = null;
    
    try {
        newLinks = await addLinks();
        console.log('New links', newLinks);
        if (newLinks.length === 0) {
            console.log('No new links added');
        }
    } catch (error) {
        addLinksError = error;
        console.error('addLinks failed:', error.message);
    }
    
    const allLinks = [...links, ...newLinks];
    const newFailures = await checkAllLinks(allLinks);
    
    if (newFailures.size > 0) {
        console.log('Failed links: \n', Array.from(newFailures, ([key, value]) => `${key} -> ${value}`).join('\n'));
    } else {
        console.log('All links are OK');
    }
    
    if (addLinksError) {
        throw addLinksError;
    }
}

await run();