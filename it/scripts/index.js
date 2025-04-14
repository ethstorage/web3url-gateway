import { links } from '../data/links.mjs';
import { checkAllLinks } from './check-links.mjs';

async function run() {
    const results = await checkAllLinks(links);
    if (results.success) {
        console.log('All links are OK');
    } else {
        console.log('results', JSON.stringify(results.failures, null, 2));
    }}
    
run();