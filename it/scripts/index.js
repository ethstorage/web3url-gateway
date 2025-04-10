import { checkAllLinks } from './check-links.mjs';

async function run() {
    const results = await checkAllLinks('../data/links.json');
    if (results.success) {
        console.log('All links are OK');
    } else {
        console.log('results', JSON.stringify(results.results, null, 2));
    }}
    
run();