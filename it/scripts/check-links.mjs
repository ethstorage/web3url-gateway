import https from 'https';
import fetch from 'node-fetch';

async function checkLink(url) {
  try {
    const response = await fetch(url, {
      agent: new https.Agent({ rejectUnauthorized: false }),
      signal: AbortSignal.timeout(30000), 
    });
    console.log(url, ":", response.statusText);
    if (!response.ok) {
      throw new Error(`HTTP status ${response.status}`);
    }
    return { url, status: response.status, success: true };
  } catch (error) {
    return { url, error: error.message, success: false };
  }
}
export async function checkAllLinks(links) {
  console.time('checkAllLinks'); 
  const results = await Promise.all(links.map(checkLink));
  const failures = results.filter(r => !r.success);
  console.timeEnd('checkAllLinks');
  return {
    success: failures.length === 0,
    results,
    failures
  };
}


