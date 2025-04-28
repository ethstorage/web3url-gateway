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
      const errorMessage = await response.text();
      throw new Error(`HTTP status ${response.status}: ${errorMessage}`);
    }
    return { url, status: response.status, success: true };
  } catch (error) {
    return { url, error: error.message, success: false };
  }
}

export async function checkAllLinks(links) {
  const all = await Promise.all(links.map(checkLink));
  const failures = all.filter(r => !r.success);
  console.log('totally checked links:', all.length, 'failed:', failures.length);
  return {
    all,
    failures
  };
}