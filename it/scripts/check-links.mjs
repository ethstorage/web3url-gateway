import { readFileSync } from 'fs';
import fetch from 'node-fetch';

async function checkLink(url) {
  try {
    const response = await fetch(url);
    console.log(url, ":", response.statusText);
    if (!response.ok) {
      throw new Error(`HTTP status ${response.status}`);
    }
    return { url, status: response.status, success: true };
  } catch (error) {
    return { url, error: error.message, success: false };
  }
}
export async function checkAllLinks(dataPath) {
  const linksData = JSON.parse(readFileSync(dataPath));
  const results = await Promise.all(linksData.links.map(checkLink));
  const failures = results.filter(r => !r.success);

  return {
    success: failures.length === 0,
    results,
    failures
  };
}


