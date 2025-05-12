import https from 'https';
import fetch from 'node-fetch';

async function checkLink(url) {
  try {
    const response = await fetch(url, {
      agent: new https.Agent({ rejectUnauthorized: false }),
      signal: AbortSignal.timeout(100000),
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
  const failures = new Map();

  for (const link of links) {
    const result = await checkLink(link);
    if (!result.success) {
      failures.set(link, result.error);
    }
  }

  let retried = 1;
  while (failures.size > 0 && retried < 4) {
    console.log('retrying failed links:', failures.size, 'times:', retried);
      const retryLinks = Array.from(failures.keys());
      for (const link of retryLinks) {
        const result = await checkLink(link);
        if (!result.success) {
          failures.set(link, result.error);
        } else {
          failures.delete(link);
        }
      }
    retried++;
  }

  console.log('totally checked links:', links.length, 'failed:', failures.size);
  return failures;
}