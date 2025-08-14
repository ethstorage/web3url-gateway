import https from 'https';
import fetch from 'node-fetch';

async function checkLink(url) {
  const startTime = Date.now();
  try {
    const response = await fetch(url, {
      agent: new https.Agent({ rejectUnauthorized: false }),
      signal: AbortSignal.timeout(100000),
    });
    const endTime = Date.now();
    const duration = endTime - startTime;
    console.log(url, ":", response.statusText, `(${duration}ms)`);
    if (!response.ok) {
      const errorMessage = await response.text();
      throw new Error(`HTTP status ${response.status}: ${errorMessage}`);
    }
    return { url, status: response.status, success: true, duration };
  } catch (error) {
    const endTime = Date.now();
    const duration = endTime - startTime;
    return { url, error: error.message, success: false, duration };
  }
}

export async function checkAllLinks(links) {
  const totalStartTime = Date.now();
  const failures = new Map();
  let slowestLink = null;
  let maxDuration = 0;

  for (const link of links) {
    const result = await checkLink(link);
    if (result.duration > maxDuration) {
      maxDuration = result.duration;
      slowestLink = link;
    }
    if (!result.success) {
      failures.set(link, result.error);
    }
  }

  let retried = 1;
  while (failures.size > 0 && retried < 4) {
    console.log('retrying failed links:', failures.size, 'times:', retried);
    const retryLinks = Array.from(failures.keys());
    for (const link of retryLinks) {
      console.log('retrying link:', link);
      await new Promise(resolve => setTimeout(resolve, retried * 10000));
      const result = await checkLink(link);
      if (result.duration > maxDuration) {
        maxDuration = result.duration;
        slowestLink = link;
      }
      if (!result.success) {
        failures.set(link, result.error);
      } else {
        failures.delete(link);
      }
    }
    retried++;
  }

  console.log();
  if (slowestLink) {
    console.log(`Slowest link: ${slowestLink} took ${maxDuration}ms`);
  }
  const totalDuration = (Date.now() - totalStartTime) / 1000;
  console.log(`Total time used: ${totalDuration}s, totally checked links: ${links.length}, failed: ${failures.size}`);
  return failures;
}