const fetch = require('node-fetch');
const fs = require('fs');

async function checkLink(url) {
  try {
    const response = await fetch(url);
    
    if (!response.ok) {
      throw new Error(`HTTP status ${response.status}`);
    }
    return { url, status: response.status, success: true };
  } catch (error) {
    return { url, error: error.message, success: false };
  }
}

async function checkAllLinks(dataPath) {
  const linksData = JSON.parse(fs.readFileSync(dataPath));
  const results = await Promise.all(linksData.links.map(checkLink));
  const failures = results.filter(r => !r.success);
  
  return {
    success: failures.length === 0,
    results,
    failures
  };
}

module.exports = { checkAllLinks };
