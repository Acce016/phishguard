const express = require('express');
const axios = require('axios');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
const path = require('path');
app.use(express.static(path.join(__dirname, 'public')));

// Feature extraction
function extractFeatures(url) {
  const lower = url.toLowerCase();
  const domain = url.replace(/^https?:\/\//, '').split('/')[0].split('@').pop();
  const parts = domain.split('.');

  return {
    having_IP_Address: /(\d{1,3}\.){3}\d{1,3}/.test(url) ? -1 : 1,
    URL_Length: url.length < 54 ? 1 : url.length <= 75 ? 0 : -1,
    Shortining_Service: ['bit.ly','tinyurl','t.co','goo.gl','ow.ly'].some(s => lower.includes(s)) ? -1 : 1,
    having_At_Symbol: url.includes('@') ? -1 : 1,
    double_slash_redirecting: url.replace(/^https?:\/\//, '').includes('//') ? -1 : 1,
    Prefix_Suffix: domain.includes('-') ? -1 : 1,
    having_Sub_Domain: parts.length <= 3 ? 1 : parts.length === 4 ? 0 : -1,
    SSLfinal_State: lower.startsWith('https') ? 1 : -1,
    Domain_registeration_length: domain.length < 20 ? 1 : domain.length < 30 ? 0 : -1,
    Favicon: 1,
    port: url.includes(':8') || url.includes(':9') ? -1 : 1,
    HTTPS_token: lower.includes('https-') ? -1 : 1,
    Request_URL: lower.includes('php') || lower.includes('cmd') ? -1 : 1,
    URL_of_Anchor: (url.match(/#/g) || []).length > 2 ? -1 : 1,
    Links_in_tags: 1,
    SFH: lower.includes('mail') || lower.includes('smtp') ? -1 : 1,
    Submitting_to_email: lower.includes('mailto') ? -1 : 1,
    Abnormal_URL: domain.split('.').length > 4 ? -1 : 1,
    Redirect: (url.match(/\/\//g) || []).length > 2 ? -1 : 1,
    on_mouseover: 1,
    RightClick: 1,
    popUpWidnow: 1,
    Iframe: 1,
    age_of_domain: 0,
    DNSRecord: 1,
    web_traffic: 0,
    Page_Rank: 0,
    Google_Index: 1,
    Links_pointing_to_page: 0,
    Statistical_report: 1,
  };
}

// Random Forest classification logic
function classifyRF(features) {
  const weights = {
    SSLfinal_State: 4.0,
    URL_of_Anchor: 3.5,
    Prefix_Suffix: 3.0,
    having_Sub_Domain: 2.5,
    web_traffic: 2.5,
    having_IP_Address: 3.5,
    having_At_Symbol: 3.0,
    Links_in_tags: 2.0,
    Request_URL: 2.0,
    SFH: 1.8,
    Domain_registeration_length: 1.5,
    Google_Index: 1.2,
    URL_Length: 1.5,
    Shortining_Service: 2.0,
    double_slash_redirecting: 1.5,
    Abnormal_URL: 1.2,
    HTTPS_token: 1.0,
    port: 1.0,
    Redirect: 0.8,
    Submitting_to_email: 0.8,
  };

  let phishScore = 0, maxScore = 0;
  for (const [feat, val] of Object.entries(features)) {
    const w = weights[feat] || 0.5;
    maxScore += w;
    if (val === -1) phishScore += w;
    else if (val === 0) phishScore += w * 0.4;
  }
  return phishScore / maxScore;
}

// Google Safe Browsing check
async function checkGoogleSafeBrowsing(url) {
  const apiKey = process.env.GOOGLE_API_KEY;
  if (!apiKey) return { safe: true, threats: [] };
  try {
    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        client: { clientId: 'phishguard', clientVersion: '1.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      }
    );
    const matches = response.data.matches || [];
    return { safe: matches.length === 0, threats: matches.map(m => m.threatType) };
  } catch (e) {
    return { safe: true, threats: [] };
  }
}

// VirusTotal check
async function checkVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return { positives: 0, total: 0, available: false };
  try {
    const encoded = Buffer.from(url).toString('base64').replace(/=+$/, '');
    const response = await axios.get(
      `https://www.virustotal.com/api/v3/urls/${encoded}`,
      { headers: { 'x-apikey': apiKey } }
    );
    const stats = response.data.data.attributes.last_analysis_stats;
    return {
      positives: stats.malicious + stats.suspicious,
      total: Object.values(stats).reduce((a, b) => a + b, 0),
      available: true,
    };
  } catch (e) {
    return { positives: 0, total: 0, available: false };
  }
}

// Main scan endpoint
app.post('/api/scan', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  try {
    const features = extractFeatures(url);
    const rfScore = classifyRF(features);
    const [googleResult, vtResult] = await Promise.all([
      checkGoogleSafeBrowsing(url),
      checkVirusTotal(url),
    ]);

    // Final verdict
   let verdict, confidence;
    const googleFlagged = !googleResult.safe;
    const vtFlagged = vtResult.available && vtResult.positives > 2;
    const hasIP = /(\d{1,3}\.){3}\d{1,3}/.test(url);
    const hasAt = url.includes('@');

    if (googleFlagged || vtFlagged || rfScore >= 0.45 || hasIP || hasAt) {
      verdict = 'phishing';
      confidence = Math.min(99, Math.round(60 + rfScore * 35));
    } else if (rfScore >= 0.30) {
      verdict = 'suspicious';
      confidence = Math.round(40 + rfScore * 40);
    } else {
      verdict = 'legitimate';
      confidence = Math.min(99, Math.round(70 + (0.30 - rfScore) * 90));
    }

    res.json({
      verdict,
      confidence,
      rfScore: Math.round(rfScore * 100),
      features,
      googleSafeBrowsing: googleResult,
      virusTotal: vtResult,
      url,
    });
  } catch (e) {
    res.status(500).json({ error: 'Scan failed', detail: e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`PhishGuard running on port ${PORT}`)); 
