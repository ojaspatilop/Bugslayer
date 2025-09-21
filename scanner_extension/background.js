let VULN_DB = {};

// Create a promise that resolves once the DB is loaded. This prevents race conditions.
const dbLoadPromise = new Promise((resolve) => {
    fetch(chrome.runtime.getURL('vuln_db.json')).then(r => r.json()).then(data => {
        VULN_DB = data;
        resolve();
    }).catch(e => console.error("Error loading DB:", e));
});

// Listen for tab updates to trigger automatic site audits
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        runSiteAudit(tabId, tab.url);
    }
});

// Listen for messages from the popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'rescanSite') {
        runSiteAudit(request.tab.id, request.tab.url).then(results => sendResponse({ results }));
        return true;
    }
    // *** THIS IS THE CORRECTED SECTION ***
    if (request.action === 'deepScan') {
        // We now correctly get the tab ID from the request object
        runDeepScan(request.tab.id).then(response => sendResponse(response));
        return true;
    }
});

// Clean up stored results when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
    chrome.storage.local.remove([`${tabId}`]);
});


// --- MAIN SCANNING FUNCTIONS ---

// 1. Main function for the automatic site audit
async function runSiteAudit(tabId, url) {
    await dbLoadPromise;
    const origin = new URL(url).origin;
    const results = await Promise.all([
        checkHeaders(url),
        checkKnownFiles(origin),
        scanHtmlContent(tabId),
        scanForVulnerableLibraries(tabId)
    ]);
    const allFindings = results.flat();
    await chrome.storage.local.set({ [tabId]: allFindings });
    return allFindings;
}

// 2. Main function for the optional "Deep Scan" using ML models
async function runDeepScan(tabId) {
    try {
        const injectionResult = await chrome.scripting.executeScript({
            target: { tabId: tabId },
            func: async () => {
                const inputs = document.querySelectorAll('input[type="text"], input[type="search"], textarea');
                if (inputs.length === 0) return { noInputs: true };
                
                const vulnerableInputs = [];
                const testPayload = "' OR 1=1--";

                for (const input of inputs) {
                    try {
                        const response = await fetch('http://127.0.0.1:5000/scan', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ payload: testPayload }),
                        });
                        if (response.ok) {
                            const result = await response.json();
                            if (result.final_verdict === 'Malicious') {
                                vulnerableInputs.push({ name: input.name || input.id || 'Unnamed Input' });
                            }
                        }
                    } catch (e) {
                        return { error: "Could not connect to the backend server. Is it running?" };
                    }
                }
                return { vulnerableInputs: vulnerableInputs };
            }
        });

        const result = injectionResult[0]?.result;
        if (result && result.error) return { error: result.error };
        if (result && result.noInputs) return { vulnerableInputs: [] };
        
        return { vulnerableInputs: (result?.vulnerableInputs || []) };
    } catch (e) {
        return { error: "Could not inject script into the page. It may be protected." };
    }
}


// --- HELPER SCANNING FUNCTIONS (Unchanged) ---

async function scanForVulnerableLibraries(tabId) {
    if (!VULN_DB.js_libraries) return [];
    try {
        const injectionResult = await chrome.scripting.executeScript({
            target: { tabId: tabId },
            func: () => {
                const detected = {};
                if (typeof window.jQuery === 'function') detected.jquery = window.jQuery.fn.jquery;
                if (typeof window.bootstrap === 'object' && window.bootstrap.Tooltip) detected.bootstrap = window.bootstrap.Tooltip.VERSION;
                else if (typeof window.jQuery === 'function' && typeof window.jQuery.fn.tooltip === 'function') detected.bootstrap = window.jQuery.fn.tooltip.Constructor.VERSION;
                if (typeof window.angular === 'object' && typeof window.angular.version === 'object') detected["angular.js"] = window.angular.version.full;
                return detected;
            }
        });
        const findings = [];
        const detectedLibraries = (injectionResult && injectionResult[0] && injectionResult[0].result) || {};
        for (const libName in detectedLibraries) {
            const version = detectedLibraries[libName];
            findings.push({ title: 'JavaScript Library Detected', severity: 'Info', details: `Found <strong>${libName}</strong> version <strong>${version}</strong>.` });
            if (VULN_DB.js_libraries[libName]) {
                for (const vuln of VULN_DB.js_libraries[libName]) {
                    if (isVersionLessThanOrEqualTo(version, vuln.up_to_version)) {
                         findings.push({ title: `Outdated Library: ${libName}`, severity: vuln.severity, details: `Version ${version} is vulnerable. ${vuln.details}` });
                    }
                }
            }
        }
        return findings;
    } catch(e) { 
        console.warn("Could not execute library scan script.", e);
        return [];
    }
}

function isVersionLessThanOrEqualTo(versionA, versionB) {
    const partsA = versionA.split('.').map(v => parseInt(v, 10));
    const partsB = versionB.split('.').map(v => parseInt(v, 10));
    const len = Math.max(partsA.length, partsB.length);
    for (let i = 0; i < len; i++) {
        const a = partsA[i] || 0;
        const b = partsB[i] || 0;
        if (a > b) return false;
        if (a < b) return true;
    }
    return true;
}

async function checkHeaders(url) {
    const findings = [];
    try {
        const response = await fetch(url, { method: 'HEAD', cache: 'no-store' });
        const headers = response.headers;
        if (!headers.has('content-security-policy')) findings.push({ title: 'Missing Content-Security-Policy', severity: 'Medium', details: 'CSP is a powerful defense against XSS attacks.' });
        if (!headers.has('x-frame-options')) findings.push({ title: 'Missing X-Frame-Options', severity: 'Medium', details: 'Helps prevent clickjacking attacks.' });
        if (!headers.has('strict-transport-security')) findings.push({ title: 'Missing Strict-Transport-Security', severity: 'Medium', details: 'HSTS enforces secure (HTTPS) connections.' });
        const server = headers.get('server') || 'Unknown';
        findings.push({ title: 'Server Technology', severity: 'Info', details: `Server identified as: <strong>${server}</strong>` });
        if (server !== 'Unknown' && VULN_DB.servers) {
            for (const entry of VULN_DB.servers) {
                if (server.toLowerCase().includes(entry.name.toLowerCase())) {
                    for (const vuln of entry.vulnerabilities) {
                        findings.push({ title: `Known Vulnerability in ${entry.name}`, severity: vuln.severity, details: vuln.details });
                    }
                }
            }
        }
    } catch (e) {}
    return findings;
}

async function checkKnownFiles(origin) {
    const findings = [];
    const files = ['/robots.txt', '/.env', '/sitemap.xml'];
    for (const file of files) {
        try {
            const response = await fetch(origin + file, { method: 'HEAD', cache: 'no-store' });
            if (response.ok) {
                findings.push({ title: 'Potentially Sensitive File Exposed', severity: 'Low', details: `The file <strong>${file}</strong> is publicly accessible.` });
            }
        } catch (e) {}
    }
    return findings;
}

async function scanHtmlContent(tabId) {
    try {
        const injectionResult = await chrome.scripting.executeScript({
            target: { tabId: tabId },
            func: () => {
                const findings = [];
                document.querySelectorAll('form').forEach(form => {
                    if (form.querySelector('input[type="password"]')) {
                        const action = form.getAttribute('action') || '';
                        if (action.startsWith('http://')) {
                            findings.push({ title: 'Insecure Password Form', severity: 'High', details: 'A form on this page submits passwords over unencrypted HTTP.' });
                        }
                    }
                });
                return findings;
            }
        });
        return (injectionResult && injectionResult[0] && injectionResult[0].result) || [];
    } catch (e) {
        return [];
    }
}