const rescanButton = document.getElementById('rescan-button');
const deepScanButton = document.getElementById('deep-scan-button');
const resultsContainer = document.getElementById('results-container');
const deepScanResultsContainer = document.getElementById('deep-scan-results');

function displayResults(results) {
    if (!results) {
        resultsContainer.innerHTML = '<h2>Site Audit:</h2><p>No scan has been run. Click "Rescan" to start.</p>';
        return;
    }
    resultsContainer.innerHTML = '<h2>Site Audit:</h2>';
    if (results.length === 0) {
        resultsContainer.innerHTML += '<div class="result-item status-info"><div class="vuln-title">✅ No major issues found.</div></div>';
    } else {
        results.forEach(result => {
            const resultDiv = document.createElement('div');
            resultDiv.className = `result-item status-${result.severity.toLowerCase()}`;
            resultDiv.innerHTML = `<div class="vuln-title">${result.title} (${result.severity})</div><div class="vuln-details">${result.details}</div>`;
            resultsContainer.appendChild(resultDiv);
        });
    }
}

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const activeTab = tabs[0];
    if (!activeTab || !activeTab.id) return;
    chrome.storage.local.get([`${activeTab.id}`], (data) => {
        displayResults(data[activeTab.id]);
    });
});

rescanButton.addEventListener('click', () => {
    resultsContainer.innerHTML = '<h2>Site Audit:</h2><p>Rescanning site...</p>';
    rescanButton.disabled = true;
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        chrome.runtime.sendMessage({ action: 'rescanSite', tab: tabs[0] }, (response) => {
            displayResults(response.results);
            rescanButton.disabled = false;
        });
    });
});

deepScanButton.addEventListener('click', () => {
    deepScanResultsContainer.innerHTML = '<h2>Deep Scan Results:</h2><p>Scanning page inputs with ML models...</p>';
    deepScanButton.disabled = true;
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        chrome.runtime.sendMessage({ action: 'deepScan', tab: tabs[0] }, (response) => {
            deepScanResultsContainer.innerHTML = '<h2>Deep Scan Results:</h2>';
            if (response.error) {
                deepScanResultsContainer.innerHTML += `<p style="color:red;">Error: ${response.error}</p>`;
            } else if (response.vulnerableInputs && response.vulnerableInputs.length > 0) {
                response.vulnerableInputs.forEach(item => {
                    const resultDiv = document.createElement('div');
                    resultDiv.className = 'result-item status-vulnerable';
                    resultDiv.innerHTML = `<div class="vuln-title">Potential Injection Vulnerability Found!</div><div class="vuln-details">An input field (name: "<strong>${item.name}</strong>") on this page appears to be vulnerable.</div>`;
                    deepScanResultsContainer.appendChild(resultDiv);
                });
            } else {
                deepScanResultsContainer.innerHTML += '<div class="result-item status-info"><div class="vuln-title">✅ No vulnerable inputs found.</div></div>';
            }
            deepScanButton.disabled = false;
        });
    });
});