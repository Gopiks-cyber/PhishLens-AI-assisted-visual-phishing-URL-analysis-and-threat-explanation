let tesseractWorker = null;

// URL Anatomy Analyzer
function parseUrl(urlString) {
    try {
        const url = new URL(urlString);
        const hostname = url.hostname;
        const parts = hostname.split('.');
        
        let subdomain = '';
        let domain = '';
        let tld = '';
        
        if (parts.length >= 3) {
            tld = parts[parts.length - 1];
            domain = parts[parts.length - 2];
            subdomain = parts.slice(0, -2).join('.');
        } else if (parts.length === 2) {
            tld = parts[1];
            domain = parts[0];
        } else {
            domain = parts[0];
        }

        const pathSegments = url.pathname.split('/').filter(Boolean);
        const queryParams = {};
        for (const [key, value] of url.searchParams) {
            queryParams[key] = value;
        }

        return {
            protocol: url.protocol.replace(':', ''),
            subdomain,
            domain,
            tld,
            path: url.pathname,
            pathSegments,
            query: url.search,
            queryParams,
            hash: url.hash,
            fullHostname: hostname,
            isIpAddress: /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)
        };
    } catch (e) {
        return null;
    }
}

function analyzeUrlComponents(parsed) {
    if (!parsed) return [];
    
    const suspicious = [];
    
    // Check protocol
    if (parsed.protocol !== 'https') {
        suspicious.push({
            component: 'Protocol',
            value: parsed.protocol,
            reason: 'Non-HTTPS protocol exposes data to interception',
            risk: 'High'
        });
    }
    
    // Check for IP address as hostname
    if (parsed.isIpAddress) {
        suspicious.push({
            component: 'Hostname',
            value: parsed.fullHostname,
            reason: 'IP address used instead of domain name — common in phishing',
            risk: 'High'
        });
    }
    
    // Check subdomain
    if (parsed.subdomain) {
        const subParts = parsed.subdomain.split('.');
        const suspiciousKeywords = ['secure', 'login', 'signin', 'verify', 'account', 'update', 'security', 'bank', 'paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook', 'instagram', 'whatsapp', 'telegram', 'support', 'help', 'service', 'admin', 'portal', 'app', 'api', 'cdn', 'static', 'img', 'images', 'media', 'files', 'download', 'upload'];
        const hasSuspiciousKeyword = subParts.some(part => 
            suspiciousKeywords.some(kw => part.toLowerCase().includes(kw))
        );
        
        if (hasSuspiciousKeyword) {
            suspicious.push({
                component: 'Subdomain',
                value: parsed.subdomain,
                reason: 'Subdomain contains brand/security-related keywords to appear legitimate',
                risk: 'High'
            });
        } else if (subParts.length > 3) {
            suspicious.push({
                component: 'Subdomain',
                value: parsed.subdomain,
                reason: 'Excessive subdomain depth — often used to hide the true domain',
                risk: 'Medium'
            });
        } else if (subParts.some(p => p.length > 20)) {
            suspicious.push({
                component: 'Subdomain',
                value: parsed.subdomain,
                reason: 'Unusually long subdomain labels — possible obfuscation',
                risk: 'Medium'
            });
        }
    }
    
    // Check domain
    const suspiciousTlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'work', 'date', 'loan', 'win', 'bid', 'racing', 'stream', 'download', 'click', 'link', 'online', 'site', 'website', 'space', 'tech', 'info', 'biz', 'cc', 'pw', 'ws', 'me', 'tv', 'io'];
    if (suspiciousTlds.includes(parsed.tld.toLowerCase())) {
        suspicious.push({
            component: 'TLD',
            value: parsed.tld,
            reason: `'${parsed.tld}' is a high-risk TLD frequently abused for phishing`,
            risk: 'Medium'
        });
    }
    
    // Check for homograph-like domains (mixed scripts, unusual chars)
    if (/[^\x00-\x7F]/.test(parsed.domain)) {
        suspicious.push({
            component: 'Domain',
            value: parsed.domain,
            reason: 'Non-ASCII characters in domain — possible homograph attack',
            risk: 'High'
        });
    }
    
    // Check domain length
    if (parsed.domain.length > 20) {
        suspicious.push({
            component: 'Domain',
            value: parsed.domain,
            reason: 'Unusually long domain name — possible typosquatting or obfuscation',
            risk: 'Medium'
        });
    }
    
    // Check for brand names in domain (simplified check)
    const brands = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook', 'instagram', 'whatsapp', 'netflix', 'spotify', 'github', 'gitlab', 'bitbucket', 'dropbox', 'onedrive', 'icloud', 'outlook', 'gmail', 'yahoo', 'protonmail', 'bank', 'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'capitalone', 'amex', 'discover'];
    const brandInDomain = brands.find(b => parsed.domain.toLowerCase().includes(b));
    if (brandInDomain && !parsed.domain.toLowerCase().startsWith(brandInDomain + '.')) {
        suspicious.push({
            component: 'Domain',
            value: parsed.domain,
            reason: `Contains brand name '${brandInDomain}' but not on official domain — likely typosquatting`,
            risk: 'High'
        });
    }
    
    // Check path
    if (parsed.pathSegments.length > 0) {
        const pathSuspicious = ['login', 'signin', 'verify', 'account', 'update', 'secure', 'security', 'password', 'credential', 'auth', 'oauth', 'confirm', 'validate', 'recover', 'reset', 'unlock', 'billing', 'payment', 'invoice', 'wallet', 'crypto', 'bitcoin', 'ethereum', 'wallet'];
        const hasSuspiciousPath = parsed.pathSegments.some(seg => 
            pathSuspicious.some(kw => seg.toLowerCase().includes(kw))
        );
        
        if (hasSuspiciousPath) {
            suspicious.push({
                component: 'Path',
                value: parsed.path,
                reason: 'Path contains credential-harvesting related keywords',
                risk: 'High'
            });
        }
        
        if (parsed.pathSegments.length > 5) {
            suspicious.push({
                component: 'Path',
                value: parsed.path,
                reason: 'Excessively deep path structure — possible obfuscation',
                risk: 'Low'
            });
        }
    }
    
    // Check query parameters
    if (Object.keys(parsed.queryParams).length > 0) {
        const sensitiveParams = ['password', 'passwd', 'pwd', 'token', 'secret', 'key', 'auth', 'session', 'sid', 'csrf', 'xsrf', 'redirect', 'return', 'next', 'url', 'target', 'goto', 'continue'];
        const hasSensitiveParam = Object.keys(parsed.queryParams).some(param => 
            sensitiveParams.some(sp => param.toLowerCase().includes(sp))
        );
        
        if (hasSensitiveParam) {
            suspicious.push({
                component: 'Query Parameters',
                value: parsed.query,
                reason: 'Query contains sensitive parameter names — possible credential theft',
                risk: 'High'
            });
        }
        
        if (Object.keys(parsed.queryParams).length > 10) {
            suspicious.push({
                component: 'Query Parameters',
                value: parsed.query,
                reason: 'Excessive number of query parameters — possible tracking/obfuscation',
                risk: 'Low'
            });
        }
    }
    
    return suspicious;
}

function renderUrlAnatomy(urlString) {
    const parsed = parseUrl(urlString);
    if (!parsed) return;
    
    const displayEl = document.getElementById('urlAnatomyDisplay');
    const suspiciousEl = document.getElementById('urlSuspiciousComponents');
    const httpsNoteEl = document.getElementById('httpsNote');
    
    // Color mapping for components
    const componentColors = {
        protocol: '#22d3ee',
        subdomain: '#a78bfa',
        domain: '#4ade80',
        tld: '#fbbf24',
        path: '#f97316',
        query: '#f472b6',
        hash: '#60a5fa'
    };
    
    // Build the anatomy display
    let anatomyHtml = '<div class="anatomy-pills">';
    
    // Protocol
    anatomyHtml += `<span class="anatomy-pill" style="--pill-color: ${componentColors.protocol};" title="Protocol">
        <span class="pill-label">protocol</span>
        <span class="pill-value">${escapeHtml(parsed.protocol)}</span>
        <span class="pill-separator">://</span>
    </span>`;
    
    // Subdomain
    if (parsed.subdomain) {
        anatomyHtml += `<span class="anatomy-pill" style="--pill-color: ${componentColors.subdomain};" title="Subdomain">
            <span class="pill-label">subdomain</span>
            <span class="pill-value">${escapeHtml(parsed.subdomain)}</span>
            <span class="pill-separator">.</span>
        </span>`;
    }
    
    // Domain
    anatomyHtml += `<span class="anatomy-pill anatomy-pill--domain" style="--pill-color: ${componentColors.domain};" title="Domain (registrable domain)">
        <span class="pill-label">domain</span>
        <span class="pill-value">${escapeHtml(parsed.domain)}</span>
    </span>`;
    
    // TLD
    if (parsed.tld) {
        anatomyHtml += `<span class="anatomy-pill" style="--pill-color: ${componentColors.tld};" title="Top-Level Domain">
            <span class="pill-separator">.</span>
            <span class="pill-label">tld</span>
            <span class="pill-value">${escapeHtml(parsed.tld)}</span>
        </span>`;
    }
    
    // Path
    if (parsed.path && parsed.path !== '/') {
        anatomyHtml += `<span class="anatomy-pill" style="--pill-color: ${componentColors.path};" title="Path">
            <span class="pill-separator">/</span>
            <span class="pill-label">path</span>
            <span class="pill-value">${escapeHtml(parsed.path)}</span>
        </span>`;
    }
    
    // Query
    if (parsed.query) {
        anatomyHtml += `<span class="anatomy-pill" style="--pill-color: ${componentColors.query};" title="Query Parameters">
            <span class="pill-separator">?</span>
            <span class="pill-label">query</span>
            <span class="pill-value">${escapeHtml(parsed.query.substring(1))}</span>
        </span>`;
    }
    
    // Hash
    if (parsed.hash) {
        anatomyHtml += `<span class="anatomy-pill" style="--pill-color: ${componentColors.hash};" title="Fragment">
            <span class="pill-separator">#</span>
            <span class="pill-label">hash</span>
            <span class="pill-value">${escapeHtml(parsed.hash.substring(1))}</span>
        </span>`;
    }
    
    anatomyHtml += '</div>';
    displayEl.innerHTML = anatomyHtml;
    
    // Analyze suspicious components
    const suspicious = analyzeUrlComponents(parsed);
    
    if (suspicious.length > 0) {
        suspiciousEl.innerHTML = `
            <h3>Suspicious Components</h3>
            <div class="suspicious-grid">
                ${suspicious.map(s => `
                    <article class="suspicious-card risk-${s.risk.toLowerCase()}">
                        <div class="suspicious-header">
                            <span class="suspicious-component">${escapeHtml(s.component)}</span>
                            <span class="risk-badge risk-${s.risk.toLowerCase()}">${s.risk}</span>
                        </div>
                        <div class="suspicious-value">${escapeHtml(s.value)}</div>
                        <p class="suspicious-reason">${escapeHtml(s.reason)}</p>
                    </article>
                `).join('')}
            </div>
        `;
    } else {
        suspiciousEl.innerHTML = `
            <div class="no-suspicious">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="20 6 9 17 4 12"/>
                </svg>
                <p>No suspicious components detected in URL structure</p>
            </div>
        `;
    }
    
    // Show HTTPS note if not HTTPS
    if (parsed.protocol !== 'https') {
        httpsNoteEl.hidden = false;
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function initTesseract() {
    if (tesseractWorker) return tesseractWorker;

    if (typeof Tesseract === 'undefined') {
        await loadTesseractScript();
    }

    tesseractWorker = await Tesseract.createWorker('eng');
    return tesseractWorker;
}

function loadTesseractScript() {
    return new Promise((resolve, reject) => {
        if (document.querySelector('script[src*="tesseract"]')) {
            resolve();
            return;
        }
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/tesseract.js@5.1.0/dist/tesseract.min.js';
        script.onload = resolve;
        script.onerror = reject;
        document.head.appendChild(script);
    });
}

function extractUrls(text) {
    const urlRegex = /(?:https?:\/\/)?(?:www\.)?[\w-]+(?:\.[\w-]+)+(?:\/[\w\-._~:/?#[\]@!$&'()*+,;=%]*)?/gi;
    const matches = text.match(urlRegex) || [];
    return matches.map(m => m.startsWith('http') ? m : 'https://' + m);
}

function showToast(message, type = 'info') {
    const existing = document.querySelector('.toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    const iconPaths = type === 'success'
        ? '<polyline points="20 6 9 17 4 12"/>'
        : type === 'error'
            ? '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>'
            : '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>';

    const iconSpan = document.createElement('span');
    iconSpan.setAttribute('aria-hidden', 'true');
    iconSpan.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' + iconPaths + '</svg>';
    if (iconSpan.firstChild) {
        toast.appendChild(iconSpan.firstChild);
    }

    const messageSpan = document.createElement('span');
    messageSpan.textContent = message;
    toast.appendChild(messageSpan);

    document.body.appendChild(toast);

    requestAnimationFrame(() => toast.classList.add('show'));

    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

async function processScreenshot(file) {
    if (!file || !file.type.startsWith('image/')) return;

    const urlInput = document.getElementById('urlInput');
    const statusEl = document.getElementById('ocrStatus') || createStatusElement();

    statusEl.textContent = 'Loading OCR engine...';
    statusEl.className = 'ocr-status loading';
    statusEl.hidden = false;

    try {
        const worker = await initTesseract();

        statusEl.textContent = 'Extracting text from image...';

        const { data: { text } } = await worker.recognize(file);

        statusEl.textContent = 'Scanning for URLs...';

        const urls = extractUrls(text);

        if (urls.length > 0) {
            const primaryUrl = urls[0];
            urlInput.value = primaryUrl;
            urlInput.focus();
            urlInput.dispatchEvent(new Event('input', { bubbles: true }));

            if (urls.length > 1) {
                showToast(`URL extracted from screenshot: ${primaryUrl} (+${urls.length - 1} more found)`, 'success');
            } else {
                showToast(`URL extracted from screenshot: ${primaryUrl}`, 'success');
            }
        } else {
            showToast('No URL found in screenshot — the image may not contain a recognizable link', 'info');
        }
    } catch (err) {
        console.error('OCR error:', err);
        const msg = err.message || String(err);
        if (msg.includes('Tesseract') || msg.includes('worker') || msg.includes('load')) {
            showToast('Failed to load OCR engine — check your internet connection', 'error');
        } else if (msg.includes('recognize') || msg.includes('timeout')) {
            showToast('OCR recognition failed — the image may be too blurry or complex', 'error');
        } else {
            showToast('Failed to extract text from image', 'error');
        }
    } finally {
        statusEl.hidden = true;
    }
}

function createStatusElement() {
    const statusEl = document.createElement('div');
    statusEl.id = 'ocrStatus';
    statusEl.className = 'ocr-status';
    statusEl.hidden = true;

    const fileUpload = document.querySelector('.file-upload');
    fileUpload.parentNode.insertBefore(statusEl, fileUpload.nextSibling);

    return statusEl;
}

document.addEventListener('DOMContentLoaded', () => {
    const screenshotInput = document.getElementById('screenshotInput');

    screenshotInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            processScreenshot(file);
        }
    });
});