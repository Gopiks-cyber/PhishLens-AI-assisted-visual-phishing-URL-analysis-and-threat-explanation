let tesseractWorker = null;

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
    toast.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            ${type === 'success' ? '<polyline points="20 6 9 17 4 12"/>' : 
              type === 'error' ? '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>' :
              '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>'}
        </svg>
        <span>${message}</span>
    `;
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
            showToast('No URL found in screenshot', 'error');
        }
    } catch (err) {
        console.error('OCR error:', err);
        showToast('Failed to extract text from image', 'error');
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