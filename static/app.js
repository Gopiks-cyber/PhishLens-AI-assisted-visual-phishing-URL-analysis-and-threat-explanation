document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('analyzeForm');
    const urlInput = document.getElementById('urlInput');
    const screenshotInput = document.getElementById('screenshotInput');
    const resultsDiv = document.getElementById('results');
    const analyzeBtn = form.querySelector('.analyze-btn');
    const btnText = analyzeBtn.querySelector('.btn-text');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const url = urlInput.value.trim();
        if (!url) return;

        const file = screenshotInput.files[0];

        analyzeBtn.disabled = true;
        btnText.textContent = 'Analyzing...';
        resultsDiv.hidden = true;
        resultsDiv.innerHTML = '';

        try {
            const formData = new FormData();
            formData.append('url', url);
            if (file) formData.append('screenshot', file);

            const response = await fetch('/analyze', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Analysis failed');
            }

            resultsDiv.hidden = false;
            resultsDiv.innerHTML = formatResults(data);
        } catch (err) {
            resultsDiv.hidden = false;
            resultsDiv.innerHTML = `
                <div class="result-error">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="15" y1="9" x2="9" y2="15"/>
                        <line x1="9" y1="9" x2="15" y2="15"/>
                    </svg>
                    <p>${err.message}</p>
                </div>
            `;
        } finally {
            analyzeBtn.disabled = false;
            btnText.textContent = 'Analyze';
        }
    });

    function formatResults(data) {
        const verdictClass = data.verdict === 'phishing' ? 'result-phishing' : 
                            data.verdict === 'suspicious' ? 'result-suspicious' : 'result-safe';
        const verdictLabel = data.verdict.charAt(0).toUpperCase() + data.verdict.slice(1);

        return `
            <div class="result-header ${verdictClass}">
                <div class="result-verdict">${verdictLabel}</div>
                <div class="result-confidence">${Math.round(data.confidence * 100)}% confidence</div>
            </div>
            ${data.explanation ? `<div class="result-explanation">${data.explanation}</div>` : ''}
            ${data.indicators?.length ? `
                <div class="result-indicators">
                    <h4>Risk Indicators</h4>
                    <ul>
                        ${data.indicators.map(i => `<li>${i}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
        `;
    }

    screenshotInput.addEventListener('change', () => {
        const label = document.querySelector('.file-upload-label span');
        if (screenshotInput.files[0]) {
            label.textContent = screenshotInput.files[0].name;
        } else {
            label.textContent = 'Upload screenshot (optional)';
        }
    });
});