document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('analyzeForm');
    const urlInput = document.getElementById('urlInput');
    const resultsDiv = document.getElementById('results');
    const loadingOverlay = document.getElementById('loadingOverlay');
    const analyzeBtn = form.querySelector('.analyze-btn');
    const btnText = analyzeBtn.querySelector('.btn-text');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const url = urlInput.value.trim();
        if (!url) return;

        analyzeBtn.disabled = true;
        btnText.textContent = 'Analyzing...';
        loadingOverlay.hidden = false;
        resultsDiv.hidden = true;
        resultsDiv.replaceChildren();

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Analysis failed');
            }

            resultsDiv.innerHTML = formatResults(data);
            resultsDiv.hidden = false;
            resultsDiv.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        } catch (err) {
            console.error('[PhishLens] Error caught:', err);
            resultsDiv.innerHTML = `
                <div class="result-error">
                    <p>${escapeHtml(err.message || 'An unexpected error occurred.')}</p>
                </div>
            `;
            resultsDiv.hidden = false;
        } finally {
            loadingOverlay.hidden = true;
            analyzeBtn.disabled = false;
            btnText.textContent = 'Analyze';
        }
    });

    function formatResults(data) {
        const score = Number(data.risk_score) || 0;
        const level = String(data.risk_level || 'unknown');
        const safeLevel = escapeHtml(level);
        const levelClass = /^[a-z-]+$/.test(level) ? level : 'unknown';

        const indicators = Array.isArray(data.indicators)
            ? data.indicators
            : [];

        const recommendations = Array.isArray(data.recommendations)
            ? data.recommendations
            : [];

        const indicatorHtml = indicators.length
            ? `
                <section class="result-indicators">
                    <h4>Risk Indicators</h4>
                    <ul>
                        ${indicators.map(item => {
                            const name = escapeHtml(item.name || 'Indicator');
                            const detail = escapeHtml(item.detail || '');
                            const severity = escapeHtml(item.severity || 'unknown');

                            return `
                                <li>
                                    <strong>${name}</strong>
                                    <span class="indicator-severity">${severity}</span>
                                    <p>${detail}</p>
                                </li>
                            `;
                        }).join('')}
                    </ul>
                </section>
            `
            : '<p>No risk indicators were identified by the current checks.</p>';

        const recommendationHtml = recommendations.length
            ? `
                <section class="result-recommendations">
                    <h4>Recommendations</h4>
                    <ul>
                        ${recommendations.map(item =>
                            `<li>${escapeHtml(item)}</li>`
                        ).join('')}
                    </ul>
                </section>
            `
            : '';

        return `
            <section class="result-card">
                <div class="result-header result-${levelClass}">
                    <div class="result-verdict">${safeLevel.toUpperCase()} RISK</div>
                    <div class="result-confidence">Risk score: ${Math.min(100, Math.max(0, score))}/100</div>
                </div>

                <div class="result-explanation">
                    <strong>Analyzed URL:</strong>
                    <p class="analyzed-url">${escapeHtml(data.url || '')}</p>
                </div>

                ${indicatorHtml}
                ${recommendationHtml}

                <p class="result-disclaimer">
                    This is a heuristic assessment, not proof that a URL is safe
                    or malicious. HTTPS alone does not guarantee safety.
                </p>
            </section>
        `;
    }

    function escapeHtml(value) {
        return String(value).replace(/[&<>"']/g, character => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        })[character]);
    }
});
