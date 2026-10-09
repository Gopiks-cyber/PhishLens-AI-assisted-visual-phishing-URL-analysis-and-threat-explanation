document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('analyzeForm');
    const urlInput = document.getElementById('urlInput');
    const resultsDiv = document.getElementById('results');
    const loadingOverlay = document.getElementById('loadingOverlay');
    const analyzeBtn = form.querySelector('.analyze-btn');
    const btnText = analyzeBtn.querySelector('.btn-text');

    const verdictEl = document.getElementById('resultVerdict');
    const confidenceEl = document.getElementById('resultConfidence');
    const explanationEl = document.getElementById('resultExplanation');
    const breakdownEl = document.getElementById('scoreBreakdown');
    const anatomySectionEl = document.getElementById('urlAnatomySection');
    const anatomyPillsEl = document.getElementById('anatomyPills');
    const suspiciousComponentsEl = document.getElementById('suspiciousComponents');
    const httpsNoteEl = document.getElementById('httpsNote');
    const indicatorsEl = document.getElementById('resultIndicators');
    const threatMapSectionEl = document.getElementById('threatMapSection');
    const threatMapPanelEl = document.getElementById('threatMapPanel');
    const threatMapPlaceholderEl = threatMapPanelEl ? threatMapPanelEl.querySelector('.threat-map-placeholder') : null;
    const threatMapContentEl = threatMapPanelEl ? threatMapPanelEl.querySelector('.threat-map-content') : null;

    let currentParsed = null;
    let currentIndicators = [];
    let currentBreakdown = null;
    let selectedComponentKey = null;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const url = urlInput.value.trim();
        if (!url) return;

        analyzeBtn.disabled = true;
        btnText.textContent = 'Analyzing...';
        loadingOverlay.hidden = false;
        resultsDiv.hidden = true;

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

            renderResults(data);
            resultsDiv.hidden = false;
            resultsDiv.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        } catch (err) {
            console.error('[PhishLens] Error caught:', err);
            verdictEl.textContent = 'ERROR';
            confidenceEl.textContent = '';
            explanationEl.innerHTML = `<p>${escapeHtml(err.message || 'An unexpected error occurred.')}</p>`;
            breakdownEl.hidden = true;
            anatomySectionEl.hidden = true;
            threatMapSectionEl.hidden = true;
            httpsNoteEl.hidden = true;
            indicatorsEl.innerHTML = '';
            resultsDiv.hidden = false;
        } finally {
            loadingOverlay.hidden = true;
            analyzeBtn.disabled = false;
            btnText.textContent = 'Analyze';
        }
    });

    function renderResults(data) {
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

        const breakdown = data.score_breakdown || null;

        // Parse URL for anatomy
        currentParsed = parseUrl(data.url || '');
        currentIndicators = indicators;
        currentBreakdown = breakdown;
        selectedComponentKey = null;

        // Build interactive anatomy pills
        anatomyPillsEl.innerHTML = '';
        if (currentParsed) {
            buildAnatomyPills(currentParsed);
            anatomySectionEl.hidden = false;
        } else {
            anatomySectionEl.hidden = true;
        }

        // Build suspicious components (from client-side analysis)
        const suspicious = currentParsed ? analyzeUrlComponents(currentParsed) : [];
        suspiciousComponentsEl.innerHTML = buildSuspiciousComponents(suspicious);

        // HTTPS note
        const isHttps = currentParsed && currentParsed.protocol === 'https';
        const httpsNoteHtml = buildHttpsNote(isHttps);
        httpsNoteEl.innerHTML = httpsNoteHtml;
        httpsNoteEl.hidden = !httpsNoteHtml;

        // Update verdict and confidence
        verdictEl.textContent = formatRiskLevel(level);
        verdictEl.className = 'result-verdict ' + levelClass;
        confidenceEl.textContent = 'Risk score: ' + Math.min(100, Math.max(0, score)) + '/100';

        // Update explanation
        explanationEl.innerHTML = `
            <strong>Analyzed URL:</strong>
            <p class="analyzed-url">${escapeHtml(data.url || '')}</p>
        `;

        // Update score breakdown
        if (breakdown) {
            breakdownEl.innerHTML = formatScoreBreakdown(breakdown);
            breakdownEl.hidden = false;
        } else {
            breakdownEl.hidden = true;
        }

        // Update indicators
        if (indicators.length) {
            indicatorsEl.innerHTML = `
                <h4>Risk Indicators</h4>
                <ul>
                    ${indicators.map(item => {
                        const name = escapeHtml(item.name || 'Indicator');
                        const detail = escapeHtml(item.detail || '');
                        const severity = escapeHtml(item.severity || 'unknown');
                        const points = Number(item.points) || 0;
                        const explanation = escapeHtml(item.explanation || '');
                        const evidence = escapeHtml(item.evidence || '');

                        return `
                            <li>
                                <strong>${name}</strong>
                                <span class="indicator-severity">${severity}</span>
                                <span class="indicator-points">+${points} pts</span>
                                <p>${detail}</p>
                                ${evidence ? '<p class="indicator-evidence">Evidence: ' + evidence + '</p>' : ''}
                                ${explanation ? '<p class="indicator-explanation">' + explanation + '</p>' : ''}
                            </li>
                        `;
                    }).join('')}
                </ul>
            `;
        } else {
            indicatorsEl.innerHTML = '<p>No risk indicators were identified by the current checks.</p>';
        }

        // Add recommendations
        if (recommendations.length) {
            const recHtml = `
                <section class="result-recommendations">
                    <h4>Recommendations</h4>
                    <ul>
                        ${recommendations.map(item =>
                            '<li>' + escapeHtml(item) + '</li>'
                        ).join('')}
                    </ul>
                </section>
            `;
            indicatorsEl.insertAdjacentHTML('beforeend', recHtml);
        }

        // Disclaimer
        indicatorsEl.insertAdjacentHTML('beforeend', `
            <p class="result-disclaimer">
                This is a heuristic assessment, not proof that a URL is safe
                or malicious. HTTPS alone does not guarantee safety.
            </p>
        `);

        // Show threat map section
        threatMapSectionEl.hidden = false;
        showThreatMapPlaceholder();
    }

    function buildAnatomyPills(parsed) {
        const componentColors = {
            protocol: '#22d3ee',
            subdomain: '#a78bfa',
            domain: '#4ade80',
            tld: '#fbbf24',
            path: '#f97316',
            query: '#f472b6',
            hash: '#60a5fa'
        };

        const componentOrder = ['protocol', 'subdomain', 'domain', 'tld', 'path', 'query', 'hash'];
        const separators = {
            protocol: '://',
            subdomain: '.',
            tld: '.',
            path: '/',
            query: '?',
            hash: '#'
        };

        componentOrder.forEach((key, index) => {
            const value = parsed[key];
            if (!value && key !== 'protocol' && key !== 'domain') return;

            const pill = document.createElement('button');
            pill.type = 'button';
            pill.className = 'anatomy-pill' + (key === 'domain' ? ' anatomy-pill--domain' : '');
            pill.dataset.component = key;
            pill.style.setProperty('--pill-color', componentColors[key]);
            pill.setAttribute('role', 'tab');
            pill.setAttribute('aria-selected', 'false');
            pill.setAttribute('tabindex', '0');
            pill.title = getComponentTitle(key);

            // Add separator before (except protocol)
            if (key !== 'protocol' && separators[key]) {
                const sep = document.createElement('span');
                sep.className = 'pill-separator';
                sep.textContent = separators[key];
                pill.appendChild(sep);
            }

            const label = document.createElement('span');
            label.className = 'pill-label';
            label.textContent = key;
            pill.appendChild(label);

            const val = document.createElement('span');
            val.className = 'pill-value';
            val.textContent = key === 'query' ? value.substring(1) : (key === 'hash' ? value.substring(1) : value);
            pill.appendChild(val);

            // Click handler
            pill.addEventListener('click', () => selectComponent(key));

            // Keyboard handler
            pill.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    selectComponent(key);
                } else if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
                    e.preventDefault();
                    navigatePills(e.key === 'ArrowRight' ? 1 : -1);
                }
            });

            anatomyPillsEl.appendChild(pill);
        });

        // Set initial ARIA state
        const firstPill = anatomyPillsEl.querySelector('.anatomy-pill');
        if (firstPill) {
            firstPill.setAttribute('tabindex', '0');
        }
    }

    function getComponentTitle(key) {
        const titles = {
            protocol: 'Protocol',
            subdomain: 'Subdomain',
            domain: 'Domain (registrable domain)',
            tld: 'Top-Level Domain',
            path: 'Path',
            query: 'Query Parameters',
            hash: 'Fragment'
        };
        return titles[key] || key;
    }

    function selectComponent(key) {
        const value = currentParsed[key];
        if (!value && key !== 'protocol' && key !== 'domain') return;

        selectedComponentKey = key;

        // Update pill selection states
        anatomyPillsEl.querySelectorAll('.anatomy-pill').forEach(pill => {
            const isSelected = pill.dataset.component === key;
            pill.setAttribute('aria-selected', isSelected);
            pill.classList.toggle('selected', isSelected);
        });

        // Update threat map
        renderThreatMap(key, value);
    }

    function navigatePills(direction) {
        const pills = Array.from(anatomyPillsEl.querySelectorAll('.anatomy-pill'));
        const currentIndex = pills.findIndex(p => p.dataset.component === selectedComponentKey);
        let nextIndex = currentIndex + direction;
        if (nextIndex < 0) nextIndex = pills.length - 1;
        if (nextIndex >= pills.length) nextIndex = 0;
        pills[nextIndex].focus();
        selectComponent(pills[nextIndex].dataset.component);
    }

    function renderThreatMap(componentKey, componentValue) {
        threatMapPlaceholderEl.hidden = true;
        threatMapContentEl.hidden = false;

        // Find matching indicators from API response
        const matchedIndicators = currentIndicators.filter(ind => {
            const detail = (ind.detail || '').toLowerCase();
            const name = (ind.name || '').toLowerCase();
            const comp = componentKey.toLowerCase();
            return detail.includes(comp) || name.includes(comp);
        });

        // Find matching suspicious components from client-side analysis
        const suspicious = currentParsed ? analyzeUrlComponents(currentParsed) : [];
        const matchedSuspicious = suspicious.filter(s =>
            s.component.toLowerCase() === componentKey.toLowerCase() ||
            (componentKey === 'domain' && s.component === 'Domain') ||
            (componentKey === 'subdomain' && s.component === 'Subdomain') ||
            (componentKey === 'tld' && s.component === 'TLD') ||
            (componentKey === 'path' && s.component === 'Path') ||
            (componentKey === 'query' && s.component === 'Query Parameters') ||
            (componentKey === 'protocol' && s.component === 'Protocol')
        );

        // Find score contribution from breakdown
        let scoreContribution = null;
        if (currentBreakdown && currentBreakdown.contributions) {
            scoreContribution = currentBreakdown.contributions.find(c => {
                const name = (c.name || '').toLowerCase();
                const comp = componentKey.toLowerCase();
                return name.includes(comp) || comp.includes(name);
            });
        }

        const componentLabels = {
            protocol: 'Protocol',
            subdomain: 'Subdomain',
            domain: 'Domain',
            tld: 'Top-Level Domain',
            path: 'Path',
            query: 'Query Parameters',
            hash: 'Fragment'
        };

        const severityColors = {
            high: '#f87171',
            medium: '#fbbf24',
            low: '#4ade80',
            unknown: '#94a3b8'
        };

        let html = '';

        // Component header
        html += '<div class="threat-map-header">';
        html += '<div class="threat-map-component-type">' + escapeHtml(componentLabels[componentKey] || componentKey) + '</div>';
        html += '<div class="threat-map-component-value">' + escapeHtml(componentValue) + '</div>';
        html += '</div>';

        // Severity from matched indicators/suspicious
        const maxSeverity = getMaxSeverity([
            ...matchedIndicators.map(i => i.severity),
            ...matchedSuspicious.map(s => s.risk.toLowerCase())
        ]);
        if (maxSeverity !== 'unknown') {
            const color = severityColors[maxSeverity] || severityColors.unknown;
            html += '<div class="threat-map-severity" style="--severity-color: ' + color + ';">';
            html += '<span class="severity-label">Severity</span>';
            html += '<span class="severity-value" style="color: ' + color + ';">' + escapeHtml(maxSeverity.charAt(0).toUpperCase() + maxSeverity.slice(1)) + '</span>';
            html += '</div>';
        }

        // Matched API indicators
        if (matchedIndicators.length > 0) {
            html += '<div class="threat-map-section">';
            html += '<h4>Matched Risk Indicators</h4>';
            matchedIndicators.forEach(ind => {
                const sevColor = severityColors[ind.severity] || severityColors.unknown;
                html += '<div class="threat-map-indicator" style="--indicator-color: ' + sevColor + ';">';
                html += '<div class="indicator-header">';
                html += '<strong>' + escapeHtml(ind.name) + '</strong>';
                html += '<span class="indicator-points" style="color: ' + sevColor + ';">+' + (ind.points || 0) + ' pts</span>';
                html += '</div>';
                if (ind.detail) {
                    html += '<p class="indicator-detail">' + escapeHtml(ind.detail) + '</p>';
                }
                if (ind.evidence) {
                    html += '<p class="indicator-evidence">Evidence: ' + escapeHtml(ind.evidence) + '</p>';
                }
                if (ind.explanation) {
                    html += '<p class="indicator-explanation">' + escapeHtml(ind.explanation) + '</p>';
                }
                html += '</div>';
            });
            html += '</div>';
        }

        // Matched suspicious components
        if (matchedSuspicious.length > 0) {
            html += '<div class="threat-map-section">';
            html += '<h4>Structural Anomalies</h4>';
            matchedSuspicious.forEach(s => {
                const sevColor = severityColors[s.risk.toLowerCase()] || severityColors.unknown;
                html += '<div class="threat-map-indicator" style="--indicator-color: ' + sevColor + ';">';
                html += '<div class="indicator-header">';
                html += '<strong>' + escapeHtml(s.component) + '</strong>';
                html += '<span class="risk-badge risk-' + s.risk.toLowerCase() + '">' + escapeHtml(s.risk) + '</span>';
                html += '</div>';
                html += '<p class="indicator-detail">' + escapeHtml(s.reason) + '</p>';
                html += '</div>';
            });
            html += '</div>';
        }

        // Score contribution
        if (scoreContribution) {
            const sevColor = severityColors[scoreContribution.severity] || severityColors.unknown;
            html += '<div class="threat-map-section">';
            html += '<h4>Score Contribution</h4>';
            html += '<div class="threat-map-indicator" style="--indicator-color: ' + sevColor + ';">';
            html += '<div class="indicator-header">';
            html += '<strong>' + escapeHtml(scoreContribution.name) + '</strong>';
            html += '<span class="indicator-points" style="color: ' + sevColor + ';">+' + (scoreContribution.points || 0) + ' pts</span>';
            html += '</div>';
            if (scoreContribution.explanation) {
                html += '<p class="indicator-explanation">' + escapeHtml(scoreContribution.explanation) + '</p>';
            }
            html += '</div>';
            html += '</div>';
        }

        // No matches
        if (matchedIndicators.length === 0 && matchedSuspicious.length === 0 && !scoreContribution) {
            html += '<div class="threat-map-empty">';
            html += '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">';
            html += '<circle cx="12" cy="12" r="10"/>';
            html += '<path d="M12 16v-4"/>';
            html += '<path d="M12 8h.01"/>';
            html += '</svg>';
            html += '<p>No specific indicator matched this component</p>';
            html += '<p class="threat-map-hint">This component was analyzed but no risk indicators were directly associated with it.</p>';
            html += '</div>';
        }

        threatMapContentEl.innerHTML = html;
    }

    function getMaxSeverity(severities) {
        const order = { high: 3, medium: 2, low: 1, unknown: 0 };
        let max = 'unknown';
        let maxVal = 0;
        severities.forEach(s => {
            const val = order[s.toLowerCase()] || 0;
            if (val > maxVal) {
                maxVal = val;
                max = s.toLowerCase();
            }
        });
        return max;
    }

    function showThreatMapPlaceholder() {
        threatMapPlaceholderEl.hidden = false;
        threatMapContentEl.hidden = true;
        threatMapContentEl.innerHTML = '';
    }

    function formatRiskLevel(level) {
        const levels = {
            'minimal': 'MINIMAL RISK',
            'low': 'LOW RISK',
            'medium': 'MEDIUM RISK',
            'high': 'HIGH RISK',
            'error': 'ANALYSIS ERROR'
        };
        return levels[level] || level.toUpperCase() + ' RISK';
    }

    function buildSuspiciousComponents(suspicious) {
        if (!suspicious || suspicious.length === 0) {
            return `
                <div class="no-suspicious">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="20 6 9 17 4 12"/>
                    </svg>
                    <p>No suspicious components detected in URL structure</p>
                </div>
            `;
        }

        return `
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
    }

    function buildHttpsNote(isHttps) {
        if (isHttps) {
            return `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="2" y="2" width="20" height="20" rx="2"/>
                    <path d="M8 12l2 2 4-4"/>
                </svg>
                <div class="https-note-content">
                    <strong>HTTPS Enabled</strong>
                    <p>This site uses HTTPS encryption. While this protects data in transit, it does not guarantee the site is legitimate. Attackers can obtain valid SSL certificates for phishing domains.</p>
                </div>
            `;
        }
        return `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22v-5"/>
                <path d="M9 12l2 2 4-4"/>
                <rect x="2" y="2" width="20" height="20" rx="2"/>
                <path d="M12 17v5"/>
            </svg>
            <div class="https-note-content">
                <strong>Not Using HTTPS</strong>
                <p>This URL uses HTTP instead of HTTPS. Data sent to this site is not encrypted and can be intercepted. Never enter sensitive information on HTTP sites.</p>
            </div>
        `;
    }

    function formatScoreBreakdown(breakdown) {
        const rawTotal = Number(breakdown.raw_total) || 0;
        const cap = Number(breakdown.cap) || 100;
        const finalScore = Number(breakdown.final_score) || 0;
        const capped = breakdown.capped === true;
        const contributions = Array.isArray(breakdown.contributions)
            ? breakdown.contributions
            : [];

        const maxPoints = Math.max(cap, 1);
        const contributionBars = contributions.map(item => {
            const name = escapeHtml(item.name || 'Indicator');
            const severity = escapeHtml(item.severity || 'unknown');
            const points = Number(item.points) || 0;
            const explanation = escapeHtml(item.explanation || '');
            const widthPercent = Math.min(100, (points / maxPoints) * 100);

            return `
                <li class="contribution-item">
                    <div class="contribution-header">
                        <span class="contribution-name">${name}</span>
                        <span class="contribution-severity severity-${escapeHtml(severity)}">${severity}</span>
                        <span class="contribution-points">+${points}</span>
                    </div>
                    <div class="contribution-bar" role="img" aria-label="${name} contributes ${points} points">
                        <div class="contribution-fill severity-fill-${escapeHtml(severity)}" style="width: ${widthPercent}%;"></div>
                    </div>
                    ${explanation ? '<p class="contribution-explanation">' + explanation + '</p>' : ''}
                </li>
            `;
        }).join('');

        return `
            <section class="score-breakdown" aria-labelledby="score-breakdown-title">
                <h4 id="score-breakdown-title">Score Breakdown</h4>
                <div class="score-summary">
                    <div class="score-summary-row">
                        <span class="score-summary-label">Raw total</span>
                        <span class="score-summary-value">${rawTotal}</span>
                    </div>
                    <div class="score-summary-row">
                        <span class="score-summary-label">Score cap</span>
                        <span class="score-summary-value">${cap}</span>
                    </div>
                    <div class="score-summary-row">
                        <span class="score-summary-label">Final score</span>
                        <span class="score-summary-value">${finalScore}</span>
                    </div>
                    ${capped ? '<p class="score-capped-note">Raw total exceeded the cap of ' + cap + '; final score is capped at ' + cap + '.</p>' : ''}
                </div>
                <ul class="contribution-list">
                    ${contributionBars || '<li class="contribution-empty">No indicators contributed to the score.</li>'}
                </ul>
            </section>
        `;
    }

    function escapeHtml(value) {
        return String(value).replace(/[&<>"']/g, character => ({
            '&': '&',
            '<': '<',
            '>': '>',
            '"': '"',
            "'": "'"
        })[character]);
    }
});
