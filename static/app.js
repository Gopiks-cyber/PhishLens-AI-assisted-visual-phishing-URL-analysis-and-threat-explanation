document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('analyzeForm');
    const urlInput = document.getElementById('urlInput');
    const loadingOverlay = document.getElementById('loadingOverlay');
    const analyzeBtn = form.querySelector('.analyze-btn');
    const btnText = analyzeBtn.querySelector('.btn-text');
    const newScanBtn = document.getElementById('newScanBtn');
    const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
    const sidebar = document.querySelector('.sidebar');

    const navItems = Array.from(document.querySelectorAll('.nav-item'));
    const tabPanels = Array.from(document.querySelectorAll('.tab-panel'));

    const verdictEl = document.getElementById('resultVerdict');
    const confidenceEl = document.getElementById('resultConfidence');
    const explanationEl = document.getElementById('resultExplanation');
    const breakdownEl = document.getElementById('scoreBreakdown');
    const riskRingSectionEl = document.getElementById('riskRingSection');
    const riskRingProgressEl = document.getElementById('riskRingProgress');
    const riskRingScoreEl = document.getElementById('riskRingScore');
    const riskRingLevelEl = document.getElementById('riskRingLevel');
    const anatomySectionEl = document.getElementById('urlAnatomySection');
    const anatomyPillsEl = document.getElementById('anatomyPills');
    const suspiciousComponentsEl = document.getElementById('suspiciousComponents');
    const httpsNoteEl = document.getElementById('httpsNote');
    const indicatorsEl = document.getElementById('resultIndicators');
    const threatMapSectionEl = document.getElementById('threatMapSection');
    const threatMapPanelEl = document.getElementById('threatMapPanel');
    const threatMapPlaceholderEl = threatMapPanelEl ? threatMapPanelEl.querySelector('.threat-map-placeholder') : null;
    const threatMapContentEl = threatMapPanelEl ? threatMapPanelEl.querySelector('.threat-map-content') : null;
    const recommendationsSectionEl = document.getElementById('recommendationsSection');
    const recommendationsListEl = document.getElementById('recommendationsList');
    const scannerEmptyEl = document.getElementById('scannerEmpty');
    const scanStatusEl = document.getElementById('scanStatus');
    const retryBtn = document.getElementById('retryBtn');

    let currentParsed = null;
    let currentIndicators = [];
    let currentRecommendations = [];
    let currentBreakdown = null;
    let selectedComponentKey = null;
    let currentView = 'scanner';

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            if (item.disabled) return;
            switchView(item.dataset.view);
        });
    });

    function switchView(viewName) {
        currentView = viewName;
        navItems.forEach(item => {
            const isActive = item.dataset.view === viewName;
            item.classList.toggle('active', isActive);
            item.setAttribute('aria-selected', isActive);
        });
        tabPanels.forEach(panel => {
            const isActive = panel.id === 'panel-' + viewName;
            panel.classList.toggle('active', isActive);
            panel.hidden = !isActive;
        });
        if (mobileMenuBtn && mobileMenuBtn.getAttribute('aria-expanded') === 'true') {
            mobileMenuBtn.setAttribute('aria-expanded', 'false');
            sidebar.classList.remove('open');
        }
    }

    function enableAnalysisViews() {
        navItems.forEach(item => {
            if (item.dataset.view !== 'scanner') {
                item.disabled = false;
            }
        });
        newScanBtn.hidden = false;
    }

    function disableAnalysisViews() {
        navItems.forEach(item => {
            if (item.dataset.view !== 'scanner') {
                item.disabled = true;
            }
        });
        newScanBtn.hidden = true;
    }

    if (mobileMenuBtn) {
        mobileMenuBtn.addEventListener('click', () => {
            const expanded = mobileMenuBtn.getAttribute('aria-expanded') === 'true';
            mobileMenuBtn.setAttribute('aria-expanded', String(!expanded));
            sidebar.classList.toggle('open');
        });
    }

    const backButtons = [
        document.getElementById('backToScanner'),
        document.getElementById('backToScanner2'),
        document.getElementById('backToScanner3'),
        document.getElementById('backToScanner4')
    ].filter(Boolean);

    backButtons.forEach(btn => {
        btn.addEventListener('click', () => switchView('scanner'));
    });

    if (newScanBtn) {
        newScanBtn.addEventListener('click', () => {
            switchView('scanner');
            urlInput.value = '';
            urlInput.focus();
        });
    }

    if (retryBtn) {
        retryBtn.addEventListener('click', () => {
            switchView('scanner');
            urlInput.focus();
        });
    }

    function createEl(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (typeof text === 'string') node.textContent = text;
        return node;
    }

    const ICON_PATHS = {
        check: '<polyline points="20 6 9 17 4 12"/>',
        info: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>'
    };

    function iconSvg(paths, strokeWidth) {
        const span = document.createElement('span');
        span.setAttribute('aria-hidden', 'true');
        span.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="' + (strokeWidth || 2) + '">' + paths + '</svg>';
        return span.firstChild;
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const url = urlInput.value.trim();
        if (!url) return;

        analyzeBtn.disabled = true;
        btnText.textContent = 'Analyzing...';
        loadingOverlay.hidden = false;
        if (scanStatusEl) scanStatusEl.textContent = 'Analyzing URL...';
        if (retryBtn) retryBtn.hidden = true;

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
            enableAnalysisViews();
            switchView('overview');

            const score = Number(data.risk_score) || 0;
            const level = String(data.risk_level || 'unknown');
            if (scanStatusEl) {
                scanStatusEl.textContent = 'Analysis complete. ' + formatRiskLevel(level) + ', risk score ' + Math.min(100, Math.max(0, score)) + ' out of 100.';
            }
        } catch (err) {
            console.error('[PhishLens] Error caught:', err);
            renderError(err.message || 'An unexpected error occurred.');
            enableAnalysisViews();
            switchView('overview');
        } finally {
            loadingOverlay.hidden = true;
            analyzeBtn.disabled = false;
            btnText.textContent = 'Analyze';
        }
    });

    function renderError(message) {
        if (verdictEl) {
            verdictEl.textContent = 'ANALYSIS ERROR';
            verdictEl.className = 'result-verdict error';
        }
        if (confidenceEl) confidenceEl.textContent = '';
        if (explanationEl) {
            explanationEl.innerHTML = '';
            explanationEl.appendChild(createEl('p', null, message));
        }
        if (breakdownEl) {
            breakdownEl.hidden = true;
            breakdownEl.innerHTML = '';
        }
        if (riskRingSectionEl) riskRingSectionEl.hidden = true;
        if (anatomySectionEl) anatomySectionEl.hidden = true;
        if (threatMapSectionEl) threatMapSectionEl.hidden = true;
        if (httpsNoteEl) httpsNoteEl.hidden = true;
        if (indicatorsEl) indicatorsEl.innerHTML = '';
        if (recommendationsSectionEl) recommendationsSectionEl.hidden = true;
        if (recommendationsListEl) recommendationsListEl.innerHTML = '';
        if (retryBtn) retryBtn.hidden = false;
        if (scanStatusEl) scanStatusEl.textContent = 'Analysis failed: ' + message;
    }

    function renderResults(data) {
        const score = Number(data.risk_score) || 0;
        const level = String(data.risk_level || 'unknown');
        const levelClass = /^[a-z-]+$/.test(level) ? level : 'unknown';

        const indicators = Array.isArray(data.indicators)
            ? data.indicators
            : [];

        const recommendations = Array.isArray(data.recommendations)
            ? data.recommendations
            : [];

        const breakdown = data.score_breakdown || null;

        currentParsed = parseUrl(data.url || '');
        currentIndicators = indicators;
        currentRecommendations = recommendations;
        currentBreakdown = breakdown;
        selectedComponentKey = null;

        anatomyPillsEl.innerHTML = '';
        if (currentParsed) {
            buildAnatomyPills(currentParsed);
            anatomySectionEl.hidden = false;
        } else {
            anatomySectionEl.hidden = true;
        }

        const suspicious = currentParsed ? analyzeUrlComponents(currentParsed) : [];
        suspiciousComponentsEl.innerHTML = '';
        suspiciousComponentsEl.appendChild(buildSuspiciousComponents(suspicious));

        const isHttps = currentParsed && currentParsed.protocol === 'https';
        httpsNoteEl.innerHTML = '';
        httpsNoteEl.appendChild(buildHttpsNote(isHttps));
        httpsNoteEl.hidden = false;

        if (verdictEl) {
            verdictEl.textContent = formatRiskLevel(level);
            verdictEl.className = 'result-verdict ' + levelClass;
        }
        if (confidenceEl) confidenceEl.textContent = 'Risk score: ' + Math.min(100, Math.max(0, score)) + '/100';

        renderRiskRing(score, level, levelClass);

        explanationEl.innerHTML = '';
        explanationEl.appendChild(createEl('strong', null, 'Analyzed URL:'));
        explanationEl.appendChild(createEl('p', 'analyzed-url', data.url || ''));

        if (breakdownEl) {
            breakdownEl.innerHTML = '';
            if (breakdown) {
                breakdownEl.appendChild(formatScoreBreakdown(breakdown));
                breakdownEl.hidden = false;
            } else {
                breakdownEl.hidden = true;
            }
        }

        indicatorsEl.innerHTML = '';
        if (indicators.length) {
            indicatorsEl.appendChild(createEl('h4', null, 'Risk Indicators'));
            const ul = createEl('ul');
            indicators.forEach(item => {
                const li = createEl('li');
                li.appendChild(createEl('strong', null, item.name || 'Indicator'));
                li.appendChild(createEl('span', 'indicator-severity severity-' + (item.severity || 'unknown'), item.severity || 'unknown'));
                li.appendChild(createEl('span', 'indicator-points', '+' + (Number(item.points) || 0) + ' pts'));
                if (item.detail) li.appendChild(createEl('p', null, item.detail));
                if (item.evidence) {
                    const evP = createEl('p', 'indicator-evidence');
                    evP.textContent = 'Evidence: ' + item.evidence;
                    li.appendChild(evP);
                }
                if (item.explanation) li.appendChild(createEl('p', 'indicator-explanation', item.explanation));
                ul.appendChild(li);
            });
            indicatorsEl.appendChild(ul);
        } else {
            indicatorsEl.appendChild(createEl('p', null, 'No risk indicators were identified by the current checks. This does not guarantee the URL is safe — the analyzer only checks a fixed set of heuristic patterns and never contacts the URL.'));
        }

        if (recommendations.length) {
            recommendationsSectionEl.hidden = false;
            recommendationsListEl.innerHTML = '';
            const ul = createEl('ul', 'recommendations-list');
            recommendations.forEach(item => {
                ul.appendChild(createEl('li', null, item));
            });
            recommendationsListEl.appendChild(ul);
        } else {
            recommendationsSectionEl.hidden = true;
            recommendationsListEl.innerHTML = '';
        }

        threatMapSectionEl.hidden = false;
        showThreatMapPlaceholder();

        if (retryBtn) retryBtn.hidden = true;
        if (scannerEmptyEl) scannerEmptyEl.hidden = true;
    }

    function renderRiskRing(score, level, levelClass) {
        if (!riskRingSectionEl) return;

        const clampedScore = Math.min(100, Math.max(0, score));
        const radius = 52;
        const circumference = 2 * Math.PI * radius;
        const offset = circumference * (1 - clampedScore / 100);

        riskRingSectionEl.hidden = false;

        if (riskRingProgressEl) {
            riskRingProgressEl.style.strokeDasharray = circumference;
            riskRingProgressEl.style.strokeDashoffset = offset;
            riskRingProgressEl.className = 'risk-ring-progress level-' + levelClass;
        }

        if (riskRingScoreEl) {
            riskRingScoreEl.textContent = clampedScore;
        }

        if (riskRingLevelEl) {
            riskRingLevelEl.textContent = formatRiskLevel(level);
            riskRingLevelEl.className = 'risk-ring-level level-' + levelClass;
        }
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

        componentOrder.forEach((key) => {
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

            pill.addEventListener('click', () => selectComponent(key));

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

        anatomyPillsEl.querySelectorAll('.anatomy-pill').forEach(pill => {
            const isSelected = pill.dataset.component === key;
            pill.setAttribute('aria-selected', isSelected);
            pill.classList.toggle('selected', isSelected);
        });

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
        threatMapContentEl.innerHTML = '';

        const matchedIndicators = currentIndicators.filter(ind => {
            const detail = (ind.detail || '').toLowerCase();
            const name = (ind.name || '').toLowerCase();
            const comp = componentKey.toLowerCase();
            return detail.includes(comp) || name.includes(comp);
        });

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
            high: '#FF496C',
            medium: '#fbbf24',
            low: '#4ade80',
            unknown: '#94a3b8'
        };

        const header = createEl('div', 'threat-map-header');
        header.appendChild(createEl('div', 'threat-map-component-type', componentLabels[componentKey] || componentKey));
        header.appendChild(createEl('div', 'threat-map-component-value', componentValue));
        threatMapContentEl.appendChild(header);

        const maxSeverity = getMaxSeverity([
            ...matchedIndicators.map(i => i.severity),
            ...matchedSuspicious.map(s => s.risk.toLowerCase())
        ]);
        if (maxSeverity !== 'unknown') {
            const color = severityColors[maxSeverity] || severityColors.unknown;
            const sevEl = createEl('div', 'threat-map-severity');
            sevEl.style.setProperty('--severity-color', color);
            sevEl.appendChild(createEl('span', 'severity-label', 'Severity'));
            const sevValue = createEl('span', 'severity-value', maxSeverity.charAt(0).toUpperCase() + maxSeverity.slice(1));
            sevValue.style.color = color;
            sevEl.appendChild(sevValue);
            threatMapContentEl.appendChild(sevEl);
        }

        if (matchedIndicators.length > 0) {
            const section = createEl('div', 'threat-map-section');
            section.appendChild(createEl('h4', null, 'Matched Risk Indicators'));
            matchedIndicators.forEach(ind => {
                const sevColor = severityColors[ind.severity] || severityColors.unknown;
                const card = createEl('div', 'threat-map-indicator');
                card.style.setProperty('--indicator-color', sevColor);
                const headerRow = createEl('div', 'indicator-header');
                headerRow.appendChild(createEl('strong', null, ind.name));
                const pointsEl = createEl('span', 'indicator-points', '+' + (ind.points || 0) + ' pts');
                pointsEl.style.color = sevColor;
                headerRow.appendChild(pointsEl);
                card.appendChild(headerRow);
                if (ind.detail) card.appendChild(createEl('p', 'indicator-detail', ind.detail));
                if (ind.evidence) {
                    const evP = createEl('p', 'indicator-evidence');
                    evP.textContent = 'Evidence: ' + ind.evidence;
                    card.appendChild(evP);
                }
                if (ind.explanation) card.appendChild(createEl('p', 'indicator-explanation', ind.explanation));
                section.appendChild(card);
            });
            threatMapContentEl.appendChild(section);
        }

        if (matchedSuspicious.length > 0) {
            const section = createEl('div', 'threat-map-section');
            section.appendChild(createEl('h4', null, 'Structural Anomalies'));
            matchedSuspicious.forEach(s => {
                const sevColor = severityColors[s.risk.toLowerCase()] || severityColors.unknown;
                const card = createEl('div', 'threat-map-indicator');
                card.style.setProperty('--indicator-color', sevColor);
                const headerRow = createEl('div', 'indicator-header');
                headerRow.appendChild(createEl('strong', null, s.component));
                headerRow.appendChild(createEl('span', 'risk-badge risk-' + s.risk.toLowerCase(), s.risk));
                card.appendChild(headerRow);
                card.appendChild(createEl('p', 'indicator-detail', s.reason));
                section.appendChild(card);
            });
            threatMapContentEl.appendChild(section);
        }

        if (scoreContribution) {
            const sevColor = severityColors[scoreContribution.severity] || severityColors.unknown;
            const section = createEl('div', 'threat-map-section');
            section.appendChild(createEl('h4', null, 'Score Contribution'));
            const card = createEl('div', 'threat-map-indicator');
            card.style.setProperty('--indicator-color', sevColor);
            const headerRow = createEl('div', 'indicator-header');
            headerRow.appendChild(createEl('strong', null, scoreContribution.name));
            const pointsEl = createEl('span', 'indicator-points', '+' + (scoreContribution.points || 0) + ' pts');
            pointsEl.style.color = sevColor;
            headerRow.appendChild(pointsEl);
            card.appendChild(headerRow);
            if (scoreContribution.explanation) card.appendChild(createEl('p', 'indicator-explanation', scoreContribution.explanation));
            section.appendChild(card);
            threatMapContentEl.appendChild(section);
        }

        if (matchedIndicators.length === 0 && matchedSuspicious.length === 0 && !scoreContribution) {
            const empty = createEl('div', 'threat-map-empty');
            empty.appendChild(iconSvg(ICON_PATHS.info));
            empty.appendChild(createEl('p', null, 'No specific indicator matched this component'));
            empty.appendChild(createEl('p', 'threat-map-hint', 'This component was analyzed but no risk indicators were directly associated with it.'));
            threatMapContentEl.appendChild(empty);
        }
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
        const wrapper = createEl('div');

        if (!suspicious || suspicious.length === 0) {
            const noSusp = createEl('div', 'no-suspicious');
            noSusp.appendChild(iconSvg(ICON_PATHS.check));
            noSusp.appendChild(createEl('p', null, 'No suspicious components detected in URL structure'));
            wrapper.appendChild(noSusp);
            return wrapper;
        }

        wrapper.appendChild(createEl('h3', null, 'Suspicious Components'));
        const grid = createEl('div', 'suspicious-grid');
        suspicious.forEach(s => {
            const card = createEl('article', 'suspicious-card risk-' + s.risk.toLowerCase());
            const headerRow = createEl('div', 'suspicious-header');
            headerRow.appendChild(createEl('span', 'suspicious-component', s.component));
            headerRow.appendChild(createEl('span', 'risk-badge risk-' + s.risk.toLowerCase(), s.risk));
            card.appendChild(headerRow);
            card.appendChild(createEl('div', 'suspicious-value', s.value));
            card.appendChild(createEl('p', 'suspicious-reason', s.reason));
            grid.appendChild(card);
        });
        wrapper.appendChild(grid);
        return wrapper;
    }

    function buildHttpsNote(isHttps) {
        const wrapper = createEl('div');

        if (isHttps) {
            wrapper.appendChild(iconSvg('<rect x="2" y="2" width="20" height="20" rx="2"/><path d="M8 12l2 2 4-4"/>'));
            const content = createEl('div', 'https-note-content');
            content.appendChild(createEl('strong', null, 'HTTPS Enabled'));
            content.appendChild(createEl('p', null, 'This site uses HTTPS encryption. While this protects data in transit, it does not guarantee the site is legitimate. Attackers can obtain valid SSL certificates for phishing domains.'));
            wrapper.appendChild(content);
        } else {
            wrapper.appendChild(iconSvg('<path d="M12 22v-5"/><path d="M9 12l2 2 4-4"/><rect x="2" y="2" width="20" height="20" rx="2"/><path d="M12 17v5"/>'));
            const content = createEl('div', 'https-note-content');
            content.appendChild(createEl('strong', null, 'Not Using HTTPS'));
            content.appendChild(createEl('p', null, 'This URL uses HTTP instead of HTTPS. Data sent to this site is not encrypted and can be intercepted. Never enter sensitive information on HTTP sites.'));
            wrapper.appendChild(content);
        }
        return wrapper;
    }

    function formatScoreBreakdown(breakdown) {
        const rawTotal = Number(breakdown.raw_total) || 0;
        const cap = Number(breakdown.cap) || 100;
        const finalScore = Number(breakdown.final_score) || 0;
        const capped = breakdown.capped === true;
        const contributions = Array.isArray(breakdown.contributions)
            ? breakdown.contributions
            : [];

        const section = createEl('section', 'score-breakdown');
        section.setAttribute('aria-labelledby', 'score-breakdown-title');
        const title = createEl('h4', null, 'Score Breakdown');
        title.id = 'score-breakdown-title';
        section.appendChild(title);

        const summary = createEl('div', 'score-summary');
        [
            ['Raw total', rawTotal],
            ['Score cap', cap],
            ['Final score', finalScore]
        ].forEach(([label, value]) => {
            const row = createEl('div', 'score-summary-row');
            row.appendChild(createEl('span', 'score-summary-label', label));
            row.appendChild(createEl('span', 'score-summary-value', String(value)));
            summary.appendChild(row);
        });
        if (capped) {
            summary.appendChild(createEl('p', 'score-capped-note', 'Raw total exceeded the cap of ' + cap + '; final score is capped at ' + cap + '.'));
        }
        section.appendChild(summary);

        const list = createEl('ul', 'contribution-list');
        if (contributions.length === 0) {
            list.appendChild(createEl('li', 'contribution-empty', 'No indicators contributed to the score.'));
        } else {
            const maxPoints = Math.max(cap, 1);
            contributions.forEach(item => {
                const name = item.name || 'Indicator';
                const severity = item.severity || 'unknown';
                const points = Number(item.points) || 0;
                const explanation = item.explanation || '';
                const widthPercent = Math.min(100, (points / maxPoints) * 100);

                const li = createEl('li', 'contribution-item');
                const headerRow = createEl('div', 'contribution-header');
                headerRow.appendChild(createEl('span', 'contribution-name', name));
                headerRow.appendChild(createEl('span', 'contribution-severity severity-' + severity, severity));
                headerRow.appendChild(createEl('span', 'contribution-points', '+' + points));
                li.appendChild(headerRow);

                const bar = createEl('div', 'contribution-bar');
                bar.setAttribute('role', 'img');
                bar.setAttribute('aria-label', name + ' contributes ' + points + ' points');
                const fill = createEl('div', 'contribution-fill severity-fill-' + severity);
                fill.style.width = widthPercent + '%';
                bar.appendChild(fill);
                li.appendChild(bar);

                if (explanation) li.appendChild(createEl('p', 'contribution-explanation', explanation));
                list.appendChild(li);
            });
        }
        section.appendChild(list);
        return section;
    }
});
