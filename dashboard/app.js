/**
 * MultiLog-OS: Web Dashboard Logic & Chart.js Visualizations
 */

let globalData = null;
let threatChartInstance = null;
let httpChartInstance = null;
let scalingChartInstance = null;
let ioChartInstance = null;

// Baseline default dataset from the 50,000 log run
const fallbackData = {
    "summary": {
        "total_lines": 50000,
        "total_bytes": 6897127,
        "total_errors": 4527,
        "total_warnings": 8409,
        "total_info": 37064
    },
    "threats": {
        "sql_injection": 1277,
        "cross_site_scripting": 942,
        "directory_traversal": 1038,
        "recon_probe": 1172,
        "auth_failure": 1439,
        "privilege_escalation": 322
    },
    "http_status": {
        "2xx": 25173,
        "3xx": 9960,
        "4xx": 5941,
        "5xx": 3040
    },
    "os_telemetry": {
        "elapsed_wall_sec": 0.2799,
        "throughput_mb_s": 23.16,
        "lines_per_sec": 95267,
        "cpu_utilization_pct": 97.5,
        "resident_set_size_bytes": 12394496,
        "page_fault_count": 3116
    },
    "alerts_sample": [
        {"line": 13, "threat": "CROSS_SITE_SCRIPTING", "ip": "194.26.29.112", "rule": "onload="},
        {"line": 31, "threat": "RECON_PROBE", "ip": "89.248.163.74", "rule": "/phpmyadmin"},
        {"line": 36, "threat": "CROSS_SITE_SCRIPTING", "ip": "89.248.163.74", "rule": "<script"},
        {"line": 46, "threat": "CROSS_SITE_SCRIPTING", "ip": "103.251.167.20", "rule": "<script"},
        {"line": 57, "threat": "RECON_PROBE", "ip": "103.251.167.20", "rule": "/phpmyadmin"},
        {"line": 62, "threat": "SQL_INJECTION", "ip": "185.220.101.5", "rule": "union select"},
        {"line": 78, "threat": "DIRECTORY_TRAVERSAL", "ip": "194.26.29.112", "rule": "/etc/passwd"},
        {"line": 89, "threat": "AUTHENTICATION_FAILURE", "ip": "103.251.167.20", "rule": "failed password"},
        {"line": 104, "threat": "PRIVILEGE_ESCALATION", "ip": "185.220.101.5", "rule": "command=/bin/sh"},
        {"line": 120, "threat": "SQL_INJECTION", "ip": "89.248.163.74", "rule": "' or '1'='1"}
    ]
};

async function loadTelemetryData() {
    try {
        const response = await fetch('../data/report.json');
        if (!response.ok) throw new Error('Network response not ok');
        const data = await response.json();
        renderDashboard(data);
    } catch (e) {
        console.warn('Using local fallback data (Direct file:// access detected)');
        renderDashboard(fallbackData);
    }
}

function handleFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const data = JSON.parse(e.target.result);
            renderDashboard(data);
        } catch (err) {
            alert('Invalid JSON file format!');
        }
    };
    reader.readAsText(file);
}

function renderDashboard(data) {
    globalData = data;
    const s = data.summary;
    const t = data.threats;
    const os = data.os_telemetry;

    // Update KPI Cards
    document.getElementById('valTotalLines').innerText = s.total_lines.toLocaleString();
    document.getElementById('valTotalBytes').innerText = ((s.total_bytes || 6897127) / (1024 * 1024)).toFixed(2) + ' MB';
    document.getElementById('valThroughput').innerHTML = (os.throughput_mb_s || 23.16).toFixed(2) + ' <span class="unit">MB/s</span>';
    document.getElementById('valLinesSec').innerText = (os.lines_per_sec || 95267).toLocaleString();
    
    const totalThreats = Object.values(t).reduce((a, b) => a + b, 0);
    document.getElementById('valThreatCount').innerText = totalThreats.toLocaleString();
    document.getElementById('valErrorCount').innerText = s.total_errors.toLocaleString();
    document.getElementById('valWallTime').innerHTML = os.elapsed_wall_sec.toFixed(3) + ' <span class="unit">s</span>';
    document.getElementById('valEfficiency').innerText = (os.cpu_utilization_pct || 97.5).toFixed(1) + '%';
    document.getElementById('valMemoryRSS').innerHTML = ((os.resident_set_size_bytes || 12394496) / (1024 * 1024)).toFixed(2) + ' <span class="unit">MB</span>';
    document.getElementById('valPageFaults').innerText = (os.page_fault_count || 3116).toLocaleString();

    // Render Charts
    renderThreatChart(t);
    renderHttpChart(data.http_status);
    renderScalingChart();
    renderIoChart();

    // Render Table
    renderIncidentTable(data.alerts_sample || []);
}

function renderThreatChart(threats) {
    const ctx = document.getElementById('threatChart').getContext('2d');
    if (threatChartInstance) threatChartInstance.destroy();

    threatChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['SQL Injection', 'XSS', 'Directory Traversal', 'Recon Probes', 'Auth / Brute Force', 'Privilege Escalation'],
            datasets: [{
                data: [
                    threats.sql_injection,
                    threats.cross_site_scripting,
                    threats.directory_traversal,
                    threats.recon_probe,
                    threats.auth_failure,
                    threats.privilege_escalation
                ],
                backgroundColor: ['#ef4444', '#f97316', '#eab308', '#38bdf8', '#a855f7', '#ec4899'],
                borderColor: '#151c2e',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#94a3b8', font: { size: 11 } }
                }
            }
        }
    });
}

function renderHttpChart(http) {
    const ctx = document.getElementById('httpChart').getContext('2d');
    if (httpChartInstance) httpChartInstance.destroy();

    httpChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['2xx Success', '3xx Redirect', '4xx Client Err', '5xx Server Err'],
            datasets: [{
                data: [http['2xx'], http['3xx'], http['4xx'], http['5xx']],
                backgroundColor: ['#10b981', '#38bdf8', '#f59e0b', '#ef4444'],
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#94a3b8' }, grid: { color: '#243048' } },
                y: { ticks: { color: '#94a3b8' }, grid: { color: '#243048' } }
            }
        }
    });
}

function renderScalingChart() {
    const ctx = document.getElementById('scalingChart').getContext('2d');
    if (scalingChartInstance) scalingChartInstance.destroy();

    scalingChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['1 Thread', '2 Threads', '4 Threads', '8 Threads', '16 Threads'],
            datasets: [
                {
                    label: 'Measured Speedup (x)',
                    data: [1.00, 2.06, 4.24, 5.52, 7.93],
                    borderColor: '#38bdf8',
                    backgroundColor: 'rgba(56, 189, 248, 0.1)',
                    fill: true,
                    tension: 0.3,
                    borderWidth: 3
                },
                {
                    label: 'Linear Ideal Speedup',
                    data: [1, 2, 4, 8, 16],
                    borderColor: '#64748b',
                    borderDash: [5, 5],
                    fill: false,
                    borderWidth: 1.5
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { labels: { color: '#94a3b8' } }
            },
            scales: {
                x: { ticks: { color: '#94a3b8' }, grid: { color: '#243048' } },
                y: { ticks: { color: '#94a3b8' }, grid: { color: '#243048' } }
            }
        }
    });
}

function renderIoChart() {
    const ctx = document.getElementById('ioChart').getContext('2d');
    if (ioChartInstance) ioChartInstance.destroy();

    ioChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Memory-Mapped (mmap)', 'Direct Syscall (read)', 'Buffered Stream (fread)'],
            datasets: [
                {
                    label: 'Throughput (MB/s)',
                    data: [23.16, 11.41, 11.95],
                    backgroundColor: '#38bdf8',
                    borderRadius: 6
                },
                {
                    label: 'Kernel CPU Time (s)',
                    data: [0.1094, 0.2031, 0.2500],
                    backgroundColor: '#ef4444',
                    borderRadius: 6
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: '#94a3b8' } } },
            scales: {
                x: { ticks: { color: '#94a3b8' }, grid: { color: '#243048' } },
                y: { ticks: { color: '#94a3b8' }, grid: { color: '#243048' } }
            }
        }
    });
}

function renderIncidentTable(alerts) {
    const tbody = document.getElementById('incidentTbody');
    tbody.innerHTML = '';
    alerts.forEach(a => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>#${a.line}</td>
            <td><span class="tag-threat">${a.threat}</span></td>
            <td><code>${a.ip}</code></td>
            <td><code>${a.rule}</code></td>
        `;
        tbody.appendChild(tr);
    });
}

function filterIncidents() {
    const q = document.getElementById('incidentSearch').value.toLowerCase();
    if (!globalData || !globalData.alerts_sample) return;
    const filtered = globalData.alerts_sample.filter(a => 
        a.ip.toLowerCase().includes(q) ||
        a.threat.toLowerCase().includes(q) ||
        a.rule.toLowerCase().includes(q)
    );
    renderIncidentTable(filtered);
}

// Initial auto-load on page load
window.addEventListener('DOMContentLoaded', loadTelemetryData);
