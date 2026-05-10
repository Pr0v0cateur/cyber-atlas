/* -------------------------------------------------------------------------- */
/*                            Chart Configurations                            */
/* -------------------------------------------------------------------------- */

// Global Chart Defaults
Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = 'rgba(74, 158, 255, 0.05)';
Chart.defaults.font.family = "'Inter', sans-serif";

async function initCharts() {
    initRegionsChart();
    initMalwareChart();
    initTypesChart();
    initTimelineChart();
}

function initRegionsChart() {
    const ctx = document.getElementById('chart-regions').getContext('2d');

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['North America', 'Europe', 'Asia Pacific', 'Latin America', 'Middle East'],
            datasets: [{
                label: 'Targeted Attacks',
                data: [450, 320, 280, 150, 90],
                backgroundColor: '#3b82f6',
                borderRadius: 4,
                barThickness: 20
            }]
        },
        options: {
            indexAxis: 'y', // Horizontal bar
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            }
        }
    });
}

function initMalwareChart() {
    const ctx = document.getElementById('chart-malware').getContext('2d');

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Cobalt Strike', 'Emotet', 'QakBot', 'AgentTesla', 'FormBook'],
            datasets: [{
                data: [35, 20, 15, 12, 18],
                backgroundColor: [
                    '#ef4444',
                    '#f59e0b',
                    '#10b981',
                    '#3b82f6',
                    '#8b5cf6'
                ],
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '70%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: { boxWidth: 12 }
                }
            }
        }
    });
}

function initTypesChart() {
    const ctx = document.getElementById('chart-types').getContext('2d');

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['IPv4', 'Domain', 'URL', 'SHA256', 'MD5'],
            datasets: [{
                label: 'Count',
                data: [12000, 8500, 15000, 5000, 3000],
                backgroundColor: 'rgba(6, 182, 212, 0.7)',
                borderColor: '#06b6d4',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: true }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

function initTimelineChart() {
    const ctx = document.getElementById('chart-timeline').getContext('2d');

    // Generate dummy dates
    const days = Array.from({ length: 30 }, (_, i) => `Day ${i + 1}`);
    const data1 = Array.from({ length: 30 }, () => Math.floor(Math.random() * 50) + 10);
    const data2 = Array.from({ length: 30 }, () => Math.floor(Math.random() * 30) + 5);

    new Chart(ctx, {
        type: 'line',
        data: {
            labels: days,
            datasets: [
                {
                    label: 'New Signals',
                    data: data1,
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0
                },
                {
                    label: 'Critical Alerts',
                    data: data2,
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false,
            },
            plugins: {
                legend: { position: 'top' }
            },
            scales: {
                x: { grid: { display: false } }
            }
        }
    });
}
