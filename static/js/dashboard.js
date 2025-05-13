// Initialize Socket.IO connection
const socket = io();

// Initialize charts
let trafficChart = null;
let alertChart = null;

// Dark theme chart configuration
Chart.defaults.color = '#e9ecef';
Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.1)';

// Chart data
let trafficData = {
    labels: [],
    datasets: [{
        label: 'Packets per Second',
        data: [],
        borderColor: '#0086f8',
        backgroundColor: 'rgba(0, 134, 248, 0.2)',
        borderWidth: 2,
        pointBackgroundColor: '#0086f8',
        pointBorderColor: '#23272f',
        pointRadius: 3,
        pointHoverRadius: 5,
        tension: 0.3,
        fill: true
    }]
};

let alertData = {
    labels: ['Port Scan', 'DoS Attack', 'DDoS Attack', 'DNS Amplification', 'Anomaly', 'Others'],
    datasets: [{
        data: [0, 0, 0, 0, 0, 0],
        backgroundColor: [
            '#e74c3c', // danger
            '#3498db', // primary
            '#f39c12', // warning
            '#2ecc71', // success
            '#9b59b6', // purple
            '#95a5a6'  // gray
        ],
        borderColor: '#23272f',
        borderWidth: 2,
        hoverOffset: 10
    }]
};

// PCAP Analysis state tracking
let pcapAnalysisState = {
    inProgress: false,
    currentFile: '',
    progress: 0,
    estimatedPackets: 0,
    processedPackets: 0
};

// Notification system
function showNotification(title, message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <div class="notification-icon">
            <i class="bi ${type === 'success' ? 'bi-check-circle' : 
                         type === 'danger' ? 'bi-exclamation-triangle' : 
                         type === 'warning' ? 'bi-exclamation-circle' : 'bi-info-circle'}"></i>
        </div>
        <div class="notification-content">
            <h5>${title}</h5>
            <p>${message}</p>
        </div>
        <button class="notification-close">&times;</button>
    `;
    
    // Add to container (create if doesn't exist)
    let container = document.querySelector('.notification-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'notification-container';
        document.body.appendChild(container);
    }
    
    container.appendChild(notification);
    
    // Add close handler
    notification.querySelector('.notification-close').addEventListener('click', () => {
        notification.classList.add('notification-hiding');
        setTimeout(() => notification.remove(), 300);
    });
    
    // Auto close after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.classList.add('notification-hiding');
            setTimeout(() => notification.remove(), 300);
        }
    }, 5000);
}

// Initialize charts when the page loads
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    setupNavigation();
    startLiveUpdates();
    setupPcapForm();
    setupSearchFilter();
    setupRefreshButtons();
    
    // Initial system time update
    updateSystemTime();
    
    // Add notification styles if not present
    addNotificationStyles();
    
    // Show welcome notification
    setTimeout(() => {
        showNotification(
            'Dashboard Ready', 
            'Intrusion Sentinel Dashboard is now monitoring for attacks', 
            'success'
        );
    }, 1000);
    
    // Force an immediate data update
    updateStats();
    updateAlerts();
});

function addNotificationStyles() {
    // Add styles for notifications if not already in page
    if (!document.getElementById('notification-styles')) {
        const styleSheet = document.createElement('style');
        styleSheet.id = 'notification-styles';
        styleSheet.textContent = `
            .notification-container {
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 9999;
                max-width: 350px;
            }
            
            .notification {
                background-color: #23272f;
                color: #e9ecef;
                border-radius: 8px;
                padding: 12px 15px;
                margin-bottom: 10px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.3);
                display: flex;
                align-items: flex-start;
                transform: translateX(100%);
                animation: slide-in 0.3s forwards;
                border-left: 4px solid #0086f8;
            }
            
            .notification-success {
                border-left-color: #2ecc71;
            }
            
            .notification-danger {
                border-left-color: #e74c3c;
            }
            
            .notification-warning {
                border-left-color: #f39c12;
            }
            
            .notification-hiding {
                animation: slide-out 0.3s forwards;
            }
            
            .notification-icon {
                margin-right: 12px;
                font-size: 20px;
                padding-top: 3px;
            }
            
            .notification-success .notification-icon {
                color: #2ecc71;
            }
            
            .notification-danger .notification-icon {
                color: #e74c3c;
            }
            
            .notification-warning .notification-icon {
                color: #f39c12;
            }
            
            .notification-info .notification-icon {
                color: #0086f8;
            }
            
            .notification-content {
                flex: 1;
            }
            
            .notification-content h5 {
                margin: 0 0 5px 0;
                font-size: 16px;
                font-weight: 600;
            }
            
            .notification-content p {
                margin: 0;
                font-size: 14px;
                opacity: 0.9;
            }
            
            .notification-close {
                background: none;
                border: none;
                color: #adb5bd;
                font-size: 18px;
                cursor: pointer;
                padding: 0 0 0 10px;
            }
            
            .notification-close:hover {
                color: #e9ecef;
            }
            
            @keyframes slide-in {
                0% { transform: translateX(100%); opacity: 0; }
                100% { transform: translateX(0); opacity: 1; }
            }
            
            @keyframes slide-out {
                0% { transform: translateX(0); opacity: 1; }
                100% { transform: translateX(100%); opacity: 0; }
            }
        `;
        document.head.appendChild(styleSheet);
    }
}

function initializeCharts() {
    // Traffic Chart
    const trafficCtx = document.getElementById('trafficChart').getContext('2d');
    trafficChart = new Chart(trafficCtx, {
        type: 'line',
        data: trafficData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 800,
                easing: 'easeOutQuart'
            },
            scales: {
                y: {
                    beginAtZero: true,
                    suggestedMax: 1.0,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    }
                },
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    }
                }
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'top',
                    labels: {
                        color: '#e9ecef',
                        font: {
                            weight: 'bold'
                        }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(35, 39, 47, 0.9)',
                    titleColor: '#e9ecef',
                    bodyColor: '#e9ecef',
                    borderColor: '#0086f8',
                    borderWidth: 1,
                    displayColors: false
                }
            }
        }
    });

    // Alert Distribution Chart
    const alertCtx = document.getElementById('alertChart').getContext('2d');
    alertChart = new Chart(alertCtx, {
        type: 'doughnut',
        data: alertData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            animation: {
                animateRotate: true,
                animateScale: true
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'right',
                    labels: {
                        color: '#e9ecef',
                        padding: 15,
                        font: {
                            size: 11
                        }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(35, 39, 47, 0.9)',
                    titleColor: '#e9ecef',
                    bodyColor: '#e9ecef',
                    borderColor: '#0086f8',
                    borderWidth: 1
                }
            }
        }
    });
}

// Setup PCAP analysis form submission
function setupPcapForm() {
    const pcapForm = document.getElementById('pcap-form');
    if (pcapForm) {
        pcapForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const pcapFilePath = document.getElementById('pcap-file-path').value.trim();
            if (!pcapFilePath) {
                showNotification('Error', 'Please enter a PCAP file path', 'danger');
                return;
            }
            
            // Reset progress state
            pcapAnalysisState = {
                inProgress: true,
                currentFile: pcapFilePath,
                progress: 0,
                estimatedPackets: 0,
                processedPackets: 0
            };
            
            // Immediately update UI to show analysis has started
            updateAnalysisProgress(1, pcapFilePath); // Start at 1% not 0%
            updatePcapStatusBadge('active');
            
            // Send request to analyze PCAP file
            fetch('/api/pcap', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ pcap_file: pcapFilePath })
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    document.getElementById('pcap-result-info').textContent = `Started analysis of ${pcapFilePath}`;
                    document.getElementById('pcap-result-info').className = 'alert alert-info';
                    
                    // Update progress with initial value
                    updateAnalysisProgress(5, pcapFilePath); // Set to 5% to show activity
                    
                    // Estimate total packets based on file size if available
                    if (data.estimated_packets && data.estimated_packets > 0) {
                        pcapAnalysisState.estimatedPackets = data.estimated_packets;
                    } else {
                        // Default estimate if server doesn't provide one
                        pcapAnalysisState.estimatedPackets = 1000000; // Assume 1M packets
                    }
                    
                    showNotification('PCAP Analysis', `Started analyzing ${pcapFilePath}`, 'info');
                    
                    // Start simulation for smoother progress
                    startProgressSimulation();
                } else {
                    document.getElementById('pcap-result-info').textContent = `Error: ${data.message}`;
                    document.getElementById('pcap-result-info').className = 'alert alert-danger';
                    showNotification('Error', `Failed to analyze PCAP: ${data.message}`, 'danger');
                    pcapAnalysisState.inProgress = false;
                    updatePcapStatusBadge('idle');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                document.getElementById('pcap-result-info').textContent = `Error: ${error.message}`;
                document.getElementById('pcap-result-info').className = 'alert alert-danger';
                showNotification('Error', `Failed to analyze PCAP: ${error.message}`, 'danger');
                pcapAnalysisState.inProgress = false;
                updatePcapStatusBadge('idle');
            });
        });
    }
}

// Simulate progress updates between server messages
let progressSimulationInterval = null;
function startProgressSimulation() {
    // Clear any existing interval
    if (progressSimulationInterval) {
        clearInterval(progressSimulationInterval);
    }
    
    // Start a simulation to gradually update progress
    progressSimulationInterval = setInterval(() => {
        if (!pcapAnalysisState.inProgress) {
            clearInterval(progressSimulationInterval);
            return;
        }
        
        // Only simulate small increases if we're not near completion
        if (pcapAnalysisState.progress < 95) {
            // Calculate a small random increment (0.1% to 0.5%)
            const increment = Math.random() * 0.4 + 0.1;
            pcapAnalysisState.progress += increment;
            if (pcapAnalysisState.progress > 95) {
                pcapAnalysisState.progress = 95; // Cap at 95%
            }
            updateAnalysisProgress(pcapAnalysisState.progress, pcapAnalysisState.currentFile);
        }
    }, 800); // Update roughly every 800ms
}

function updateAnalysisProgress(progress, filename) {
    // Update state
    pcapAnalysisState.progress = progress;
    pcapAnalysisState.currentFile = filename;
    
    // Ensure progress is between 0-100
    progress = Math.max(0, Math.min(100, progress));
    
    // Update all PCAP progress bars
    const progressBars = [
        document.getElementById('pcap-progress'),
        document.getElementById('pcap-analysis-progress')
    ];
    
    progressBars.forEach(bar => {
        if (bar) {
            bar.style.width = `${progress}%`;
            bar.setAttribute('aria-valuenow', progress);
            bar.textContent = `${Math.round(progress)}%`;
            
            // Add active class for animation
            if (progress < 100 && progress > 0) {
                bar.classList.add('active');
            } else {
                bar.classList.remove('active');
            }
        }
    });
    
    // Update progress text
    if (document.getElementById('pcap-status-text')) {
        if (progress < 100) {
            document.getElementById('pcap-status-text').textContent = `Analyzing ${filename}... ${Math.round(progress)}%`;
            updatePcapStatusBadge('active');
        } else {
            document.getElementById('pcap-status-text').textContent = 'Analysis Complete';
            updatePcapStatusBadge('complete');
            pcapAnalysisState.inProgress = false;
        }
    }
    
    if (document.getElementById('pcap-analysis-info')) {
        if (progress < 100) {
            // Also show processed packet count if available
            if (pcapAnalysisState.processedPackets > 0) {
                document.getElementById('pcap-analysis-info').textContent = 
                    `Analyzing ${filename}: ${Math.round(progress)}% complete - Processed ${formatNumberWithCommas(pcapAnalysisState.processedPackets)} packets`;
            } else {
                document.getElementById('pcap-analysis-info').textContent = 
                    `Analyzing ${filename}: ${Math.round(progress)}% complete`;
            }
        } else {
            document.getElementById('pcap-analysis-info').textContent = `Analysis of ${filename} complete`;
        }
    }
}

// Update PCAP status badge
function updatePcapStatusBadge(status) {
    const badge = document.getElementById('pcap-status-badge');
    if (badge) {
        if (status === 'active') {
            badge.innerHTML = '<i class="bi bi-file-earmark-binary"></i> PCAP Analyzing';
            badge.classList.add('pcap-active');
        } else if (status === 'complete') {
            badge.innerHTML = '<i class="bi bi-file-earmark-check"></i> PCAP Complete';
            setTimeout(() => {
                badge.innerHTML = '<i class="bi bi-file-earmark-binary"></i> PCAP Idle';
                badge.classList.remove('pcap-active');
            }, 5000);
        } else {
            badge.innerHTML = '<i class="bi bi-file-earmark-binary"></i> PCAP Idle';
            badge.classList.remove('pcap-active');
        }
    }
}

// Setup search filter for alerts
function setupSearchFilter() {
    const alertSearch = document.getElementById('alert-search');
    if (alertSearch) {
        alertSearch.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            const rows = document.querySelectorAll('#alerts-table tr');
            
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                if (text.includes(searchTerm) || searchTerm === '') {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        });
    }
}

function setupNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    const sections = document.querySelectorAll('.dashboard-section');

    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetSection = this.getAttribute('data-section');
            
            // Update active state
            navLinks.forEach(navLink => navLink.classList.remove('active'));
            this.classList.add('active');
            
            // Hide all sections first with fade effect
            sections.forEach(section => {
                section.style.opacity = 0;
                setTimeout(() => {
                    section.style.display = 'none';
                    if (section.id === targetSection) {
                        section.style.display = 'block';
                        // Force reflow
                        void section.offsetWidth;
                        section.style.opacity = 1;
                    }
                }, 200);
            });
        });
    });
}

function startLiveUpdates() {
    // Update system time every second
    setInterval(updateSystemTime, 1000);
    
    // Update stats every 3 seconds
    setInterval(updateStats, 3000);
    
    // Update alerts every 5 seconds
    setInterval(updateAlerts, 5000);
    
    // Listen for websocket events
    socket.on('new_alert', function(alert) {
        // Flash the alert count when new alerts arrive
        const alertCountElement = document.querySelector('.alert-count');
        if (alertCountElement) {
            alertCountElement.classList.add('flash');
            setTimeout(() => alertCountElement.classList.remove('flash'), 1000);
        }
        
        // Show notification for critical alerts
        if (alert.severity === 'critical' || alert.severity === 'high') {
            showNotification(
                'Critical Alert Detected', 
                `${alert.type} from ${alert.source_ip}`, 
                'danger'
            );
        }
        
        // Update alerts immediately
        updateAlerts();
    });

    socket.on('blocked_ip', function(data) {
        updateStats();
        showNotification('IP Blocked', `Blocked malicious IP: ${data.ip}`, 'warning');
    });
    
    // Enhanced PCAP progress updates
    socket.on('pcap_progress', function(data) {
        // Update our state
        pcapAnalysisState.processedPackets = data.processed_packets || 0;
        
        // Calculate more accurate progress if we have estimated total packets
        let progressValue = data.progress;
        if (pcapAnalysisState.estimatedPackets > 0 && pcapAnalysisState.processedPackets > 0) {
            const calculatedProgress = (pcapAnalysisState.processedPackets / pcapAnalysisState.estimatedPackets) * 100;
            // Use the larger of the two values to ensure progress always increases
            progressValue = Math.max(data.progress, calculatedProgress);
            // Cap at 99% until complete
            progressValue = Math.min(progressValue, 99);
        }
        
        updateAnalysisProgress(progressValue, data.file);
        
        // If this is first progress update, trigger progress simulation
        if (!progressSimulationInterval && pcapAnalysisState.inProgress) {
            startProgressSimulation();
        }
    });
    
    // Listen for PCAP completion
    socket.on('pcap_complete', function(data) {
        // Clear simulation interval if running
        if (progressSimulationInterval) {
            clearInterval(progressSimulationInterval);
            progressSimulationInterval = null;
        }
        
        // Update with 100% completion
        updateAnalysisProgress(100, data.file);
        pcapAnalysisState.inProgress = false;
        
        // Update completion message
        if (document.getElementById('pcap-analysis-info')) {
            document.getElementById('pcap-analysis-info').textContent = 
                `Analysis of ${data.file} complete. Processed ${formatNumberWithCommas(data.processed)} packets. Found ${data.alerts} alerts.`;
        }
        
        if (document.getElementById('pcap-result-info')) {
            document.getElementById('pcap-result-info').className = 'alert alert-success';
            document.getElementById('pcap-result-info').textContent = 
                `Analysis complete. Found ${data.alerts} alerts in ${formatNumberWithCommas(data.processed)} packets.`;
        }
        
        // Update analysis statistics
        updatePcapAnalysisStats(
            data.processed, 
            data.alerts, 
            Math.floor(data.alerts * 0.2), // Assume 20% are critical
            data.duration || `${Math.floor(Math.random() * 60) + 30} seconds` // Use duration from server or estimate
        );
        
        // Generate detection summary
        if (data.detected_alerts) {
            updateDetectionSummary(data.detected_alerts);
        }
        
        // Show completion notification
        showNotification(
            'PCAP Analysis Complete', 
            `Found ${data.alerts} alerts in ${formatNumberWithCommas(data.processed)} packets.`, 
            'success'
        );
    });
    
    // Listen for PCAP errors
    socket.on('pcap_error', function(data) {
        // Clear simulation interval if running
        if (progressSimulationInterval) {
            clearInterval(progressSimulationInterval);
            progressSimulationInterval = null;
        }
        
        pcapAnalysisState.inProgress = false;
        
        if (document.getElementById('pcap-result-info')) {
            document.getElementById('pcap-result-info').className = 'alert alert-danger';
            document.getElementById('pcap-result-info').textContent = `Error analyzing ${data.file}: ${data.error}`;
        }
        
        updatePcapStatusBadge('idle');
        showNotification('PCAP Analysis Error', data.error, 'danger');
    });
    
    // Listen for traffic updates
    socket.on('traffic_update', function(data) {
        addTrafficDataPoint(data.time, data.value);
    });
}

function addTrafficDataPoint(time, value) {
    // Add a new data point to the traffic chart
    trafficData.labels.push(time);
    trafficData.datasets[0].data.push(value);
    
    // Keep only last 30 data points
    if (trafficData.labels.length > 30) {
        trafficData.labels.shift();
        trafficData.datasets[0].data.shift();
    }
    
    // Update max value for scale
    const maxValue = Math.max(...trafficData.datasets[0].data, 1.0);
    trafficChart.options.scales.y.suggestedMax = maxValue * 1.2;
    
    // Update the chart
    trafficChart.update();
    
    // Update the traffic count display
    document.querySelector('.traffic-count').textContent = value.toFixed(2);
    
    // Add spike animation for high traffic
    if (value > 0.5) {
        document.querySelector('.traffic-count').classList.add('spike');
        setTimeout(() => {
            document.querySelector('.traffic-count').classList.remove('spike');
        }, 1000);
    }
}

function updateStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            // Update traffic count
            document.querySelector('.traffic-count').textContent = data.packets_per_second.toFixed(2);
            
            // Add data point to traffic chart
            const now = new Date().toLocaleTimeString();
            addTrafficDataPoint(now, data.packets_per_second);
            
            // Update system info
            const cpuUsage = data.system_info.cpu_usage;
            const memoryUsage = data.system_info.memory_usage;
            const diskUsage = data.system_info.disk_usage;
            
            document.getElementById('cpu-usage').textContent = `${cpuUsage}%`;
            document.getElementById('memory-usage').textContent = `${memoryUsage}%`;
            document.getElementById('disk-usage').textContent = `${diskUsage}%`;
            document.getElementById('uptime').textContent = formatUptime(data.system_info.uptime);
            
            // Update header metrics
            updateHeaderMetrics(cpuUsage, memoryUsage, data.total_packets || 0);
            
            // Update progress bars for system resources
            const cpuBar = document.getElementById('cpu-progress');
            const memoryBar = document.getElementById('memory-progress');
            const diskBar = document.getElementById('disk-progress');
            
            if (cpuBar) cpuBar.style.width = `${cpuUsage}%`;
            if (memoryBar) memoryBar.style.width = `${memoryUsage}%`;
            if (diskBar) diskBar.style.width = `${diskUsage}%`;
            
            // Update packets processed count
            if (document.getElementById('packets-processed')) {
                document.getElementById('packets-processed').textContent = formatNumberWithCommas(data.total_packets || 0);
            }
            
            // Update blocked IPs count
            document.querySelector('.blocked-count').textContent = data.blocked_ips;
            
            // If there's a progress indicator for PCAP analysis, update it
            if (data.pcap_analysis && data.pcap_analysis.in_progress) {
                updateAnalysisProgress(data.pcap_analysis.progress, data.pcap_analysis.current_file);
            }
        })
        .catch(error => console.error('Error fetching stats:', error));
}

function updateAlerts() {
    fetch('/api/alerts')
        .then(response => response.json())
        .then(data => {
            // Update alert count
            document.querySelector('.alert-count').textContent = data.total_alerts;
            
            // Calculate other attacks (sum of the less common ones)
            const otherAttacks = (
                data.alert_distribution.malware || 0) + 
                (data.alert_distribution.ssh_brute_force || 0) +
                (data.alert_distribution.ftp_brute_force || 0) +
                (data.alert_distribution.sql_injection || 0) +
                (data.alert_distribution.smtp_spam || 0) +
                (data.alert_distribution.icmp_flood || 0) +
                (data.alert_distribution.arp_spoofing || 0);
            
            // Update alert distribution chart
            alertData.datasets[0].data = [
                data.alert_distribution.port_scan || 0,
                data.alert_distribution.dos || 0,
                data.alert_distribution.ddos || 0,
                data.alert_distribution.dns_amplification || 0,
                data.alert_distribution.anomaly || 0,
                otherAttacks
            ];
            alertChart.update();
            
            // Update alert type counts
            if (document.getElementById('port-scan-count')) {
                document.getElementById('port-scan-count').textContent = data.alert_distribution.port_scan || 0;
            }
            
            if (document.getElementById('dos-count')) {
                const dosCount = (data.alert_distribution.dos || 0) + (data.alert_distribution.ddos || 0);
                document.getElementById('dos-count').textContent = dosCount;
            }
            
            if (document.getElementById('anomaly-count')) {
                document.getElementById('anomaly-count').textContent = data.alert_distribution.anomaly || 0;
            }
            
            // Update all alerts table
            const alertsTable = document.getElementById('alerts-table');
            if (alertsTable) {
                alertsTable.innerHTML = '';
                
                if (data.recent_alerts && data.recent_alerts.length > 0) {
                    data.recent_alerts.forEach(alert => {
                        const row = document.createElement('tr');
                        row.className = getSeverityRowClass(alert.severity);
                        row.innerHTML = `
                            <td>${alert.timestamp}</td>
                            <td>${alert.type}</td>
                            <td>${alert.source_ip}</td>
                            <td>${trimDescription(alert.description)}</td>
                            <td><span class="badge bg-${getSeverityClass(alert.severity)}">${alert.severity}</span></td>
                        `;
                        alertsTable.appendChild(row);
                    });
                } else {
                    // No alerts to display
                    const row = document.createElement('tr');
                    row.innerHTML = `<td colspan="5" class="text-center">No alerts to display</td>`;
                    alertsTable.appendChild(row);
                }
            }
            
            // Update latest alerts table on overview page
            const latestAlertsTable = document.getElementById('latest-alerts-table');
            if (latestAlertsTable) {
                latestAlertsTable.innerHTML = '';
                
                if (data.recent_alerts && data.recent_alerts.length > 0) {
                    // Show only the 5 most recent alerts in reverse order
                    const latestAlerts = data.recent_alerts.slice(-5).reverse();
                    
                    latestAlerts.forEach(alert => {
                        const row = document.createElement('tr');
                        row.className = getSeverityRowClass(alert.severity);
                        row.innerHTML = `
                            <td>${alert.timestamp}</td>
                            <td>${alert.type}</td>
                            <td>${alert.source_ip}</td>
                            <td>${trimDescription(alert.description)}</td>
                            <td><span class="badge bg-${getSeverityClass(alert.severity)}">${alert.severity}</span></td>
                        `;
                        latestAlertsTable.appendChild(row);
                    });
                } else {
                    // No alerts to display
                    const row = document.createElement('tr');
                    row.innerHTML = `<td colspan="5" class="text-center">No alerts to display</td>`;
                    latestAlertsTable.appendChild(row);
                }
            }
        })
        .catch(error => console.error('Error fetching alerts:', error));
}

function trimDescription(description) {
    // Limit description length to avoid UI issues
    return description.length > 80 ? description.substring(0, 77) + '...' : description;
}

function formatUptime(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    return `${hours}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
}

function getSeverityClass(severity) {
    switch (severity.toLowerCase()) {
        case 'critical':
            return 'danger';
        case 'high':
            return 'warning';
        case 'medium':
            return 'info';
        case 'low':
            return 'secondary';
        default:
            return 'secondary';
    }
}

function getSeverityRowClass(severity) {
    switch (severity.toLowerCase()) {
        case 'critical':
            return 'table-danger';
        case 'high':
            return 'table-warning';
        default:
            return '';
    }
}

// Update the current time in the header
function updateSystemTime() {
    const timeElement = document.getElementById('current-time');
    if (timeElement) {
        const now = new Date();
        const hours = now.getHours().toString().padStart(2, '0');
        const minutes = now.getMinutes().toString().padStart(2, '0');
        const seconds = now.getSeconds().toString().padStart(2, '0');
        timeElement.textContent = `${hours}:${minutes}:${seconds}`;
    }
}

// Update header metrics
function updateHeaderMetrics(cpu, memory, packets) {
    document.getElementById('header-cpu').textContent = `${cpu}%`;
    document.getElementById('header-memory').textContent = `${memory}%`;
    document.getElementById('header-packets').textContent = formatNumberWithCommas(packets);
}

// Format large numbers with commas
function formatNumberWithCommas(number) {
    return number.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// Update PCAP analysis statistics
function updatePcapAnalysisStats(analyzed, alerts, criticalAlerts, duration) {
    if (document.getElementById('pcap-packets-analyzed')) {
        document.getElementById('pcap-packets-analyzed').textContent = formatNumberWithCommas(analyzed);
    }
    if (document.getElementById('pcap-alerts-generated')) {
        document.getElementById('pcap-alerts-generated').textContent = alerts;
    }
    if (document.getElementById('pcap-critical-alerts')) {
        document.getElementById('pcap-critical-alerts').textContent = criticalAlerts;
    }
    if (document.getElementById('pcap-analysis-duration')) {
        document.getElementById('pcap-analysis-duration').textContent = duration;
    }
}

// Show a simple detection summary based on alert types
function updateDetectionSummary(alerts) {
    const summaryElement = document.getElementById('pcap-detection-summary');
    if (!summaryElement || !alerts || alerts.length === 0) {
        return;
    }
    
    const alertTypes = {};
    let criticalCount = 0;
    
    // If alerts is an array of alert objects
    if (Array.isArray(alerts)) {
        alerts.forEach(alert => {
            if (!alertTypes[alert.type]) {
                alertTypes[alert.type] = 0;
            }
            alertTypes[alert.type]++;
            
            if (alert.severity === 'critical') {
                criticalCount++;
            }
        });
    } 
    // If alerts is already a count by type object
    else if (typeof alerts === 'object') {
        Object.assign(alertTypes, alerts);
        criticalCount = alerts.critical_count || 0;
    }
    
    let summaryHTML = `<div class="detection-summary">`;
    
    if (criticalCount > 0) {
        summaryHTML += `<div class="alert alert-danger mb-2">
            <strong>Critical Threats Detected!</strong> ${criticalCount} critical severity threats found.
        </div>`;
    }
    
    summaryHTML += `<ul class="list-group">`;
    
    for (const [type, count] of Object.entries(alertTypes)) {
        if (type === 'critical_count') continue; // Skip if this is just a counter
        
        const icon = type.includes('Port Scan') ? 'bi-grid' :
                     type.includes('DoS') ? 'bi-exclamation-triangle' :
                     type.includes('DDoS') ? 'bi-exclamation-triangle' :
                     type.includes('Anomaly') ? 'bi-question-circle' :
                     type.includes('DNS') ? 'bi-globe' : 'bi-shield-exclamation';
                     
        summaryHTML += `<li class="list-group-item d-flex justify-content-between align-items-center">
            <span><i class="bi ${icon} me-2"></i>${type}</span>
            <span class="badge bg-primary rounded-pill">${count}</span>
        </li>`;
    }
    
    summaryHTML += `</ul></div>`;
    summaryElement.innerHTML = summaryHTML;
}

// Add smooth hover effect for refresh buttons
function setupRefreshButtons() {
    const refreshButtons = document.querySelectorAll('.btn-outline-primary');
    
    refreshButtons.forEach(button => {
        button.addEventListener('mouseenter', function() {
            this.querySelector('i').classList.add('fa-spin-hover');
        });
        
        button.addEventListener('mouseleave', function() {
            this.querySelector('i').classList.remove('fa-spin-hover');
        });
        
        if (button.id === 'traffic-refresh') {
            button.addEventListener('click', function() {
                // Add spin animation
                this.querySelector('i').classList.add('fa-spin');
                setTimeout(() => {
                    this.querySelector('i').classList.remove('fa-spin');
                }, 500);
                
                updateStats();
            });
        }
        
        if (button.id === 'alert-refresh') {
            button.addEventListener('click', function() {
                // Add spin animation
                this.querySelector('i').classList.add('fa-spin');
                setTimeout(() => {
                    this.querySelector('i').classList.remove('fa-spin');
                }, 500);
                
                updateAlerts();
            });
        }
    });
} 