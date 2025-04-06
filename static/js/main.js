document.addEventListener('DOMContentLoaded', function() {
    // Dashboard functionality
    const scanBtn = document.getElementById('scan-btn');
    const scanSpinner = document.getElementById('scan-spinner');
    const statusMessage = document.getElementById('status-message');
    const networksCount = document.getElementById('networks-count');
    const networksTable = document.getElementById('networks-table');
    const networksTbody = document.getElementById('networks-tbody');
    
    // Modal elements
    const modal = document.getElementById('network-details-modal');
    const closeModalBtn = document.getElementById('close-modal-btn');
    const modalTitle = document.getElementById('modal-title');
    const modalSsid = document.getElementById('modal-ssid');
    const modalBssid = document.getElementById('modal-bssid');
    const modalSecurity = document.getElementById('modal-security');
    const checkSecurityBtn = document.getElementById('check-security-btn');
    const vulnerabilitiesList = document.getElementById('vulnerabilities-list');
    
    // Security page elements
    const securityForm = document.getElementById('security-form');
    const securityResults = document.getElementById('security-results');
    const resultSsid = document.getElementById('result-ssid');
    const resultBssid = document.getElementById('result-bssid');
    const securityStatus = document.getElementById('security-status');
    const statusSecure = document.getElementById('status-secure');
    const statusWarning = document.getElementById('status-warning');
    const statusText = document.getElementById('status-text');
    const vulnerabilitiesListSecurity = document.getElementById('vulnerabilities-list');
    const recommendationsList = document.getElementById('recommendations-list');
    
    // Initialize polling for network status
    let pollingInterval = null;
    
    // Dashboard scan button
    if (scanBtn) {
        scanBtn.addEventListener('click', function() {
            startScan();
        });
    }
    
    // Close modal button
    if (closeModalBtn) {
        closeModalBtn.addEventListener('click', function() {
            modal.style.display = 'none';
        });
    }
    
    // Check security button in modal
    if (checkSecurityBtn) {
        checkSecurityBtn.addEventListener('click', function() {
            const ssid = modalSsid.textContent;
            const bssid = modalBssid.textContent;
            
            if (ssid && bssid) {
                checkNetworkSecurity(ssid, bssid);
            }
        });
    }
    
    // Security form submission
    if (securityForm) {
        securityForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const ssid = document.getElementById('ssid-input').value;
            const bssid = document.getElementById('bssid-input').value;
            
            if (ssid && bssid) {
                securityResults.classList.remove('hidden');
                resultSsid.textContent = ssid;
                resultBssid.textContent = bssid;
                statusText.textContent = 'Analyzing...';
                statusSecure.classList.add('hidden');
                statusWarning.classList.add('hidden');
                
                checkNetworkSecurityDetailed(ssid, bssid);
            }
        });
    }
    
    // Add event listeners to security check buttons in the table
    if (networksTbody) {
        networksTbody.addEventListener('click', function(e) {
            if (e.target.classList.contains('security-btn') || 
                e.target.parentElement.classList.contains('security-btn')) {
                
                const button = e.target.classList.contains('security-btn') ? 
                    e.target : e.target.parentElement;
                
                const ssid = button.getAttribute('data-ssid');
                const bssid = button.getAttribute('data-bssid');
                
                openNetworkModal(ssid, bssid);
            }
        });
    }
    
    // Function to start network scan
    function startScan() {
        // Show spinner and update status
        scanSpinner.classList.remove('hidden');
        statusMessage.textContent = 'Scanning for networks...';
        scanBtn.disabled = true;
        
        // Call the scan API
        fetch('/api/scan')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    // Start polling for results
                    startPolling();
                } else {
                    // Show error
                    statusMessage.textContent = 'Error: ' + data.message;
                    scanSpinner.classList.add('hidden');
                    scanBtn.disabled = false;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                statusMessage.textContent = 'Error: Could not start scan';
                scanSpinner.classList.add('hidden');
                scanBtn.disabled = false;
            });
    }
    
    // Function to poll for network scan results
    function startPolling() {
        // Clear any existing interval
        if (pollingInterval) {
            clearInterval(pollingInterval);
        }
        
        // Set up polling interval
        pollingInterval = setInterval(() => {
            fetch('/api/networks')
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        // Update the networks count
                        networksCount.textContent = data.networks.length;
                        
                        // Update the table
                        updateNetworksTable(data.networks);
                        
                        // If scanning is complete, stop polling
                        if (!data.scanning) {
                            clearInterval(pollingInterval);
                            scanSpinner.classList.add('hidden');
                            statusMessage.textContent = 'Scan complete. Found ' + data.networks.length + ' networks.';
                            scanBtn.disabled = false;
                        }
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    clearInterval(pollingInterval);
                    scanSpinner.classList.add('hidden');
                    statusMessage.textContent = 'Error: Could not retrieve scan results';
                    scanBtn.disabled = false;
                });
        }, 1000); // Poll every second
    }
    
    // Function to update the networks table
    function updateNetworksTable(networks) {
        // Clear the table
        networksTbody.innerHTML = '';
        
        // Add each network to the table
        networks.forEach(network => {
            const row = document.createElement('tr');
            
            // Create cells
            const ssidCell = document.createElement('td');
            ssidCell.textContent = network.ssid;
            
            const bssidCell = document.createElement('td');
            bssidCell.textContent = network.bssid;
            
            const channelCell = document.createElement('td');
            channelCell.textContent = network.channel;
            
            const signalCell = document.createElement('td');
            signalCell.textContent = network.signal_strength;
            
            const securityCell = document.createElement('td');
            securityCell.textContent = network.security;
            securityCell.classList.add('security-cell');
            if (network.security === 'None') {
                securityCell.classList.add('insecure');
            }
            
            const actionsCell = document.createElement('td');
            const securityBtn = document.createElement('button');
            securityBtn.classList.add('btn', 'small-btn', 'security-btn');
            securityBtn.setAttribute('data-ssid', network.ssid);
            securityBtn.setAttribute('data-bssid', network.bssid);
            
            const icon = document.createElement('i');
            icon.classList.add('fas', 'fa-shield-alt');
            securityBtn.appendChild(icon);
            securityBtn.appendChild(document.createTextNode(' Check'));
            
            actionsCell.appendChild(securityBtn);
            
            // Add cells to row
            row.appendChild(ssidCell);
            row.appendChild(bssidCell);
            row.appendChild(channelCell);
            row.appendChild(signalCell);
            row.appendChild(securityCell);
            row.appendChild(actionsCell);
            
            // Add row to table
            networksTbody.appendChild(row);
        });
    }
    
    // Function to open the network details modal
    function openNetworkModal(ssid, bssid) {
        modalTitle.textContent = 'Network Details: ' + ssid;
        modalSsid.textContent = ssid;
        modalBssid.textContent = bssid;
        
        // Find the security type from the table
        const securityCell = Array.from(document.querySelectorAll('#networks-tbody tr')).find(row => {
            return row.cells[0].textContent === ssid && row.cells[1].textContent === bssid;
        })?.cells[4];
        
        if (securityCell) {
            modalSecurity.textContent = securityCell.textContent;
        } else {
            modalSecurity.textContent = 'Unknown';
        }
        
        // Reset vulnerabilities list
        vulnerabilitiesList.innerHTML = '<p>Click "Check Security" to analyze this network</p>';
        
        // Show the modal
        modal.style.display = 'flex';
    }
    
    // Function to check network security (for modal)
    function checkNetworkSecurity(ssid, bssid) {
        vulnerabilitiesList.innerHTML = '<p>Analyzing security...</p>';
        
        fetch('/api/security', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                ssid: ssid,
                bssid: bssid
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                // Clear the list
                vulnerabilitiesList.innerHTML = '';
                
                if (data.vulnerabilities.length === 0) {
                    vulnerabilitiesList.innerHTML = '<p class="secure-message"><i class="fas fa-check-circle"></i> No obvious vulnerabilities found</p>';
                } else {
                    // Create a list of vulnerabilities
                    const list = document.createElement('ul');
                    data.vulnerabilities.forEach(vuln => {
                        const item = document.createElement('li');
                        item.textContent = vuln;
                        list.appendChild(item);
                    });
                    vulnerabilitiesList.appendChild(list);
                }
            } else {
                vulnerabilitiesList.innerHTML = '<p class="error-message">Error: ' + data.message + '</p>';
            }
        })
        .catch(error => {
            console.error('Error:', error);
            vulnerabilitiesList.innerHTML = '<p class="error-message">Error: Could not check security</p>';
        });
    }
    
    // Function to check network security (for security page)
    function checkNetworkSecurityDetailed(ssid, bssid) {
        fetch('/api/security', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                ssid: ssid,
                bssid: bssid
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                // Clear the lists
                vulnerabilitiesListSecurity.innerHTML = '';
                recommendationsList.innerHTML = '';
                
                if (data.vulnerabilities.length === 0) {
                    // Show secure status
                    statusSecure.classList.remove('hidden');
                    statusWarning.classList.add('hidden');
                    statusText.textContent = 'No vulnerabilities detected';
                    
                    // Add a message to the vulnerabilities list
                    const secureItem = document.createElement('li');
                    secureItem.textContent = 'No obvious vulnerabilities found in this network';
                    vulnerabilitiesListSecurity.appendChild(secureItem);
                    
                    // Add general recommendations
                    const rec1 = document.createElement('li');
                    rec1.textContent = 'Continue using strong, unique passwords';
                    recommendationsList.appendChild(rec1);
                    
                    const rec2 = document.createElement('li');
                    rec2.textContent = 'Keep your router firmware updated';
                    recommendationsList.appendChild(rec2);
                    
                    const rec3 = document.createElement('li');
                    rec3.textContent = 'Consider enabling additional security features like MAC filtering';
                    recommendationsList.appendChild(rec3);
                } else {
                    // Show warning status
                    statusSecure.classList.add('hidden');
                    statusWarning.classList.remove('hidden');
                    statusText.textContent = data.vulnerabilities.length + ' vulnerabilities detected';
                    
                    // Create a list of vulnerabilities
                    data.vulnerabilities.forEach(vuln => {
                        const item = document.createElement('li');
                        item.textContent = vuln;
                        vulnerabilitiesListSecurity.appendChild(item);
                    });
                    
                    // Add recommendations based on vulnerabilities
                    if (data.vulnerabilities.some(v => v.includes('WEP'))) {
                        const rec = document.createElement('li');
                        rec.textContent = 'Upgrade to WPA2 or WPA3 encryption immediately';
                        recommendationsList.appendChild(rec);
                    }
                    
                    if (data.vulnerabilities.some(v => v.includes('open'))) {
                        const rec = document.createElement('li');
                        rec.textContent = 'Enable WPA2 or WPA3 encryption with a strong password';
                        recommendationsList.appendChild(rec);
                    }
                    
                    // Add general recommendations
                    const rec = document.createElement('li');
                    rec.textContent = 'Update your router firmware to the latest version';
                    recommendationsList.appendChild(rec);
                }
            } else {
                // Show error
                statusSecure.classList.add('hidden');
                statusWarning.classList.remove('hidden');
                statusText.textContent = 'Error: ' + data.message;
                
                vulnerabilitiesListSecurity.innerHTML = '<li>Could not analyze security</li>';
            }
        })
        .catch(error => {
            console.error('Error:', error);
            statusSecure.classList.add('hidden');
            statusWarning.classList.remove('hidden');
            statusText.textContent = 'Error: Could not check security';
            
            vulnerabilitiesListSecurity.innerHTML = '<li>Could not analyze security</li>';
        });
    }
    
    // Initialize the dashboard if we're on that page
    if (scanBtn && networksTbody) {
        // Check if there are already networks in the table
        if (parseInt(networksCount.textContent) > 0) {
            statusMessage.textContent = 'Ready to scan. Last scan found ' + networksCount.textContent + ' networks.';
        } else {
            statusMessage.textContent = 'Ready to scan';
        }
    }
    
    // Close the modal when clicking outside of it
    window.addEventListener('click', function(event) {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
});
