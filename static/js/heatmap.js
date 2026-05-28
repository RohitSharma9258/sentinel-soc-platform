/**
 * Smart WiFi Intruder Detection System - Subnet Activity Heatmap
 * Maps active devices to a 16x16 IP grid space, pulsing block colors based on threat level and packet activity.
 */

let heatmapRequestFrame = null;

async function initSubnetHeatmap() {
    const canvas = document.getElementById('subnet-heatmap-canvas');
    if (!canvas) return;
    
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * window.devicePixelRatio;
    canvas.height = rect.height * window.devicePixelRatio;
    
    const ctx = canvas.getContext('2d');
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    
    // Fetch fresh devices
    const devicesRes = await fetch('/devices?filter=all');
    const devicesData = await devicesRes.json();
    if (!devicesData.success) return;
    
    // Setup 256 cells representing .0 to .255 in subnet
    const gridCells = Array.from({length: 256}, (_, idx) => {
        return {
            octet: idx,
            ip: '',
            device: null,
            pulse: Math.random() * Math.PI
        };
    });
    
    devicesData.devices.forEach(d => {
        const parts = d.ip.split('.');
        if (parts.length === 4) {
            const octet = parseInt(parts[3], 10);
            if (octet >= 0 && octet < 256) {
                gridCells[octet].ip = d.ip;
                gridCells[octet].device = d;
            }
        }
    });
    
    const columns = 16;
    const rows = 16;
    const padding = 2;
    const cellWidth = (rect.width - (columns + 1) * padding) / columns;
    const cellHeight = (rect.height - (rows + 1) * padding) / rows;
    
    if (heatmapRequestFrame) cancelAnimationFrame(heatmapRequestFrame);
    
    function drawHeatmap() {
        ctx.clearRect(0, 0, rect.width, rect.height);
        
        // Draw subtle background grid lines
        ctx.strokeStyle = 'rgba(0, 255, 136, 0.01)';
        ctx.lineWidth = 1;
        
        for (let i = 0; i < 256; i++) {
            const cell = gridCells[i];
            const x = i % columns;
            const y = Math.floor(i / columns);
            
            const px = padding + x * (cellWidth + padding);
            const py = padding + y * (cellHeight + padding);
            
            let fillStyle = 'rgba(15, 23, 42, 0.35)'; // Default empty cell color
            let strokeStyle = 'rgba(30, 41, 59, 0.3)';
            
            if (cell.device) {
                cell.pulse += 0.04;
                const wave = Math.abs(Math.sin(cell.pulse));
                
                if (cell.device.threat_level && cell.device.threat_level !== 'none') {
                    // Critical/warning alert (Flash deep red-orange)
                    fillStyle = `rgba(255, 59, 92, ${0.25 + wave * 0.45})`;
                    strokeStyle = `rgba(255, 59, 92, 0.75)`;
                } else if (cell.device.is_online) {
                    // Safe active device (Pulse emerald-cyan)
                    fillStyle = `rgba(0, 255, 136, ${0.15 + wave * 0.25})`;
                    strokeStyle = `rgba(0, 255, 136, 0.55)`;
                } else {
                    // Offline device
                    fillStyle = 'rgba(71, 85, 105, 0.15)';
                    strokeStyle = 'rgba(71, 85, 105, 0.35)';
                }
            }
            
            ctx.fillStyle = fillStyle;
            ctx.strokeStyle = strokeStyle;
            ctx.fillRect(px, py, cellWidth, cellHeight);
            ctx.strokeRect(px, py, cellWidth, cellHeight);
            
            // Draw attention indicators inside high-risk cells
            if (cell.device && cell.device.threat_level && cell.device.threat_level !== 'none') {
                ctx.fillStyle = '#ffffff';
                ctx.font = 'bold 9px sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText('!', px + cellWidth / 2, py + cellHeight / 2 + 3);
            }
        }
        
        heatmapRequestFrame = requestAnimationFrame(drawHeatmap);
    }
    
    drawHeatmap();
    
    // Mouse hover listener
    canvas.addEventListener('mousemove', e => {
        const mouseX = e.offsetX;
        const mouseY = e.offsetY;
        
        const col = Math.floor((mouseX - padding) / (cellWidth + padding));
        const row = Math.floor((mouseY - padding) / (cellHeight + padding));
        
        const tooltip = document.getElementById('heatmap-tooltip-subnet');
        
        if (col >= 0 && col < columns && row >= 0 && row < rows) {
            const idx = row * columns + col;
            const cell = gridCells[idx];
            
            if (cell && cell.device) {
                canvas.style.cursor = 'pointer';
                tooltip.style.display = 'block';
                tooltip.style.left = `${e.offsetX + 15}px`;
                tooltip.style.top = `${e.offsetY + 15}px`;
                tooltip.innerHTML = `
                    <strong>Subnet Addr:</strong> .${cell.octet}<br/>
                    <strong>IP:</strong> ${cell.device.ip}<br/>
                    <strong>MAC:</strong> ${cell.device.mac}<br/>
                    <strong>Vendor:</strong> ${cell.device.vendor || 'Unknown'}<br/>
                    <strong>Threat:</strong> ${cell.device.threat_level.toUpperCase()}
                `;
                return;
            }
        }
        
        canvas.style.cursor = 'default';
        tooltip.style.display = 'none';
    });
}
