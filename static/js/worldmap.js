/**
 * Smart WiFi Intruder Detection System - Attack Heatmap
 * Renders a futuristic dot-matrix world map and triggers pulsing neon alert points.
 */

let worldmapRequestFrame = null;

// Stylized dot coordinates mapping continents (X: 0-100, Y: 0-100)
const WORLD_MATRIX = [
    // North America
    {x: 8, y: 16}, {x: 12, y: 14}, {x: 16, y: 12}, {x: 20, y: 10}, {x: 24, y: 8},
    {x: 10, y: 20}, {x: 14, y: 18}, {x: 18, y: 16}, {x: 22, y: 14}, {x: 26, y: 12},
    {x: 12, y: 25}, {x: 16, y: 22}, {x: 20, y: 20}, {x: 24, y: 18}, {x: 28, y: 16},
    {x: 15, y: 30}, {x: 19, y: 28}, {x: 23, y: 26}, {x: 27, y: 24}, {x: 31, y: 22},
    {x: 18, y: 35}, {x: 22, y: 33}, {x: 26, y: 31}, {x: 30, y: 29}, {x: 20, y: 40},
    {x: 24, y: 38}, {x: 28, y: 36},
    // Central America
    {x: 21, y: 44}, {x: 22, y: 47}, {x: 23, y: 50},
    // South America
    {x: 25, y: 55}, {x: 29, y: 57}, {x: 27, y: 62}, {x: 31, y: 64}, {x: 29, y: 70},
    {x: 33, y: 72}, {x: 31, y: 78}, {x: 32, y: 84}, {x: 33, y: 90},
    // Greenland
    {x: 32, y: 8}, {x: 36, y: 6}, {x: 40, y: 4}, {x: 36, y: 11},
    // Africa
    {x: 44, y: 48}, {x: 48, y: 50}, {x: 52, y: 52}, {x: 50, y: 57}, {x: 53, y: 61},
    {x: 54, y: 66}, {x: 55, y: 71}, {x: 56, y: 76}, {x: 57, y: 81}, {x: 48, y: 44},
    {x: 52, y: 46}, {x: 56, y: 48}, {x: 54, y: 41}, {x: 58, y: 43},
    // Europe
    {x: 43, y: 22}, {x: 47, y: 20}, {x: 51, y: 18}, {x: 45, y: 26}, {x: 49, y: 24},
    {x: 53, y: 22}, {x: 47, y: 31}, {x: 51, y: 29}, {x: 55, y: 27}, {x: 49, y: 36},
    {x: 53, y: 34}, {x: 57, y: 32},
    // Asia
    {x: 58, y: 15}, {x: 63, y: 13}, {x: 68, y: 11}, {x: 73, y: 9}, {x: 78, y: 7},
    {x: 60, y: 20}, {x: 65, y: 18}, {x: 70, y: 16}, {x: 75, y: 14}, {x: 80, y: 12},
    {x: 62, y: 25}, {x: 67, y: 23}, {x: 72, y: 21}, {x: 77, y: 19}, {x: 82, y: 17},
    {x: 64, y: 30}, {x: 69, y: 28}, {x: 74, y: 26}, {x: 79, y: 24}, {x: 84, y: 22},
    {x: 66, y: 35}, {x: 71, y: 33}, {x: 76, y: 31}, {x: 81, y: 29}, {x: 86, y: 27},
    {x: 68, y: 41}, {x: 73, y: 39}, {x: 78, y: 37}, {x: 83, y: 35}, {x: 88, y: 33},
    // Middle East & India
    {x: 59, y: 43}, {x: 63, y: 45}, {x: 67, y: 47}, {x: 69, y: 51}, {x: 71, y: 55},
    // Southeast Asia
    {x: 76, y: 50}, {x: 80, y: 53}, {x: 84, y: 56},
    // Australia
    {x: 82, y: 71}, {x: 86, y: 73}, {x: 90, y: 75}, {x: 84, y: 77}, {x: 88, y: 79},
    {x: 86, y: 83}
];

async function initAttackHeatmap() {
    const canvas = document.getElementById('world-heatmap-canvas');
    if (!canvas) return;
    
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * window.devicePixelRatio;
    canvas.height = rect.height * window.devicePixelRatio;
    
    const ctx = canvas.getContext('2d');
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    
    // Fetch active threat events
    const threatsRes = await fetch('/threats');
    const threatsData = await threatsRes.json();
    if (!threatsData.success) return;
    
    const activeThreats = (threatsData.threats || []).filter(t => !t.resolved);
    
    // Derive deterministic map locations based on threat IP hashes
    const attackHotspots = activeThreats.map(t => {
        const ip = t.device_ip || '192.168.1.5';
        const hash = ip.split('.').reduce((acc, part) => acc + parseInt(part, 10), 0);
        
        // Hashing boundaries to place markers inside continental blocks
        const x = 15 + (hash * 17) % 70; 
        const y = 15 + (hash * 31) % 65; 
        
        return {
            x: (x / 100) * rect.width,
            y: (y / 100) * rect.height,
            ip: ip,
            type: t.threat_type,
            level: t.threat_level,
            pulse: Math.random() * Math.PI
        };
    });
    
    if (worldmapRequestFrame) cancelAnimationFrame(worldmapRequestFrame);
    
    function drawMap() {
        ctx.clearRect(0, 0, rect.width, rect.height);
        
        // 1. Draw dot-matrix continents
        WORLD_MATRIX.forEach(dot => {
            const px = (dot.x / 100) * rect.width;
            const py = (dot.y / 100) * rect.height;
            
            ctx.beginPath();
            ctx.arc(px, py, 1.8, 0, 2 * Math.PI);
            ctx.fillStyle = 'rgba(148, 163, 184, 0.15)'; // Slate dots
            ctx.fill();
        });
        
        // 2. Draw local monitoring hub target node (North America)
        const targetX = rect.width * 0.22;
        const targetY = rect.height * 0.35;
        
        ctx.beginPath();
        ctx.arc(targetX, targetY, 4, 0, 2 * Math.PI);
        ctx.fillStyle = '#00d4ff';
        ctx.fill();
        
        const targetWave = Math.abs(Math.sin(Date.now() / 400));
        ctx.beginPath();
        ctx.arc(targetX, targetY, 4 + targetWave * 8, 0, 2 * Math.PI);
        ctx.strokeStyle = 'rgba(0, 212, 255, 0.4)';
        ctx.stroke();

        // 3. Draw active pulsing circles and parabolic attack arcs
        const hotspots = attackHotspots.length > 0 ? attackHotspots : [
            { x: rect.width * 0.55, y: rect.height * 0.25, level: 'critical', pulse: Math.random() * 5 }, // Europe
            { x: rect.width * 0.72, y: rect.height * 0.45, level: 'warning', pulse: Math.random() * 5 }   // India/Asia
        ];

        hotspots.forEach(spot => {
            if (!spot.pulse) spot.pulse = Math.random();
            spot.pulse += 0.02;
            const wave = Math.abs(Math.sin(spot.pulse));
            
            // Draw parabolic Bezier arc
            const midX = (spot.x + targetX) / 2;
            const midY = (spot.y + targetY) / 2 - 30; // Upward curve vertical height offset
            
            ctx.beginPath();
            ctx.moveTo(spot.x, spot.y);
            ctx.quadraticCurveTo(midX, midY, targetX, targetY);
            ctx.strokeStyle = spot.level === 'critical' ? 'rgba(255, 59, 92, 0.15)' : 'rgba(255, 159, 67, 0.15)';
            ctx.lineWidth = 1;
            ctx.stroke();
            
            // Flowing neon package particle
            const t = (spot.pulse * 0.25) % 1;
            const px = (1-t)*(1-t)*spot.x + 2*(1-t)*t*midX + t*t*targetX;
            const py = (1-t)*(1-t)*spot.y + 2*(1-t)*t*midY + t*t*targetY;
            
            ctx.beginPath();
            ctx.arc(px, py, 2, 0, 2 * Math.PI);
            ctx.fillStyle = spot.level === 'critical' ? '#ff3b5c' : '#ff9f43';
            ctx.shadowColor = ctx.fillStyle;
            ctx.shadowBlur = 4;
            ctx.fill();
            ctx.shadowBlur = 0; // Reset
            
            // Pulsing source coordinates glow
            ctx.beginPath();
            ctx.arc(spot.x, spot.y, 6 + wave * 14, 0, 2 * Math.PI);
            ctx.strokeStyle = spot.level === 'critical' ? 'rgba(255, 59, 92, 0.4)' : 'rgba(255, 159, 67, 0.4)';
            ctx.lineWidth = 1;
            ctx.stroke();
            
            // Inner source core
            ctx.beginPath();
            ctx.arc(spot.x, spot.y, 3, 0, 2 * Math.PI);
            ctx.fillStyle = spot.level === 'critical' ? '#ff3b5c' : '#ff9f43';
            ctx.fill();
        });
        
        worldmapRequestFrame = requestAnimationFrame(drawMap);
    }
    
    drawMap();
    
    // Mouse hover listener
    canvas.addEventListener('mousemove', e => {
        const mouseX = e.offsetX;
        const mouseY = e.offsetY;
        let found = null;
        
        for (const spot of attackHotspots) {
            const dist = Math.hypot(spot.x - mouseX, spot.y - mouseY);
            if (dist < 15) {
                found = spot;
                break;
            }
        }
        
        const tooltip = document.getElementById('heatmap-tooltip');
        if (found) {
            canvas.style.cursor = 'pointer';
            tooltip.style.display = 'block';
            tooltip.style.left = `${e.offsetX + 15}px`;
            tooltip.style.top = `${e.offsetY + 15}px`;
            tooltip.innerHTML = `
                <strong>Attack Point:</strong> Live Stream<br/>
                <strong>Source IP:</strong> ${found.ip}<br/>
                <strong>Anomaly:</strong> ${found.type.toUpperCase()}<br/>
                <strong>Level:</strong> <span style="color:#ff3b5c; font-weight:700;">${found.level.toUpperCase()}</span>
            `;
        } else {
            canvas.style.cursor = 'default';
            tooltip.style.display = 'none';
        }
    });
}
