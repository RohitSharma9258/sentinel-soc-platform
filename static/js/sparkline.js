/**
 * Smart WiFi Intruder Detection System - Sparkline Utility
 * Renders small, glowing line charts on canvas elements inside metric cards.
 */

function drawSparkline(canvasId, dataPoints, color = '#00ff88') {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * window.devicePixelRatio;
    canvas.height = rect.height * window.devicePixelRatio;
    
    const ctx = canvas.getContext('2d');
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    ctx.clearRect(0, 0, rect.width, rect.height);
    
    // Generate organic simulated wave data if no data provided
    if (!dataPoints || dataPoints.length < 2) {
        const seed = Math.random() * 10;
        dataPoints = Array.from({length: 12}, (_, i) => 15 + Math.sin(i * 0.7 + seed) * 8 + Math.random() * 3);
    }
    
    const max = Math.max(...dataPoints) * 1.15;
    const min = Math.min(...dataPoints) * 0.85;
    const range = max - min || 1;
    
    const step = rect.width / (dataPoints.length - 1);
    
    ctx.beginPath();
    ctx.lineWidth = 1.8;
    ctx.strokeStyle = color;
    
    // Subtle glow backing
    ctx.shadowColor = color;
    ctx.shadowBlur = 6;
    
    dataPoints.forEach((val, idx) => {
        const x = idx * step;
        const y = rect.height - ((val - min) / range) * (rect.height - 8) - 4;
        if (idx === 0) {
            ctx.moveTo(x, y);
        } else {
            ctx.lineTo(x, y);
        }
    });
    ctx.stroke();
    
    // Gradient fill under trend line
    ctx.shadowBlur = 0; 
    ctx.lineTo(rect.width, rect.height);
    ctx.lineTo(0, rect.height);
    ctx.closePath();
    
    const gradient = ctx.createLinearGradient(0, 0, 0, rect.height);
    
    let rgbaColor = 'rgba(0, 255, 136, 0.1)';
    if (color === '#ff3b5c') rgbaColor = 'rgba(255, 59, 92, 0.1)';
    else if (color === '#00d4ff') rgbaColor = 'rgba(0, 212, 255, 0.1)';
    else if (color === '#ff9f43') rgbaColor = 'rgba(255, 159, 67, 0.1)';
    
    gradient.addColorStop(0, rgbaColor);
    gradient.addColorStop(1, 'transparent');
    ctx.fillStyle = gradient;
    ctx.fill();
}
