/**
 * Smart WiFi Intruder Detection System - Real-time Node Graph
 * Uses D3.js Force Simulation to render canvas-based topology and packet flows.
 */

let graphSimulation = null;
let graphNodes = [];
let graphLinks = [];
let hoveredNode = null;
let graphZoom = null;
let graphTransform = d3.zoomIdentity;

async function initNetworkGraph() {
    const canvas = document.getElementById('network-graph-canvas');
    if (!canvas) return;
    
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * window.devicePixelRatio;
    canvas.height = rect.height * window.devicePixelRatio;
    const width = canvas.width;
    const height = canvas.height;
    
    const ctx = canvas.getContext('2d');
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    
    // Initialize D3 zoom behavior
    graphZoom = d3.zoom()
        .scaleExtent([0.15, 6])
        .on('zoom', (event) => {
            graphTransform = event.transform;
            if (graphSimulation && graphSimulation.alpha() < 0.05) {
                // If simulation is idle, force a redraw frame to make zoom feel responsive
                graphSimulation.alpha(0.01).restart();
            }
        });
        
    d3.select(canvas).call(graphZoom).on("dblclick.zoom", null);
    
    // Fetch data
    const devicesRes = await fetch('/devices?filter=all');
    const devicesData = await devicesRes.json();
    const threatsRes = await fetch('/threats');
    const threatsData = await threatsRes.json();
    
    if (!devicesData.success) return;
    
    const threatsSet = new Set((threatsData.threats || []).filter(t => !t.resolved).map(t => t.device_mac));
    
    // Fetch system values for gateway/local
    let gatewayIp = '192.168.1.1';
    let localIp = '127.0.0.1';
    try {
        const liveRes = await fetch('/live-status');
        const liveData = await liveRes.json();
        if (liveData.success) {
            gatewayIp = liveData.gateway_ip || liveData.stats?.current_subnet?.replace('.0/24', '.1') || '192.168.1.1';
            localIp = liveData.local_ip || '127.0.0.1';
        }
    } catch(e) {
        console.warn('Could not load live stats for node mapping:', e);
    }
    
    // Keep positions if updating to prevent jumping nodes
    const nodePositionMap = new Map(graphNodes.map(n => [n.id, { x: n.x, y: n.y, vx: n.vx, vy: n.vy }]));
    
    graphNodes = devicesData.devices.map(d => {
        let type = 'device';
        if (d.ip === gatewayIp) type = 'gateway';
        else if (d.is_blocked === 1) type = 'blocked';
        else if (threatsSet.has(d.mac)) type = 'threat';
        else if (d.is_known === 1) type = 'trusted';
        else if (d.ip === localIp) type = 'local';
        
        const oldPos = nodePositionMap.get(d.mac);
        return {
            id: d.mac,
            ip: d.ip,
            mac: d.mac,
            hostname: d.hostname || 'Unknown',
            vendor: d.vendor || 'Unknown',
            type: type,
            isOnline: d.is_online === 1,
            x: oldPos ? oldPos.x : Math.random() * rect.width,
            y: oldPos ? oldPos.y : Math.random() * rect.height,
            vx: oldPos ? oldPos.vx : 0,
            vy: oldPos ? oldPos.vy : 0
        };
    });
    
    // Connect all node devices to the gateway
    const gatewayNode = graphNodes.find(n => n.type === 'gateway');
    graphLinks = [];
    if (gatewayNode) {
        graphNodes.forEach(n => {
            if (n.id !== gatewayNode.id) {
                graphLinks.push({
                    source: n.id,
                    target: gatewayNode.id,
                    pulse: Math.random()
                });
            }
        });
    }
    
    if (graphSimulation) graphSimulation.stop();
    
    graphSimulation = d3.forceSimulation(graphNodes)
        .force('link', d3.forceLink(graphLinks).id(d => d.id).distance(110))
        .force('charge', d3.forceManyBody().strength(-200))
        .force('center', d3.forceCenter(rect.width / 2, rect.height / 2))
        .force('collide', d3.forceCollide().radius(25));
        
    graphSimulation.on('tick', () => {
        ctx.clearRect(0, 0, rect.width, rect.height);
        
        ctx.save();
        ctx.translate(graphTransform.x, graphTransform.y);
        ctx.scale(graphTransform.k, graphTransform.k);
        
        // 1. Draw subtle background cyber lines (zooming grid)
        ctx.strokeStyle = 'rgba(0, 255, 136, 0.015)';
        ctx.lineWidth = 1;
        for (let i = -rect.width * 2; i < rect.width * 3; i += 20) {
            ctx.beginPath(); ctx.moveTo(i, -rect.height * 2); ctx.lineTo(i, rect.height * 3); ctx.stroke();
        }
        for (let j = -rect.height * 2; j < rect.height * 3; j += 20) {
            ctx.beginPath(); ctx.moveTo(-rect.width * 2, j); ctx.lineTo(rect.width * 3, j); ctx.stroke();
        }
        
        // 2. Draw connections (links) with animated stream particles
        graphLinks.forEach(link => {
            if (!link.source.x || !link.source.y || !link.target.x || !link.target.y) return;
            
            ctx.beginPath();
            ctx.moveTo(link.source.x, link.source.y);
            ctx.lineTo(link.target.x, link.target.y);
            ctx.strokeStyle = (link.source.type === 'threat' || link.target.type === 'threat')
                ? 'rgba(255, 59, 92, 0.25)'
                : 'rgba(0, 212, 255, 0.15)';
            ctx.lineWidth = 1.5;
            ctx.stroke();
            
            // Particle pulse animation along the connector
            link.pulse = (link.pulse + 0.006) % 1;
            const px = link.source.x + (link.target.x - link.source.x) * link.pulse;
            const py = link.source.y + (link.target.y - link.source.y) * link.pulse;
            
            ctx.beginPath();
            ctx.arc(px, py, 3.5, 0, 2 * Math.PI);
            ctx.fillStyle = (link.source.type === 'threat' || link.target.type === 'threat') ? '#ff3b5c' : '#00d4ff';
            ctx.fill();
        });
        
        // 3. Draw nodes with neon overlays
        graphNodes.forEach(node => {
            if (!node.x || !node.y) return;
            
            if (node.type === 'gateway') {
                // Double Ring Shield gateway
                ctx.beginPath();
                ctx.arc(node.x, node.y, 16, 0, 2 * Math.PI);
                ctx.strokeStyle = '#00ff88';
                ctx.lineWidth = 1;
                ctx.stroke();
                
                ctx.beginPath();
                ctx.arc(node.x, node.y, 11, 0, 2 * Math.PI);
                ctx.fillStyle = '#00ff88';
                ctx.strokeStyle = 'rgba(0, 255, 136, 0.3)';
                ctx.lineWidth = 3;
                ctx.stroke();
                ctx.fill();
                
                ctx.fillStyle = '#04060a';
                ctx.font = 'bold 9px sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText('🛡️', node.x, node.y);
            } else if (node.type === 'blocked') {
                // Orange/red blocked crosshair node
                ctx.beginPath();
                ctx.arc(node.x, node.y, 8, 0, 2 * Math.PI);
                ctx.fillStyle = '#ff9f43';
                ctx.strokeStyle = 'rgba(255, 159, 67, 0.4)';
                ctx.lineWidth = 3;
                ctx.stroke();
                ctx.fill();
                
                ctx.strokeStyle = '#04060a';
                ctx.lineWidth = 1.5;
                ctx.beginPath();
                ctx.moveTo(node.x - 4, node.y - 4);
                ctx.lineTo(node.x + 4, node.y + 4);
                ctx.moveTo(node.x + 4, node.y - 4);
                ctx.lineTo(node.x - 4, node.y + 4);
                ctx.stroke();
            } else if (node.type === 'threat') {
                // Red threat pulsing skull node
                const wave = Math.sin(Date.now() / 150) * 2;
                ctx.beginPath();
                ctx.arc(node.x, node.y, 13 + wave, 0, 2 * Math.PI);
                ctx.fillStyle = 'rgba(255, 59, 92, 0.15)';
                ctx.fill();
                
                ctx.beginPath();
                ctx.arc(node.x, node.y, 8, 0, 2 * Math.PI);
                ctx.fillStyle = '#ff3b5c';
                ctx.strokeStyle = 'rgba(255, 59, 92, 0.4)';
                ctx.lineWidth = 3;
                ctx.stroke();
                ctx.fill();
                
                ctx.fillStyle = '#fff';
                ctx.font = 'bold 8px sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText('💀', node.x, node.y);
            } else if (node.type === 'trusted') {
                // Trusted green node
                ctx.beginPath();
                ctx.arc(node.x, node.y, 8, 0, 2 * Math.PI);
                ctx.fillStyle = '#00ff88';
                ctx.strokeStyle = 'rgba(0, 255, 136, 0.3)';
                ctx.lineWidth = 3;
                ctx.stroke();
                ctx.fill();
            } else if (node.type === 'local') {
                // Cyan local node
                ctx.beginPath();
                ctx.arc(node.x, node.y, 8, 0, 2 * Math.PI);
                ctx.fillStyle = '#00d4ff';
                ctx.strokeStyle = 'rgba(0, 212, 255, 0.3)';
                ctx.lineWidth = 3;
                ctx.stroke();
                ctx.fill();
            } else {
                // Generic node
                ctx.beginPath();
                ctx.arc(node.x, node.y, 7, 0, 2 * Math.PI);
                ctx.fillStyle = node.isOnline ? '#00d4ff' : '#475569';
                ctx.strokeStyle = node.isOnline ? 'rgba(0, 212, 255, 0.2)' : 'rgba(71, 85, 105, 0.2)';
                ctx.lineWidth = 2.5;
                ctx.stroke();
                ctx.fill();
            }
            
            // Node name labels
            ctx.fillStyle = node.type === 'threat' ? '#ff3b5c' : '#94a3b8';
            ctx.font = '9px "JetBrains Mono", monospace';
            ctx.textAlign = 'center';
            ctx.fillText(node.ip, node.x, node.y - (node.type === 'gateway' ? 18 : 14));
        });
        
        ctx.restore();
    });
    
    // Mouse hover handler
    canvas.addEventListener('mousemove', e => {
        const mouseX = (e.offsetX - graphTransform.x) / graphTransform.k;
        const mouseY = (e.offsetY - graphTransform.y) / graphTransform.k;
        let found = null;
        
        for (const node of graphNodes) {
            const dist = Math.hypot(node.x - mouseX, node.y - mouseY);
            if (dist < 15) {
                found = node;
                break;
            }
        }
        
        const tooltip = document.getElementById('graph-tooltip');
        if (found) {
            canvas.style.cursor = 'pointer';
            hoveredNode = found;
            tooltip.style.display = 'block';
            tooltip.style.left = `${e.offsetX + 15}px`;
            tooltip.style.top = `${e.offsetY + 15}px`;
            tooltip.innerHTML = `
                <strong>Host:</strong> ${found.hostname}<br/>
                <strong>IP:</strong> ${found.ip}<br/>
                <strong>MAC:</strong> ${found.mac}<br/>
                <strong>Vendor:</strong> ${found.vendor}<br/>
                <strong>Type:</strong> ${found.type.toUpperCase()}<br/>
                <strong>Status:</strong> ${found.isOnline ? 'ONLINE' : 'OFFLINE'}
            `;
        } else {
            canvas.style.cursor = 'default';
            hoveredNode = null;
            tooltip.style.display = 'none';
        }
    });
}

function zoomInGraph() {
    const canvas = document.getElementById('network-graph-canvas');
    if (canvas && graphZoom) {
        d3.select(canvas).transition().duration(250).call(graphZoom.scaleBy, 1.3);
    }
}

function zoomOutGraph() {
    const canvas = document.getElementById('network-graph-canvas');
    if (canvas && graphZoom) {
        d3.select(canvas).transition().duration(250).call(graphZoom.scaleBy, 0.75);
    }
}

function resetGraphView() {
    const canvas = document.getElementById('network-graph-canvas');
    if (canvas && graphZoom) {
        d3.select(canvas).transition().duration(250).call(graphZoom.transform, d3.zoomIdentity);
    }
    if (graphSimulation) {
        graphSimulation.alpha(1).restart();
    }
}
