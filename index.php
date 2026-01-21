<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Analyseur de Paquets Réseau - Temps Réel</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .header h1 {
            color: #333;
            margin-bottom: 10px;
        }

        .status {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 14px;
            color: #666;
        }

        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #4CAF50;
            animation: pulse 1s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .controls {
            margin-top: 10px;
            display: flex;
            gap: 10px;
        }

        button {
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            background: #667eea;
            color: white;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.3s;
        }

        button:hover {
            background: #764ba2;
        }

        .packets-container {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 15px;
        }

        .packet-card {
            background: white;
            border-radius: 8px;
            padding: 15px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
            animation: slideIn 0.3s ease;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .packet-card.lan {
            border-left-color: #4CAF50;
        }

        .packet-card.internet {
            border-left-color: #FF9800;
        }

        .packet-title {
            font-weight: bold;
            color: #333;
            margin-bottom: 10px;
            font-size: 14px;
        }

        .packet-info {
            font-size: 12px;
            color: #666;
            line-height: 1.8;
        }

        .label {
            font-weight: bold;
            color: #667eea;
        }

        .scope-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
            margin-top: 5px;
        }

        .scope-badge.lan {
            background: #c8e6c9;
            color: #2e7d32;
        }

        .scope-badge.internet {
            background: #ffe0b2;
            color: #e65100;
        }

        .no-packets {
            grid-column: 1 / -1;
            text-align: center;
            padding: 40px;
            color: white;
            font-size: 16px;
        }

        .packet-count {
            background: white;
            padding: 10px 15px;
            border-radius: 4px;
            font-weight: bold;
            color: #667eea;
        }

        .type-badge {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: bold;
            margin-right: 5px;
        }

        .type-badge.arp {
            background: #e1bee7;
            color: #6a1b9a;
        }

        .type-badge.tcp {
            background: #bbdefb;
            color: #0d47a1;
        }

        .type-badge.udp {
            background: #c8e6c9;
            color: #1b5e20;
        }

        .type-badge.icmp {
            background: #ffe0b2;
            color: #e65100;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Analyseur de Paquets Réseau</h1>
            <div class="status">
                <div class="status-indicator"></div>
                <span>Capture en temps réel...</span>
            </div>
            <div class="controls">
                <button onclick="pauseRefresh()">⏸ Pause</button>
                <button onclick="resumeRefresh()">▶ Reprendre</button>
                <span class="packet-count" id="packet-count">0 paquets</span>
            </div>
        </div>

        <div class="packets-container" id="packets-list">
            <div class="no-packets">En attente de paquets...</div>
        </div>
    </div>

    <script>
        let autoRefresh = true;
        let refreshInterval = null;

        function getPacketType(packet) {
            if (packet.arp) return { name: 'ARP', class: 'arp' };
            if (packet.tcp) return { name: 'TCP', class: 'tcp' };
            if (packet.udp) return { name: 'UDP', class: 'udp' };
            if (packet.icmp) return { name: 'ICMP', class: 'icmp' };
            return { name: 'AUTRE', class: 'autre' };
        }

        function getProtocolName(protocolNumber) {
            const protocols = {
                1: 'ICMP',
                6: 'TCP',
                17: 'UDP'
            };
            return protocols[protocolNumber] || `Proto ${protocolNumber}`;
        }

        function formatTime(timestamp) {
            const date = new Date(timestamp * 1000);
            return date.toLocaleTimeString('fr-FR');
        }

        function createPacketCard(packet) {
            const type = getPacketType(packet);
            const scope = packet.scope || 'UNKNOWN';
            let content = `<div class="packet-title">
                <span class="type-badge ${type.class}">${type.name}</span>
                ${formatTime(packet.timestamp)}
            </div>
            <div class="packet-info">`;

            // IPv4 - Source et Destinataire
            if (packet.ip) {
                const protocolName = getProtocolName(packet.ip.protocol);
                content += `<span class="label">Source:</span> ${packet.ip.src_ip}<br>`;
                content += `<span class="label">Destinataire:</span> ${packet.ip.dst_ip}<br>`;
                content += `<span class="label">Protocole:</span> ${protocolName} | `;
                content += `<span class="label">TTL:</span> ${packet.ip.ttl}<br>`;
            }

            // TCP - Info unifiée
            if (packet.tcp) {
                const service = packet.tcp.service;
                const flags = packet.tcp.flags;
                const info = flags !== "NONE" ? `${service} (${flags})` : service;
                content += `<span class="label">Port:</span> ${packet.tcp.src_port} → ${packet.tcp.dst_port}<br>`;
                content += `<span class="label">Info:</span> ${info}<br>`;
            }

            // UDP - Info unifiée
            if (packet.udp) {
                content += `<span class="label">Port:</span> ${packet.udp.src_port} → ${packet.udp.dst_port}<br>`;
                content += `<span class="label">Info:</span> ${packet.udp.service}<br>`;
            }

            // ICMP - Info unifiée
            if (packet.icmp) {
                content += `<span class="label">Info:</span> ${packet.icmp.type_name}<br>`;
            }

            // ARP
            if (packet.arp) {
                const opcode = packet.arp.opcode === 1 ? 'Request' : 'Reply';
                content += `<span class="label">Opcode:</span> ${opcode}<br>`;
                content += `<span class="label">Source:</span> ${packet.arp.src_ip} (${packet.arp.src_mac})<br>`;
                content += `<span class="label">Destinataire:</span> ${packet.arp.target_ip} (${packet.arp.target_mac})<br>`;
            }

            content += `<span class="scope-badge ${scope.toLowerCase()}">${scope}</span>`;
            content += `</div>`;

            const card = document.createElement('div');
            card.className = `packet-card ${scope.toLowerCase()}`;
            card.innerHTML = content;
            return card;
        }

        function loadPackets() {
            fetch('get_packets.php')
                .then(response => response.json())
                .then(packets => {
                    const container = document.getElementById('packets-list');
                    container.innerHTML = '';

                    if (!packets || packets.length === 0) {
                        container.innerHTML = '<div class="no-packets">En attente de paquets...</div>';
                    } else {
                        packets.forEach(packet => {
                            container.appendChild(createPacketCard(packet));
                        });
                    }

                    document.getElementById('packet-count').textContent = packets.length + ' paquet' + (packets.length > 1 ? 's' : '');
                })
                .catch(error => console.error('Erreur:', error));
        }

        function startAutoRefresh() {
            refreshInterval = setInterval(loadPackets, 1000); // Rafraîchissement chaque 1s
        }

        function pauseRefresh() {
            clearInterval(refreshInterval);
            autoRefresh = false;
        }

        function resumeRefresh() {
            autoRefresh = true;
            startAutoRefresh();
        }

        // Chargement initial et démarrage du rafraîchissement
        loadPackets();
        startAutoRefresh();
    </script>
</body>
</html>
