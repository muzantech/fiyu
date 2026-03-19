/**
 * FLYHOST WhatsApp Bot — Module Baileys standalone
 * Usage: node whatsapp-bot.js
 * Config: Set FLYHOST_API_URL and FLYHOST_BOT_TOKEN via env or config below
 */

const { default: makeWASocket, useMultiFileAuthState, DisconnectReason, fetchLatestBaileysVersion } = require('@whiskeysockets/baileys');
const { Boom } = require('@hapi/boom');
const path = require('path');
const fs = require('fs');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));

const CONFIG = {
    API_URL: process.env.FLYHOST_API_URL || 'http://localhost:5000',
    BOT_TOKEN: process.env.FLYHOST_BOT_TOKEN || '',
    AUTH_DIR: path.join(__dirname, 'whatsapp-auth'),
    PREFIX: '!',
    ADMIN_NUMBERS: (process.env.FLYHOST_BOT_ADMINS || '').split(',').filter(Boolean),
};

const COMMANDS = {
    start: { desc: 'Démarrer un serveur', usage: '!start <server_id>', admin: false },
    stop: { desc: 'Arrêter un serveur', usage: '!stop <server_id>', admin: false },
    restart: { desc: 'Redémarrer un serveur', usage: '!restart <server_id>', admin: false },
    status: { desc: 'Statut d\'un serveur', usage: '!status <server_id>', admin: false },
    coins: { desc: 'Voir votre solde de coins', usage: '!coins', admin: false },
    servers: { desc: 'Liste de vos serveurs', usage: '!servers', admin: false },
    help: { desc: 'Afficher cette aide', usage: '!help', admin: false },
    ping: { desc: 'Vérifier que le bot est actif', usage: '!ping', admin: false },
    broadcast: { desc: 'Envoyer un message à tous', usage: '!broadcast <message>', admin: true },
    stats: { desc: 'Statistiques plateforme', usage: '!stats', admin: true },
};

async function callAPI(endpoint, method = 'GET', body = null, token = null) {
    const opts = {
        method,
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : { Authorization: `Bearer ${CONFIG.BOT_TOKEN}` }) },
    };
    if (body) opts.body = JSON.stringify(body);
    const r = await fetch(CONFIG.API_URL + endpoint, opts);
    return r.json();
}

async function getUserByPhone(phone) {
    try {
        const clean = phone.replace('@s.whatsapp.net', '').replace(/\D/g, '');
        const d = await callAPI(`/api/bot/user-by-phone/${clean}`);
        return d.success ? d.user : null;
    } catch(e) { return null; }
}

async function handleCommand(sock, jid, message, senderPhone) {
    const text = message.conversation || message.extendedTextMessage?.text || '';
    if (!text.startsWith(CONFIG.PREFIX)) return;

    const [rawCmd, ...args] = text.slice(1).trim().split(/\s+/);
    const cmd = rawCmd.toLowerCase();
    const isAdmin = CONFIG.ADMIN_NUMBERS.includes(senderPhone.replace(/\D/g,''));

    const send = async (msg) => sock.sendMessage(jid, { text: msg });

    if (cmd === 'ping') {
        return send('🏓 Pong ! FLYHOST Bot est actif.');
    }

    if (cmd === 'help') {
        const lines = ['🚀 *FLYHOST Bot — Commandes disponibles*\n'];
        for (const [c, info] of Object.entries(COMMANDS)) {
            if (info.admin && !isAdmin) continue;
            lines.push(`▸ *${info.usage}*\n  ${info.desc}`);
        }
        return send(lines.join('\n'));
    }

    if (cmd === 'stats' && isAdmin) {
        try {
            const d = await callAPI('/api/status');
            if (!d.success) return send('❌ Impossible de récupérer les stats.');
            const s = d.stats;
            return send(
                `📊 *Statistiques FLYHOST*\n\n` +
                `👥 Utilisateurs: *${s.total_users || 0}*\n` +
                `🖥️ Serveurs actifs: *${s.active_servers || 0}*\n` +
                `▶️ En marche: *${s.running_servers || 0}*\n` +
                `🚀 Déploiements réussis: *${s.total_deployments || 0}*\n` +
                `💳 Paiements: *${s.total_payments || 0}*\n` +
                `🔌 Panel: *${d.panel_online ? 'En ligne ✅' : 'Hors ligne ❌'}*`
            );
        } catch(e) { return send('❌ Erreur réseau.'); }
    }

    if (cmd === 'broadcast' && isAdmin) {
        if (!args.length) return send('❌ Usage: !broadcast <message>');
        return send(`📢 Broadcast envoyé: "${args.join(' ')}"\n(Fonctionnalité en cours d\'intégration)`);
    }

    const user = await getUserByPhone(senderPhone);
    if (!user) {
        return send(`❌ Aucun compte FLYHOST lié à ce numéro.\nCreez votre compte sur *flihost.site* puis ajoutez votre numéro dans votre profil.`);
    }

    if (cmd === 'coins') {
        try {
            const d = await callAPI(`/api/bot/user-info/${user.id}`);
            return send(`💰 *Votre solde FLYHOST*\n\nCoins: *${d.coins || 0}*\nUtilisateur: *${user.username}*\nStatut: *${user.role || 'user'}*`);
        } catch(e) { return send('❌ Erreur récupération solde.'); }
    }

    if (cmd === 'servers') {
        try {
            const d = await callAPI(`/api/bot/servers/${user.id}`);
            if (!d.servers?.length) return send('📭 Vous n\'avez aucun serveur.');
            const lines = d.servers.map(s => `▸ [${s.id}] *${s.name}* — ${s.server_status || 'inconnu'} | ${s.game || '?'}`);
            return send(`🖥️ *Vos serveurs (${d.servers.length})*\n\n${lines.join('\n')}\n\nUtilisez *!status <id>* pour les détails.`);
        } catch(e) { return send('❌ Erreur récupération serveurs.'); }
    }

    if (['start','stop','restart','status'].includes(cmd)) {
        const serverId = args[0];
        if (!serverId) return send(`❌ Usage: ${COMMANDS[cmd]?.usage}`);
        const ACTIONS = { start: 'start', stop: 'kill', restart: 'restart' };
        try {
            if (cmd === 'status') {
                const d = await callAPI(`/api/bot/server-status/${user.id}/${serverId}`);
                if (!d.success) return send(`❌ Serveur #${serverId} introuvable ou accès refusé.`);
                const s = d.server;
                return send(
                    `🖥️ *Serveur #${s.id} — ${s.name}*\n\n` +
                    `▸ Statut: *${s.server_status || 'inconnu'}*\n` +
                    `▸ Jeu: *${s.game || '?'}*\n` +
                    `▸ RAM: *${s.ram_mb || '?'} MB*\n` +
                    `▸ Expire: *${s.expires_at ? new Date(s.expires_at).toLocaleDateString('fr-FR') : 'N/A'}*`
                );
            }
            const d = await callAPI(`/api/bot/server-action/${user.id}/${serverId}`, 'POST', { action: ACTIONS[cmd] });
            if (d.success) return send(`✅ Action *${cmd}* envoyée au serveur #${serverId}.`);
            return send(`❌ Erreur: ${d.error || 'Action refusée.'}`);
        } catch(e) { return send('❌ Erreur réseau.'); }
    }

    send(`❓ Commande inconnue. Tapez *!help* pour voir les commandes disponibles.`);
}

async function startBot() {
    if (!fs.existsSync(CONFIG.AUTH_DIR)) fs.mkdirSync(CONFIG.AUTH_DIR, { recursive: true });
    const { state, saveCreds } = await useMultiFileAuthState(CONFIG.AUTH_DIR);
    const { version } = await fetchLatestBaileysVersion();

    const sock = makeWASocket({
        version,
        auth: state,
        printQRInTerminal: true,
        browser: ['FLYHOST Bot', 'Chrome', '1.0.0'],
        syncFullHistory: false,
    });

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('connection.update', ({ connection, lastDisconnect, qr }) => {
        if (qr) console.log('[FLYHOST Bot] Scannez le QR code ci-dessus avec WhatsApp.');
        if (connection === 'close') {
            const code = new Boom(lastDisconnect?.error)?.output?.statusCode;
            const shouldReconnect = code !== DisconnectReason.loggedOut;
            console.log(`[FLYHOST Bot] Déconnecté (code ${code}). Reconnexion: ${shouldReconnect}`);
            if (shouldReconnect) setTimeout(startBot, 3000);
        } else if (connection === 'open') {
            console.log('[FLYHOST Bot] ✅ Connecté à WhatsApp !');
        }
    });

    sock.ev.on('messages.upsert', async ({ messages, type }) => {
        if (type !== 'notify') return;
        for (const msg of messages) {
            if (msg.key.fromMe || !msg.message) continue;
            const jid = msg.key.remoteJid;
            if (!jid) continue;
            const senderPhone = jid.replace('@s.whatsapp.net','').replace('@g.us','');
            try {
                await handleCommand(sock, jid, msg.message, senderPhone);
            } catch(e) {
                console.error('[FLYHOST Bot] Erreur traitement message:', e.message);
            }
        }
    });

    return sock;
}

// Bot API endpoints intégrés (à ajouter dans index.js si voulu)
const BOT_ROUTES = `
// Bot WhatsApp helper routes (requiert requireSuperAdmin)
app.get('/api/bot/user-by-phone/:phone', (req, res) => {
    db.get('SELECT id, username, role FROM users WHERE whatsapp_number LIKE ?', ['%' + req.params.phone + '%'],
        (err, row) => res.json({ success: !!row, user: row || null }));
});
app.get('/api/bot/user-info/:id', requireSuperAdmin, (req, res) => {
    db.get('SELECT id, username, coins, role FROM users WHERE id = ?', [req.params.id],
        (err, row) => res.json({ success: !!row, ...row }));
});
app.get('/api/bot/servers/:userId', requireSuperAdmin, (req, res) => {
    db.all('SELECT id, name, game, server_status, ram_mb, expires_at FROM servers WHERE user_id = ? AND is_active = 1', [req.params.userId],
        (err, rows) => res.json({ success: true, servers: rows || [] }));
});
app.get('/api/bot/server-status/:userId/:serverId', requireSuperAdmin, (req, res) => {
    db.get('SELECT * FROM servers WHERE id = ? AND user_id = ?', [req.params.serverId, req.params.userId],
        (err, row) => res.json({ success: !!row, server: row || null }));
});
app.post('/api/bot/server-action/:userId/:serverId', requireSuperAdmin, async (req, res) => {
    const { action } = req.body;
    const server = await new Promise(r => db.get('SELECT * FROM servers WHERE id = ? AND user_id = ?', [req.params.serverId, req.params.userId], (e,row) => r(row)));
    if (!server?.pterodactyl_id) return res.json({ success: false, error: 'Serveur introuvable' });
    try {
        await callPterodactylAPI('/api/client/servers/' + server.pterodactyl_id + '/power', 'POST', { signal: action }, true);
        res.json({ success: true });
    } catch(e) { res.json({ success: false, error: e.message }); }
});
`;

console.log('[FLYHOST Bot] Démarrage...');
console.log('[FLYHOST Bot] API URL:', CONFIG.API_URL);
console.log('[FLYHOST Bot] Admins:', CONFIG.ADMIN_NUMBERS.length ? CONFIG.ADMIN_NUMBERS.join(', ') : 'Aucun configuré');
console.log('\n[FLYHOST Bot] NOTE: Pour les routes API bot, ajoutez BOT_ROUTES dans index.js\n');

startBot().catch(e => {
    console.error('[FLYHOST Bot] Erreur fatale:', e.message);
    process.exit(1);
});
