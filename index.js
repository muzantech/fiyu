// =============================================
// FLYHOST
// =============================================

import express from 'express';
import sqlite3 from 'sqlite3';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import nodemailer from 'nodemailer';
import cron from 'node-cron';
import fs from 'fs';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import compression from 'compression';
import { WebSocketServer, WebSocket as WsClient } from 'ws';
import multer from 'multer';
import AdmZip from 'adm-zip';
import httpProxy from 'http-proxy';
import { exec } from 'child_process';
import axios from 'axios';
import https from 'https';
import PDFDocument from 'pdfkit';
import { networkInterfaces } from 'os';
import net from 'net';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || process.env.SERVER_PORT || 5000;

// =============================================
// CONFIGURATIONS DE SÉCURITÉ
// =============================================

// Redirect HTTP → HTTPS en production (quand derrière Nginx/proxy SSL)
if (process.env.NODE_ENV === 'production') {
    app.use((req, res, next) => {
        if (req.headers['x-forwarded-proto'] === 'http') {
            return res.redirect(301, 'https://' + req.headers.host + req.originalUrl);
        }
        next();
    });
}

app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    frameguard: false,
    crossOriginResourcePolicy: false,
    hsts: process.env.NODE_ENV === 'production' ? { maxAge: 31536000, includeSubDomains: true } : false
}));
app.use(compression({
    filter: (req, res) => {
        // Ne pas compresser les SSE (text/event-stream) — la compression bufférise et casse le streaming
        if (req.path && req.path.includes('/sse')) return false;
        return compression.filter(req, res);
    }
}));
app.use(express.urlencoded({ extended: true }));
const ALLOWED_ORIGINS = [
    'https://flihost.site',
    'https://www.flihost.site',
    /\.flihost\.site$/,
    /\.replit\.dev$/,
    /\.riker\.replit\.dev$/
];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        const allowed = ALLOWED_ORIGINS.some(o =>
            typeof o === 'string' ? o === origin : o.test(origin)
        );
        callback(null, allowed);
    },
    credentials: true
}));
app.use(express.json({ limit: '2mb' }));

// =============================================
// PROXY SOUS-DOMAINES FLIHOST.SITE
// =============================================
const subdomainProxy = httpProxy.createProxyServer({ proxyTimeout: 15000, timeout: 15000 });
subdomainProxy.on('error', (err, req, res) => {
    console.error(`❌ Proxy sous-domaine erreur: ${err.message}`);
    // Invalider le cache Docker pour ce port → re-scan au prochain accès
    if (req._proxyPort) invalidateContainerIpCache(req._proxyPort);
    if (res && !res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<html><body style="font-family:sans-serif;text-align:center;padding:60px;background:#0f172a;color:#f1f5f9"><h2 style="color:#818cf8">🚀 Application en démarrage</h2><p style="color:#94a3b8;margin-top:12px">Votre application démarre, veuillez patienter quelques secondes...</p><script>setTimeout(()=>location.reload(),5000)</script></body></html>');
    }
});

const subdomainCache = new Map();
const SUBDOMAIN_CACHE_TTL = 60000;

const PTERODACTYL_HOST_IP = process.env.PTERODACTYL_HOST_IP || '173.212.226.118';

// ─── Découverte dynamique des containers Docker ───────────────────────────────
// FLYHOST tourne dans un container Docker Pterodactyl sur le réseau bridge
// (ex: 172.18.0.x). Les autres containers sont sur le même réseau.
// On ne peut pas utiliser 127.0.0.1 (= notre propre container) ni l'IP publique
// (iptables bloque l'accès depuis le bridge). La solution : scanner le sous-réseau
// Docker pour trouver l'IP directe du container cible.

// Cache des IPs Docker par port découvert dynamiquement
const containerIpCache = new Map(); // port → { ip, ts }
const CONTAINER_IP_TTL = 300000; // 5 minutes

// Retourne le préfixe du sous-réseau Docker de FLYHOST (ex: "172.18.0.")
function getDockerSubnetPrefix() {
    const nets = networkInterfaces();
    for (const addrs of Object.values(nets)) {
        for (const addr of addrs) {
            if (addr.family === 'IPv4' && !addr.internal) {
                // IPs Docker bridge typiques: 172.x.x.x ou 10.x.x.x (non publiques)
                if (addr.address.startsWith('172.') ||
                    (addr.address.startsWith('10.') && addr.address !== PTERODACTYL_HOST_IP)) {
                    const parts = addr.address.split('.');
                    return { prefix: `${parts[0]}.${parts[1]}.${parts[2]}.`, ownIp: addr.address };
                }
            }
        }
    }
    return null;
}

// Tester si un port TCP est joignable (timeout court pour scan rapide)
function testTcpPort(ip, port, timeoutMs = 200) {
    return new Promise(resolve => {
        const socket = new net.Socket();
        socket.setTimeout(timeoutMs);
        socket.on('connect', () => { socket.destroy(); resolve(true); });
        socket.on('error', () => { socket.destroy(); resolve(false); });
        socket.on('timeout', () => { socket.destroy(); resolve(false); });
        socket.connect(port, ip);
    });
}

// Découvrir l'IP du container qui écoute sur ce port dans le sous-réseau Docker
async function discoverContainerIp(port, forceRefresh = false) {
    const cached = containerIpCache.get(port);
    if (!forceRefresh && cached && (Date.now() - cached.ts < CONTAINER_IP_TTL)) {
        return cached.ip;
    }

    const subnet = getDockerSubnetPrefix();
    if (!subnet) {
        console.log(`⚠️  Impossible de détecter le sous-réseau Docker, fallback externe`);
        return null;
    }

    const { prefix, ownIp } = subnet;
    console.log(`🔍 Scan Docker ${prefix}1-50 pour port ${port} (notre IP: ${ownIp})`);

    // Scanner les 50 premières IPs par groupes de 10 en parallèle
    for (let i = 1; i <= 50; i += 10) {
        const batch = [];
        for (let j = i; j < i + 10 && j <= 50; j++) {
            const ip = `${prefix}${j}`;
            if (ip !== ownIp) batch.push(ip); // ignorer notre propre container
        }
        const results = await Promise.all(
            batch.map(ip => testTcpPort(ip, port, 200).then(ok => ok ? ip : null))
        );
        const found = results.find(Boolean);
        if (found) {
            containerIpCache.set(port, { ip: found, ts: Date.now() });
            console.log(`✅ Container trouvé: ${found}:${port}`);
            return found;
        }
    }

    console.log(`❌ Aucun container trouvé sur ${prefix}x:${port}`);
    return null;
}

// Invalider le cache d'un port (ex: après un proxy error → container redémarré)
function invalidateContainerIpCache(port) {
    containerIpCache.delete(port);
}

function isSameHost(alloc_ip) {
    return !alloc_ip
        || alloc_ip === '0.0.0.0'
        || alloc_ip === '127.0.0.1'
        || alloc_ip === PTERODACTYL_HOST_IP;
}

// resolveProxyTarget reste sync pour les serveurs externes
// Pour les serveurs sur le même hôte, utiliser resolveProxyTargetAsync
function resolveProxyTarget(row) {
    if (!row || !row.alloc_port) return null;
    if (isSameHost(row.alloc_ip)) return null; // → utiliser resolveProxyTargetAsync
    return { port: row.alloc_port, ip: row.alloc_ip };
}

// Résolution async pour les serveurs sur le même hôte (Docker scan)
async function resolveProxyTargetAsync(row) {
    if (!row || !row.alloc_port) return null;
    if (!isSameHost(row.alloc_ip)) return { port: row.alloc_port, ip: row.alloc_ip };
    const ip = await discoverContainerIp(row.alloc_port);
    if (!ip) return null;
    return { port: row.alloc_port, ip };
}

app.use(async (req, res, next) => {
    const host = (req.headers.host || '').split(':')[0].toLowerCase();
    const PROD_DOMAIN = 'flihost.site';

    let cacheKey, queryPromise;

    if (host.endsWith(`.${PROD_DOMAIN}`)) {
        const subdomain = host.slice(0, -(PROD_DOMAIN.length + 1));
        if (!subdomain || subdomain === 'www' || subdomain.includes('.')) return next();
        cacheKey = subdomain;
        queryPromise = () => new Promise(resolve =>
            db.get(
                `SELECT alloc_port, alloc_ip FROM servers WHERE (server_identifier = ? OR custom_subdomain = ?) AND is_active = 1 LIMIT 1`,
                [subdomain, subdomain], (e, r) => resolve(r)
            )
        );
    } else if (host !== 'flihost.site' && host !== 'www.flihost.site' && !host.includes('replit')) {
        cacheKey = 'domain:' + host;
        queryPromise = () => new Promise(resolve =>
            db.get(
                `SELECT alloc_port, alloc_ip FROM servers WHERE custom_domain = ? AND is_active = 1 LIMIT 1`,
                [host], (e, r) => resolve(r)
            )
        );
    } else {
        return next();
    }

    const cached = subdomainCache.get(cacheKey);
    let target = cached && (Date.now() - cached.ts < SUBDOMAIN_CACHE_TTL) ? cached : null;

    if (!target) {
        const row = await queryPromise();
        target = await resolveProxyTargetAsync(row);
        if (!target) return next();
        subdomainCache.set(cacheKey, { ...target, ts: Date.now() });
    }

    req.url = req.url || '/';
    req._proxyPort = target.port; // pour invalidation cache sur erreur
    subdomainProxy.web(req, res, { target: `http://${target.ip}:${target.port}`, changeOrigin: true });
});

// No-cache headers pour l'environnement Replit
if (process.env.NODE_ENV !== 'production') {
    app.use((req, res, next) => {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        next();
    });
}

app.use(express.static(__dirname));

// Rate limiting pour l'API
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        error: 'Trop de requêtes, veuillez réessayer plus tard',
        code: 'RATE_LIMIT_EXCEEDED'
    }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        error: 'Trop de tentatives, veuillez réessayer dans 15 minutes',
        code: 'RATE_LIMIT_EXCEEDED'
    }
});

app.use('/api/', apiLimiter);
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);

// =============================================
// CONFIGURATION CHAT
// =============================================

const CHAT_CONFIG = {
    upload_dir: path.join(__dirname, 'uploads', 'chat'),
    max_file_size: 50 * 1024 * 1024, // 50 MB
    allowed_image_types: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
    allowed_video_types: ['video/mp4', 'video/webm', 'video/ogg'],
    allowed_audio_types: ['audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/webm'],
    message_history_limit: 100,
    media_history_limit: 50
};

// Créer le dossier uploads s'il n'existe pas
if (!fs.existsSync(CHAT_CONFIG.upload_dir)) {
    fs.mkdirSync(CHAT_CONFIG.upload_dir, { recursive: true });
}

// =============================================
// MULTER POUR CHAT
// =============================================

const chatUpload = multer({
    dest: CHAT_CONFIG.upload_dir,
    limits: { fileSize: CHAT_CONFIG.max_file_size },
    fileFilter: (req, file, cb) => {
        const allowedTypes = [
            ...CHAT_CONFIG.allowed_image_types,
            ...CHAT_CONFIG.allowed_video_types,
            ...CHAT_CONFIG.allowed_audio_types
        ];
        
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Type de fichier non supporté. Utilisez images, vidéos ou audio.'), false);
        }
    }
});

// =============================================
// CONFIGURATION INTERNE
// =============================================

const PTERODACTYL_CONFIG = {
    url: process.env.PTERODACTYL_URL || 'https://panel.lionelmelo.qzz.io',
    applicationApiKey: process.env.PTERODACTYL_APPLICATION_KEY || 'ptla_r2kzut51T81Mgw9amMrnsplRlBN1AgR6PKFbxodPMVD',
    clientApiKey: process.env.PTERODACTYL_CLIENT_KEY || 'ptlc_mPDwkobcQuClCH0zqnmuzH5Lon43849RaTOlxcFErzm'
};

const CLOUDFLARE_CONFIG = {
    token: process.env.CF_TOKEN || 'm7VWlDT3z3-U72bo3iG_sHNX4MvdnJ2zSnnwTZuY',
    zoneId: process.env.CF_ZONE_ID || 'a70d7c505e26b0d0397cacf7958d7272',
    domain: 'flihost.site',
    serverIp: process.env.SERVER_IP || '173.212.226.118'
};

async function syncAllocPortsFromPterodactyl() {
    try {
        const servers = await new Promise(resolve =>
            db.all(`SELECT id, pterodactyl_id, server_identifier, alloc_port FROM servers WHERE is_active = 1`, [], (e, r) => resolve(r || []))
        );
        let updated = 0;
        for (const srv of servers) {
            try {
                const data = await callPterodactylAPI(`/api/application/servers/${srv.pterodactyl_id}?include=allocations`);
                const allocData = data.attributes?.relationships?.allocations?.data || [];
                const primary = allocData.find(a => a.attributes?.is_default) || allocData[0];
                if (!primary) continue;
                const newPort = primary.attributes.port;
                const newIp = primary.attributes.ip || '0.0.0.0';
                if (newPort && newPort !== srv.alloc_port) {
                    await new Promise(resolve =>
                        db.run(`UPDATE servers SET alloc_port = ?, alloc_ip = ? WHERE id = ?`,
                            [newPort, newIp, srv.id], resolve)
                    );
                    subdomainCache.clear();
                    console.log(`🔄 Sync port serveur ${srv.server_identifier}: ${srv.alloc_port} → ${newPort}`);
                    updated++;
                }
            } catch { /* serveur inaccessible, on ignore */ }
        }
        if (updated > 0) console.log(`✅ ${updated} port(s) serveur synchronisé(s) depuis Pterodactyl`);
        else console.log(`✅ Ports serveurs déjà à jour`);
    } catch (err) {
        console.warn('⚠️ Erreur sync ports Pterodactyl:', err.message);
    }
}

async function ensureWildcardDNS() {
    try {
        const { token, zoneId, domain, serverIp } = CLOUDFLARE_CONFIG;
        const listRes = await fetch(
            `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?type=A&name=*.${domain}`,
            { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } }
        );
        const listData = await listRes.json();
        if (listData.result && listData.result.length > 0) {
            console.log(`✅ DNS wildcard *.${domain} déjà configuré`);
            return;
        }
        const createRes = await fetch(
            `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`,
            {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({ type: 'A', name: `*.${domain}`, content: serverIp, ttl: 1, proxied: true })
            }
        );
        const createData = await createRes.json();
        if (createData.success) {
            console.log(`✅ DNS wildcard *.${domain} → ${serverIp} créé`);
        } else {
            console.warn(`⚠️ Impossible de créer le DNS wildcard:`, JSON.stringify(createData.errors));
        }
    } catch (err) {
        console.warn('⚠️ Erreur vérification DNS Cloudflare:', err.message);
    }
}

const EMAIL_CONFIG = {
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT) || 587,
    secure: false,
    auth: {
        user: process.env.SMTP_USER || 'flyhost2.0@gmail.com',
        pass: process.env.SMTP_PASS || 'cxaj vhfv iqkp iucd'
    },
    from: process.env.SMTP_FROM || 'FLYHOST <flyhost2.0@gmail.com>'
};

const PLANS_CONFIG = {
    'free': { 
        memory: 256, 
        disk: 5120, 
        cpu: 50, 
        swap: 0, 
        io: 500, 
        price: 0, 
        duration: 1,
        api_calls_per_day: 300,
        max_servers: 1
    },
    '1gb': { 
        memory: 1024, 
        disk: 10240, 
        cpu: 100, 
        swap: 0, 
        io: 500, 
        price: 50, 
        duration: 14,
        api_calls_per_day: 200,
        max_servers: 3
    },
    '2gb': { 
        memory: 2048, 
        disk: 20480, 
        cpu: 200, 
        swap: 0, 
        io: 500, 
        price: 80, 
        duration: 14,
        api_calls_per_day: 500,
        max_servers: 5
    },
    '4gb': { 
        memory: 4096, 
        disk: 40960, 
        cpu: 400, 
        swap: 0, 
        io: 500, 
        price: 130, 
        duration: 14,
        api_calls_per_day: 1000,
        max_servers: 10
    },
    '8gb': { 
        memory: 8192, 
        disk: 81920, 
        cpu: 800, 
        swap: 0, 
        io: 500, 
        price: 170, 
        duration: 14,
        api_calls_per_day: 2000,
        max_servers: 15
    },
    'unlimited': { 
        memory: 0, 
        disk: 0, 
        cpu: 0, 
        swap: 0, 
        io: 500, 
        price: 200, 
        duration: 14,
        api_calls_per_day: 5000,
        max_servers: 999
    },
    'admin': { 
        memory: 20000, 
        disk: 20000, 
        cpu: 2000, 
        swap: 0, 
        io: 500, 
        price: 800, 
        duration: 14,
        api_calls_per_day: 10000,
        max_servers: 999
    }
};

const PLAN_COINS_PRICES = {
    'free': 0,
    '1gb': 50,
    '2gb': 80,
    '4gb': 130,
    '8gb': 170,
    'unlimited': 200,
    'admin': 800
};

// JWT_SECRET persistant — ne change plus au redémarrage
const _SECRET_FILE = path.join(__dirname, '.jwt_secret');
let _persistentJwtSecret;
try {
    _persistentJwtSecret = fs.readFileSync(_SECRET_FILE, 'utf8').trim();
    if (!_persistentJwtSecret || _persistentJwtSecret.length < 32) throw new Error('trop court');
} catch (e) {
    _persistentJwtSecret = crypto.randomBytes(64).toString('hex');
    fs.writeFileSync(_SECRET_FILE, _persistentJwtSecret, { mode: 0o600 });
}

const WEB_CONFIG = {
    JWT_SECRET: process.env.JWT_SECRET || _persistentJwtSecret,
    SITE_URL: process.env.SITE_URL || 'https://flihost.site',
    INTERNAL_API_KEY: process.env.INTERNAL_API_KEY || 'FLYHOST_INTERNAL_' + crypto.randomBytes(32).toString('hex'),
    INTERNAL_PASSWORD: 'JESUS'
};

// =============================================
// TECH ENVIRONMENTS — Multi-technologie
// =============================================
const TECH_ENVIRONMENTS = {
    nodejs: {
        name: 'Node.js',
        icon: 'fab fa-node-js',
        color: '#68a063',
        egg: parseInt(process.env.EGG_NODEJS) || 15,
        docker_image: process.env.DOCKER_NODEJS || 'ghcr.io/parkervcp/yolks:nodejs_24',
        startup: 'if [ -f /home/container/package.json ]; then /usr/local/bin/npm install --prefer-offline --no-audit --no-fund --maxsockets 2 2>&1 || true; fi; /usr/local/bin/node "/home/container/${MAIN_FILE}"',
        env: { MAIN_FILE: 'index.js', NODE_ARGS: '', NODE_PACKAGES: '', UNNODE_PACKAGES: '', USER_UPLOAD: '0', AUTO_UPDATE: '0' },
        detect_files: ['package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
        detect_extensions: ['.js', '.ts', '.mjs', '.cjs'],
        frameworks: {
            nextjs:   { detect: ['next.config.js','next.config.mjs','next.config.ts'], build: 'npm install && npm run build', start: 'npm start', label: 'Next.js' },
            react:    { detect: ['src/App.jsx','src/App.tsx','src/App.js','vite.config.js','vite.config.ts'], build: 'npm install && npm run build', start: 'npx serve -s dist -p ${SERVER_PORT}', label: 'React' },
            vue:      { detect: ['src/App.vue','vue.config.js'], build: 'npm install && npm run build', start: 'npx serve -s dist -p ${SERVER_PORT}', label: 'Vue.js' },
            express:  { detect: ['app.js','server.js','index.js'], build: 'npm install', start: 'npm start', label: 'Express' },
            discord:  { detect: [], build: 'npm install', start: 'npm start', label: 'Bot Discord' },
        },
        default_start: 'npm start',
        default_build: 'npm install',
        entry_candidates: ['index.js','bot.js','app.js','server.js','main.js','start.js']
    },
    python: {
        name: 'Python',
        icon: 'fab fa-python',
        color: '#3572a5',
        egg: parseInt(process.env.EGG_PYTHON) || 18,
        docker_image: process.env.DOCKER_PYTHON || 'ghcr.io/parkervcp/yolks:python_3.11',
        startup: 'if [[ ! -z "{{PY_PACKAGES}}" ]]; then pip install -U --prefix .local {{PY_PACKAGES}}; fi; if [[ -f /home/container/${REQUIREMENTS_FILE} ]]; then pip install -U --prefix .local -r ${REQUIREMENTS_FILE}; fi; /usr/local/bin/python /home/container/{{PY_FILE}}',
        env: { PY_FILE: 'main.py', REQUIREMENTS_FILE: 'requirements.txt', PY_PACKAGES: '', USER_UPLOAD: '0', AUTO_UPDATE: '0' },
        detect_files: ['requirements.txt','Pipfile','pyproject.toml','setup.py','setup.cfg'],
        detect_extensions: ['.py'],
        frameworks: {
            django:  { detect: ['manage.py','settings.py'], build: 'pip install -r requirements.txt', start: 'python manage.py runserver 0.0.0.0:${SERVER_PORT}', label: 'Django' },
            flask:   { detect: ['app.py','wsgi.py'], build: 'pip install -r requirements.txt', start: 'python app.py', label: 'Flask' },
            fastapi: { detect: ['main.py'], build: 'pip install -r requirements.txt', start: 'uvicorn main:app --host 0.0.0.0 --port ${SERVER_PORT}', label: 'FastAPI' },
        },
        default_start: 'python main.py',
        default_build: 'pip install -r requirements.txt',
        entry_candidates: ['main.py','app.py','bot.py','server.py','run.py','index.py']
    },
    php: {
        name: 'PHP',
        icon: 'fab fa-php',
        color: '#777bb4',
        egg: parseInt(process.env.EGG_PHP) || 19,
        docker_image: process.env.DOCKER_PHP || 'php:8.2-cli',
        startup: 'if [ -f /home/container/composer.json ]; then composer install --no-interaction --no-dev --optimize-autoloader 2>&1 || true; fi; php -S 0.0.0.0:{{SERVER_PORT}} -t /home/container/{{DOCUMENT_ROOT}}',
        env: { DOCUMENT_ROOT: '.', USER_UPLOAD: '0' },
        detect_files: ['composer.json','composer.lock','index.php','artisan'],
        detect_extensions: ['.php'],
        frameworks: {
            laravel: { detect: ['artisan','app/Http/Controllers'], build: 'composer install', start: 'php artisan serve --host=0.0.0.0 --port=${SERVER_PORT}', label: 'Laravel' },
            symfony: { detect: ['symfony.lock','config/packages'], build: 'composer install', start: 'php -S 0.0.0.0:${SERVER_PORT} -t public', label: 'Symfony' },
            wordpress: { detect: ['wp-config.php','wp-login.php'], build: '', start: 'php -S 0.0.0.0:${SERVER_PORT}', label: 'WordPress' },
        },
        default_start: 'php -S 0.0.0.0:${SERVER_PORT}',
        default_build: 'composer install',
        entry_candidates: ['index.php','app.php','public/index.php']
    },
    java: {
        name: 'Java',
        icon: 'fab fa-java',
        color: '#b07219',
        egg: parseInt(process.env.EGG_JAVA) || 16,
        docker_image: process.env.DOCKER_JAVA || 'ghcr.io/parkervcp/yolks:java_21',
        startup: 'java -Dterminal.jline=false -Dterminal.ansi=true -jar {{JARFILE}}',
        env: { JARFILE: 'app.jar' },
        detect_files: ['pom.xml','build.gradle','gradlew','mvnw'],
        detect_extensions: ['.java','.jar'],
        frameworks: {
            springboot: { detect: ['src/main/java','application.properties','application.yml'], build: './mvnw package -DskipTests', start: 'java -jar target/*.jar', label: 'Spring Boot' },
            maven:      { detect: ['pom.xml'], build: './mvnw package -DskipTests', start: 'java -jar target/*.jar', label: 'Maven' },
            gradle:     { detect: ['build.gradle','gradlew'], build: './gradlew build', start: 'java -jar build/libs/*.jar', label: 'Gradle' },
        },
        default_start: 'java -jar app.jar',
        default_build: './mvnw package -DskipTests',
        entry_candidates: ['app.jar','target/app.jar']
    },
    static: {
        name: 'Site Statique',
        icon: 'fab fa-html5',
        color: '#e34c26',
        egg: parseInt(process.env.EGG_STATIC) || 15,
        docker_image: process.env.DOCKER_STATIC || 'ghcr.io/parkervcp/yolks:nodejs_24',
        startup: 'npx --yes serve /home/container -p ${SERVER_PORT} -s',
        env: { NODE_PACKAGES: '', UNNODE_PACKAGES: '', USER_UPLOAD: '0', AUTO_UPDATE: '0', MAIN_FILE: 'index.html', NODE_ARGS: '' },
        detect_files: ['index.html'],
        detect_extensions: ['.html','.htm'],
        frameworks: {},
        default_start: 'npx serve . -p ${SERVER_PORT}',
        default_build: '',
        entry_candidates: ['index.html','index.htm']
    }
};

// Détecter la technologie d'un projet depuis la liste de ses fichiers
function detectTechnologyFromFiles(fileList) {
    const files = fileList.map(f => f.toLowerCase().replace(/\\/g, '/'));
    const basename = f => f.split('/').pop();
    const fileNames = files.map(basename);

    let scores = { nodejs: 0, python: 0, php: 0, java: 0, static: 0 };
    let detectedFramework = null;
    let detectedTech = 'nodejs';
    let confidence = 'low';

    // Score par fichiers détecteurs
    for (const [tech, cfg] of Object.entries(TECH_ENVIRONMENTS)) {
        for (const df of cfg.detect_files) {
            if (fileNames.includes(df.toLowerCase()) || files.some(f => f.endsWith('/' + df.toLowerCase()))) {
                scores[tech] += 10;
            }
        }
        // Score par extensions
        const extCount = files.filter(f => cfg.detect_extensions.some(e => f.endsWith(e))).length;
        scores[tech] += Math.min(extCount, 5);
    }

    // Bonus spécifiques
    if (fileNames.includes('package.json')) scores.nodejs += 15;
    if (fileNames.includes('requirements.txt') || fileNames.includes('pipfile')) scores.python += 15;
    if (fileNames.includes('composer.json') || fileNames.includes('artisan')) scores.php += 15;
    if (fileNames.includes('pom.xml') || fileNames.includes('build.gradle')) scores.java += 15;
    if (fileNames.includes('index.html') && scores.nodejs === 0 && scores.python === 0) scores.static += 10;

    // Bonus Python pour projets hybrides (Python backend + Node.js frontend)
    // Si .py files existent dans backend/, src/ ou à la racine → Python est le vrai backend
    const hasPyFiles = files.some(f => f.endsWith('.py'));
    const hasBackendPy = files.some(f => /\/(backend|api|server)\/.*\.py$/.test(f) || /^(backend|api)\/.*\.py$/.test(f));
    if (hasBackendPy) scores.python += 20; // Forte priorité si backend Python explicite
    else if (hasPyFiles) scores.python += 5;

    // Choisir la tech avec le meilleur score
    const sorted = Object.entries(scores).sort((a, b) => b[1] - a[1]);
    detectedTech = sorted[0][0];
    const topScore = sorted[0][1];
    confidence = topScore >= 20 ? 'high' : topScore >= 10 ? 'medium' : 'low';

    // Si seulement HTML/CSS → static
    if (scores.static > 0 && scores.nodejs === 0 && scores.python === 0 && scores.php === 0 && scores.java === 0) {
        detectedTech = 'static';
        confidence = 'high';
    }

    // Détecter le framework
    const techCfg = TECH_ENVIRONMENTS[detectedTech];
    for (const [fwKey, fwCfg] of Object.entries(techCfg.frameworks || {})) {
        const matched = fwCfg.detect.some(d => {
            const dl = d.toLowerCase();
            return fileNames.includes(dl) || files.some(f => f.includes(dl));
        });
        if (matched) { detectedFramework = fwKey; break; }
    }

    // Déduire start/build selon le framework ou la tech
    let suggestedStart = '';
    let suggestedBuild = '';

    if (detectedFramework && techCfg.frameworks[detectedFramework]) {
        const fw = techCfg.frameworks[detectedFramework];
        suggestedStart = fw.start;
        suggestedBuild = fw.build;
    } else {
        suggestedBuild = techCfg.default_build;
        // Chercher fichier d'entrée commun (y compris dans backend/)
        if (detectedTech === 'nodejs') {
            const entry = techCfg.entry_candidates.find(c => fileNames.includes(c));
            suggestedStart = entry ? `node ${entry}` : techCfg.default_start;
        } else if (detectedTech === 'python') {
            // Chercher dans backend/, api/, server/ puis à la racine
            const extCandidates = [
                ...['backend','api','server'].flatMap(d => ['server.py','app.py','main.py','run.py'].map(f => `${d}/${f}`)),
                ...techCfg.entry_candidates
            ];
            const entry = extCandidates.find(c => files.some(f => f.endsWith(c.toLowerCase())));
            suggestedStart = entry ? `python ${entry}` : techCfg.default_start;
        } else {
            suggestedStart = techCfg.default_start;
        }
    }

    return {
        tech: detectedTech,
        framework: detectedFramework,
        frameworkLabel: detectedFramework ? techCfg.frameworks[detectedFramework]?.label : null,
        confidence,
        scores,
        suggestedStart,
        suggestedBuild,
        egg: techCfg.egg,
        docker_image: techCfg.docker_image,
        startup: techCfg.startup,
        env: techCfg.env,
        techName: techCfg.name
    };
}

// Construire le startup command Pterodactyl adapté à la technologie
function buildStartupCommand(tech, startCmd, buildCmd) {
    const cfg = TECH_ENVIRONMENTS[tech] || TECH_ENVIRONMENTS.nodejs;
    // npm install avec limite mémoire pour éviter OOM dans des containers limités
    const npmInstall = `if [ -f /home/container/package.json ]; then NODE_OPTIONS="--max-old-space-size=512" /usr/local/bin/npm install --prefer-offline --no-audit --no-fund --maxsockets 1 2>&1 || true; fi`;
    // Exécution du script de build si présent (projets Replit, monorepos, etc.)
    const buildSh = `if [ -f /home/container/build.sh ]; then bash /home/container/build.sh 2>&1 || true; fi`;
    // Auto-détection du point d'entrée Node.js (gère les structures frontend/server, src/, dist/, etc.)
    const autoDetectEntry = `_E=""; for _f in index.js server/index.js src/index.js app.js server/app.js src/app.js main.js dist/index.js build/index.js; do if [ -f "/home/container/$_f" ]; then _E=$_f; break; fi; done; if [ -z "$_E" ] && [ -f /home/container/package.json ]; then _PMAIN=$(node -e "try{const p=JSON.parse(require('fs').readFileSync('package.json','utf8'));console.log(p.main||'')}catch(e){}" 2>/dev/null); if [ -n "$_PMAIN" ] && [ -f "/home/container/$_PMAIN" ]; then _E=$_PMAIN; fi; fi; if [ -z "$_E" ]; then echo "Aucun point d entree trouve (index.js, server/index.js, app.js...)"; exit 1; fi; echo "Lancement: $_E"; exec /usr/local/bin/node "/home/container/$_E"`;

    if (tech === 'nodejs') {
        const cmd = (startCmd || '').trim();

        // npm start / npm run xxx → exécuter npm directement
        if (/^npm\s+(start|run\b)/.test(cmd)) {
            const npmCmd = cmd.replace(/^npm\s+/, '');
            return {
                startup: `${npmInstall}; ${buildSh}; /usr/local/bin/npm ${npmCmd}`,
                env: { ...cfg.env, MAIN_FILE: 'index.js', NODE_ARGS: '' }
            };
        }

        // yarn start / yarn run xxx
        if (/^yarn\b/.test(cmd)) {
            return {
                startup: `${npmInstall}; ${buildSh}; yarn ${cmd.replace(/^yarn\s*/, '')}`,
                env: { ...cfg.env, MAIN_FILE: 'index.js', NODE_ARGS: '' }
            };
        }

        // npx commands (serve, etc.) — run directly, replace hardcoded 8080 with ${SERVER_PORT}
        if (/^npx\b/.test(cmd)) {
            const npxCmd = cmd.replace(/\b8080\b/g, '${SERVER_PORT}');
            return {
                startup: `${npmInstall}; ${buildSh}; ${npxCmd}`,
                env: { ...cfg.env, MAIN_FILE: 'index.js', NODE_ARGS: '' }
            };
        }

        // node [flags] file.js — utilisateur a spécifié un fichier, mais fallback si absent
        if (/^(node|ts-node|nodemon)\b/.test(cmd)) {
            const tokens = cmd.replace(/^(node|ts-node|nodemon)\s+/, '').trim().split(/\s+/);
            const nodeFlags = tokens.filter(p => p.startsWith('-')).join(' ');
            const mainFile = tokens.find(p => !p.startsWith('-') && p.length > 0) || 'index.js';
            const flagsPart = nodeFlags ? nodeFlags + ' ' : '';
            // Script runtime : tente le fichier spécifié, sinon auto-détecte
            const smartEntry = `_E="/home/container/${mainFile}"; if [ ! -f "$_E" ]; then for _f in index.js server/index.js src/index.js app.js server/app.js src/app.js main.js dist/index.js build/index.js; do if [ -f "/home/container/$_f" ]; then _E="/home/container/$_f"; break; fi; done; fi; echo "Lancement: $_E"; exec /usr/local/bin/node ${flagsPart}"$_E"`;
            return {
                startup: `${npmInstall}; ${buildSh}; ${smartEntry}`,
                env: { ...cfg.env, MAIN_FILE: mainFile, NODE_ARGS: nodeFlags }
            };
        }

        // Aucune commande explicite → auto-détection du point d'entrée
        return {
            startup: `${npmInstall}; ${buildSh}; ${autoDetectEntry}`,
            env: { ...cfg.env, MAIN_FILE: 'index.js', NODE_ARGS: '' }
        };
    } else if (tech === 'python') {
        const rawFile = (startCmd || '').replace(/^(python3?|python\s+)/i, '').trim().split(/\s+/)[0];
        // Détection projet hybride : Python backend + Node.js frontend (package.json présent)
        // Dans ce cas on utilise l'image Node.js (Ubuntu) qui a Python3 préinstallé
        // L'image Python pure n'a pas npm → impossible de builder le frontend React/Vue
        const isHybrid = !rawFile || rawFile === 'server.py'; // s'il y a un doute on force hybride
        const nodejsCfg = TECH_ENVIRONMENTS.nodejs;
        // Étape 1 : build frontend si package.json présent (Node.js image a npm)
        const pyNpmBuild = `if [ -f /home/container/package.json ]; then NODE_OPTIONS="--max-old-space-size=512" /usr/local/bin/npm install --prefer-offline --no-audit --no-fund --maxsockets 1 2>&1 || true; fi; if [ -f /home/container/build.sh ]; then bash /home/container/build.sh 2>&1 || true; fi`;
        // Étape 2 : pip install depuis requirements.txt (cherche dans plusieurs endroits)
        // Utilise python3 -m pip car pip3/pip ne sont pas dans le PATH de l'image Node.js (yolks:nodejs_24)
        const pyPipInstall = `for _req in /home/container/requirements.txt /home/container/backend/requirements.txt /home/container/api/requirements.txt; do if [ -f "$_req" ]; then python3 -m ensurepip --upgrade 2>/dev/null || true; python3 -m pip install -r "$_req" 2>&1 || true; fi; done`;
        // Étape 3 : auto-détection de l'entrée Python si non spécifiée ou fichier absent
        const pyEntry = rawFile
            ? `_PE="/home/container/${rawFile}"; if [ ! -f "$_PE" ]; then for _pf in backend/server.py backend/app.py backend/main.py api/server.py api/app.py server.py app.py main.py run.py; do if [ -f "/home/container/$_pf" ]; then _PE="/home/container/$_pf"; break; fi; done; fi`
            : `_PE=""; for _pf in backend/server.py backend/app.py backend/main.py api/server.py api/app.py server.py app.py main.py run.py; do if [ -f "/home/container/$_pf" ]; then _PE="/home/container/$_pf"; break; fi; done`;
        const pyRun = `if [ -z "$_PE" ] || [ ! -f "$_PE" ]; then echo "Aucun fichier Python trouve"; exit 1; fi; echo "Lancement Python: $_PE"; exec python3 "$_PE" 2>/dev/null || exec python "$_PE"`;
        return {
            startup: `${pyNpmBuild}; ${pyPipInstall}; ${pyEntry}; ${pyRun}`,
            // Projets hybrides Python+Node → image Node.js (Ubuntu, a Python3 préinstallé + npm)
            docker_image: nodejsCfg.docker_image,
            egg: nodejsCfg.egg,
            env: { ...cfg.env, PY_FILE: rawFile || 'server.py', REQUIREMENTS_FILE: 'requirements.txt', PY_PACKAGES: '', USER_UPLOAD: '0', AUTO_UPDATE: '0', MAIN_FILE: rawFile || 'server.py', NODE_ARGS: '' }
        };
    } else if (tech === 'php') {
        const docRoot = startCmd?.includes('public') ? 'public' : '.';
        return {
            startup: cfg.startup,
            env: { ...cfg.env, DOCUMENT_ROOT: docRoot, USER_UPLOAD: '0' }
        };
    } else if (tech === 'java') {
        const jarFile = (startCmd || 'java -jar app.jar').replace(/^java\s+(-[^\s]+\s+)*-jar\s+/i, '').trim().split(/\s+/)[0] || 'app.jar';
        return {
            startup: cfg.startup,
            env: { ...cfg.env, JARFILE: jarFile }
        };
    } else if (tech === 'static') {
        return {
            startup: 'npx --yes serve /home/container -p ${SERVER_PORT} -s',
            env: { ...cfg.env }
        };
    }
    return { startup: cfg.startup, env: cfg.env };
}

// Analyser les erreurs de déploiement et retourner des recommandations
function analyzeDeployError(errorMsg, tech) {
    const e = (errorMsg || '').toLowerCase();
    const raw = (errorMsg || '');

    // ── Variables d'environnement manquantes ──────────────────────────────
    const keyErrorMatch = raw.match(/KeyError:\s*['"]?([A-Z_][A-Z0-9_]*)['"]?/);
    if (keyErrorMatch) {
        const varName = keyErrorMatch[1];
        return {
            icon: '🔑',
            reason: `Variable d'environnement manquante : ${varName}`,
            suggestion: `Votre application attend la variable "${varName}". Allez dans les fichiers du serveur → backend/.env (ou .env) et ajoutez :\n${varName}=votre_valeur`,
            alt_tech: null,
            severity: 'error'
        };
    }
    const envMatch = raw.match(/(?:environ|getenv|env)\[['"]([A-Z_][A-Z0-9_]*)['"]\]/);
    if (envMatch) {
        return {
            icon: '🔑',
            reason: `Variable d'environnement manquante : ${envMatch[1]}`,
            suggestion: `Ajoutez "${envMatch[1]}=votre_valeur" dans le fichier .env de votre projet.`,
            alt_tech: null,
            severity: 'error'
        };
    }

    // ── Modules / packages manquants ─────────────────────────────────────
    const pyModuleMatch = raw.match(/(?:ModuleNotFoundError|ImportError):\s*No module named ['"]([^'"]+)['"]/);
    if (pyModuleMatch) {
        return {
            icon: '📦',
            reason: `Package Python manquant : ${pyModuleMatch[1]}`,
            suggestion: `Ajoutez "${pyModuleMatch[1]}" dans votre fichier requirements.txt puis redéployez.`,
            alt_tech: null,
            severity: 'error'
        };
    }
    if (e.includes('modulenotfounderror') || e.includes('no module named')) {
        return {
            icon: '📦',
            reason: 'Package Python manquant',
            suggestion: 'Un package importé dans votre code est absent de requirements.txt. Vérifiez tous vos imports et ajoutez-les.',
            alt_tech: null,
            severity: 'error'
        };
    }
    const nodeModuleMatch = raw.match(/Cannot find module ['"]([^'"]+)['"]/);
    if (nodeModuleMatch) {
        return {
            icon: '📦',
            reason: `Package Node.js manquant : ${nodeModuleMatch[1]}`,
            suggestion: `Ajoutez "${nodeModuleMatch[1]}" dans package.json → dependencies puis redéployez.`,
            alt_tech: null,
            severity: 'error'
        };
    }
    if (e.includes('cannot find module') || e.includes('module not found')) {
        return {
            icon: '📦',
            reason: 'Package Node.js introuvable',
            suggestion: 'Un module requis est manquant dans package.json. Vérifiez vos require/import et ajoutez les dépendances.',
            alt_tech: null,
            severity: 'error'
        };
    }

    // ── Fichier de démarrage introuvable ──────────────────────────────────
    if (e.includes('enoent') || e.includes('no such file or directory')) {
        const fileMatch = raw.match(/(?:ENOENT|No such file).*?['"]([^'"]+)['"]/);
        const fname = fileMatch ? fileMatch[1] : 'fichier de démarrage';
        return {
            icon: '📁',
            reason: `Fichier introuvable : ${fname}`,
            suggestion: 'Le fichier de démarrage de votre application est absent ou mal configuré. Vérifiez que le fichier principal existe dans votre dépôt.',
            alt_tech: null,
            severity: 'error'
        };
    }

    // ── Erreurs de syntaxe ────────────────────────────────────────────────
    if (e.includes('syntaxerror') || (e.includes('syntax error') && !e.includes('postgresql'))) {
        const lineMatch = raw.match(/line (\d+)/i);
        const lineInfo = lineMatch ? ` (ligne ${lineMatch[1]})` : '';
        return {
            icon: '🐛',
            reason: `Erreur de syntaxe dans votre code${lineInfo}`,
            suggestion: 'Votre code contient une erreur de syntaxe. Vérifiez les accolades, parenthèses, indentations et virgules manquantes.',
            alt_tech: null,
            severity: 'error'
        };
    }
    if (e.includes('indentationerror')) {
        return {
            icon: '🐛',
            reason: 'Erreur d\'indentation Python',
            suggestion: 'Python exige une indentation cohérente. Utilisez soit des espaces (4), soit des tabulations, mais pas les deux.',
            alt_tech: null,
            severity: 'error'
        };
    }

    // ── Base de données inaccessible ──────────────────────────────────────
    if (e.includes('connection refused') && (e.includes('mongo') || e.includes('27017'))) {
        return {
            icon: '🍃',
            reason: 'Connexion MongoDB refusée',
            suggestion: 'La base MongoDB est inaccessible. Vérifiez que MONGO_URL est correct dans .env, que votre cluster Atlas est actif et que votre IP est autorisée (Network Access).',
            alt_tech: null,
            severity: 'error'
        };
    }
    if (e.includes('authentication failed') && e.includes('mongo')) {
        return {
            icon: '🍃',
            reason: 'Authentification MongoDB échouée',
            suggestion: 'Le nom d\'utilisateur ou mot de passe MongoDB est incorrect. Vérifiez MONGO_URL dans le fichier .env.',
            alt_tech: null,
            severity: 'error'
        };
    }
    if (e.includes('nxdomain') || e.includes('dns query name does not exist') || (e.includes('configurationerror') && e.includes('mongodb'))) {
        // Détecter si c'est encore la valeur d'exemple
        const isPlaceholder = raw.includes('cluster0.abc12') || raw.includes('monuser') || raw.includes('monmotdepasse') || raw.includes('example.com');
        return {
            icon: '🍃',
            reason: isPlaceholder ? 'MONGO_URL contient encore les valeurs d\'exemple' : 'Adresse MongoDB introuvable (DNS)',
            suggestion: isPlaceholder
                ? 'Vous avez gardé l\'exemple fourni. Vous devez utiliser une vraie URL MongoDB Atlas :\n1. Créez un compte gratuit sur mongodb.com/atlas\n2. Créez un cluster M0 (gratuit)\n3. Dans "Connect" → "Drivers", copiez l\'URL\n4. Remplacez le contenu de backend/.env par : MONGO_URL=mongodb+srv://USER:PASS@cluster0.XXXXX.mongodb.net/jarixfire'
                : 'Le domaine MongoDB dans MONGO_URL est introuvable. Vérifiez que l\'URL est correcte et que votre cluster Atlas existe.',
            alt_tech: null,
            severity: 'error'
        };
    }
    if ((e.includes('connection refused') || e.includes('econnrefused')) && (e.includes('postgres') || e.includes('5432') || e.includes('mysql') || e.includes('3306'))) {
        return {
            icon: '🗄️',
            reason: 'Connexion base de données refusée',
            suggestion: 'Impossible de joindre la base de données. Vérifiez DATABASE_URL / DB_HOST dans vos variables d\'environnement et que la base est bien démarrée.',
            alt_tech: null,
            severity: 'error'
        };
    }
    if (e.includes('connection refused') || e.includes('econnrefused')) {
        return {
            icon: '🔌',
            reason: 'Connexion réseau refusée',
            suggestion: 'Un service externe (base de données, API) est inaccessible. Vérifiez vos variables d\'environnement de connexion.',
            alt_tech: null,
            severity: 'error'
        };
    }

    // ── Mémoire insuffisante ──────────────────────────────────────────────
    if (e.includes('out of memory') || e.includes('oomkilled') || (e.includes('heap') && e.includes('allocation failed'))) {
        return {
            icon: '💾',
            reason: 'Mémoire RAM insuffisante',
            suggestion: 'Votre application dépasse la limite de RAM allouée. Passez à un plan supérieur ou optimisez l\'utilisation mémoire.',
            alt_tech: null,
            severity: 'error'
        };
    }

    // ── Port déjà utilisé ─────────────────────────────────────────────────
    if ((e.includes('port') && e.includes('already in use')) || e.includes('eaddrinuse')) {
        return {
            icon: '🔌',
            reason: 'Port réseau déjà utilisé',
            suggestion: 'Redémarrez le serveur depuis le panel Pterodactyl pour libérer le port, puis redéployez.',
            alt_tech: null,
            severity: 'warning'
        };
    }

    // ── Mauvais environnement tech ────────────────────────────────────────
    if ((e.includes('python') || e.includes('pip') || e.includes('.py')) && tech === 'nodejs') {
        return {
            icon: '🔄',
            reason: 'Mauvais environnement : projet Python sur Node.js',
            suggestion: 'Votre projet est Python mais le serveur est configuré en Node.js. Redéployez en sélectionnant l\'environnement Python.',
            alt_tech: 'python',
            severity: 'error'
        };
    }
    if ((e.includes('package.json') || e.includes('npm') || e.includes('node_modules')) && tech === 'python') {
        return {
            icon: '🔄',
            reason: 'Mauvais environnement : projet Node.js sur Python',
            suggestion: 'Votre projet est Node.js mais le serveur est configuré en Python. Redéployez en sélectionnant l\'environnement Node.js.',
            alt_tech: 'nodejs',
            severity: 'error'
        };
    }

    // ── Permissions ───────────────────────────────────────────────────────
    if (e.includes('permission denied') || e.includes('eacces')) {
        return {
            icon: '🔐',
            reason: 'Permission refusée',
            suggestion: 'Le fichier de démarrage n\'a pas les droits d\'exécution. Vérifiez les permissions de votre script.',
            alt_tech: null,
            severity: 'error'
        };
    }

    // ── Timeout / health check ────────────────────────────────────────────
    if (e.includes('timeout') || e.includes('health check') || e.includes('not responding')) {
        return {
            icon: '⏱️',
            reason: 'Serveur ne répond pas au démarrage',
            suggestion: 'Votre application met trop de temps à démarrer ou n\'écoute pas sur le bon port. Assurez-vous d\'écouter sur PORT ou SERVER_PORT.',
            alt_tech: null,
            severity: 'warning'
        };
    }

    // ── GitHub / dépôt inaccessible ───────────────────────────────────────
    if (e.includes('repository not found') || e.includes('git clone') || (e.includes('404') && e.includes('github'))) {
        return {
            icon: '🔗',
            reason: 'Dépôt GitHub inaccessible',
            suggestion: 'Le dépôt GitHub est introuvable ou privé. Vérifiez que vous êtes bien connecté à GitHub et que le dépôt existe.',
            alt_tech: null,
            severity: 'error'
        };
    }

    // ── Erreur générique avec contexte ────────────────────────────────────
    const errorLineMatch = raw.match(/(?:Error|Exception|Traceback)[^\n]*\n([^\n]+)/);
    if (errorLineMatch) {
        return {
            icon: '❌',
            reason: 'Erreur au démarrage de l\'application',
            suggestion: `Détail : "${errorLineMatch[1].trim()}". Consultez les logs complets pour identifier la ligne exacte.`,
            alt_tech: null,
            severity: 'error'
        };
    }

    return {
        icon: '❓',
        reason: 'Erreur de déploiement',
        suggestion: 'Consultez les logs complets pour identifier la cause. Assurez-vous que l\'environnement correspond à votre projet et que toutes les variables d\'environnement sont configurées.',
        alt_tech: null,
        severity: 'warning'
    };
}

const GITHUB_CONFIG = {
    client_id: process.env.GITHUB_CLIENT_ID || 'Ov23ligezX3ASiydVfvS',
    client_secret: process.env.GITHUB_CLIENT_SECRET || '',
    redirect_uri: process.env.GITHUB_REDIRECT_URI || 'https://flihost.site/api/github/callback',
    scope: 'repo read:user',
    webhook_secret: process.env.GITHUB_WEBHOOK_SECRET || crypto.randomBytes(32).toString('hex')
};

const MONEYFUSION_CONFIG = {
    api_url: process.env.MONEYFUSION_API_URL || 'https://www.pay.moneyfusion.net/FLYHOST_2_0/f79ff474520d482b/pay/',
    status_url: process.env.MONEYFUSION_STATUS_URL || 'https://www.pay.moneyfusion.net/paiementNotif/'
};

const ADMIN_GRADE_CONFIG = {
    price_coins: 800,
    price_money: 10,
    duration_days: 30,
    renewable: true
};

const CREDITS_CONFIG = {
    default_on_register: 0.00,
    bonus_email_verify: 0.50,
    minimum_purchase: 500,
    actions_cost: {
        create_server_free: 0,
        create_server_1gb: 2.00,
        create_server_2gb: 3.50,
        create_server_4gb: 6.00,
        create_server_8gb: 10.00,
        renew_server: 2.00,
        deploy: 0.50
    }
};

// =============================================
// NOUVELLE CONFIGURATION REVENDEUR
// =============================================

const RESELLER_CONFIG = {
    default_commission_rate: 15.00,      // 15% de commission par défaut
    min_withdrawal_amount: 5000,          // 5000 XOF minimum pour retrait
    withdrawal_processing_days: 2,
    bulk_discount_tiers: [
        { min_quantity: 5,  discount: 5  },
        { min_quantity: 10, discount: 10 },
        { min_quantity: 20, discount: 15 },
        { min_quantity: 50, discount: 20 }
    ],
    max_promo_codes_per_reseller: 50,
    affiliate_commission_lifetime: true   // Commission à vie sur les clients référés
};

// Permissions détaillées par type d'API Key
const API_KEY_PERMISSIONS = {
    user: {
        can_view_own_servers: true,
        can_power_own_servers: true,
        can_create_server: false,         // Requiert interface web
        can_view_own_stats: true,
        can_view_own_transactions: true,
        can_claim_daily_reward: true,
        can_view_own_deployments: true,
        can_manage_platform: false,
        can_manage_users: false,
        can_manage_resellers: false
    },
    reseller: {
        can_view_own_servers: true,
        can_power_own_servers: true,
        can_create_server: true,
        can_view_own_stats: true,
        can_view_own_transactions: true,
        can_view_clients: true,
        can_manage_clients: true,
        can_create_promo_codes: true,
        can_view_commission: true,
        can_request_withdrawal: true,
        can_send_client_notification: true,
        can_bulk_purchase: true,
        can_view_client_servers: true,
        can_manage_platform: false,
        can_manage_resellers: false
    },
    superadmin: {
        // Toutes les permissions
        can_view_all_users: true,
        can_manage_all_users: true,
        can_ban_users: true,
        can_manage_resellers: true,
        can_approve_withdrawals: true,
        can_adjust_commission_rates: true,
        can_view_all_transactions: true,
        can_manage_platform_settings: true,
        can_view_system_logs: true,
        can_manage_all_servers: true,
        can_delete_any_server: true,
        can_create_promo_codes: true,
        can_add_coins_to_any_user: true,
        can_view_financial_reports: true,
        can_manage_bulk_purchases: true,
        can_everything: true
    }
};

const DEPLOY_TIMEOUT = 10 * 60 * 1000;
const MAX_DEPLOY_SIZE_MB = 500;

const UPLOADS_DIR = path.join(__dirname, 'uploads', 'deployments');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const upload = multer({
    dest: UPLOADS_DIR,
    limits: { fileSize: 100 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/zip' || file.originalname.endsWith('.zip')) {
            cb(null, true);
        } else {
            cb(new Error('Seuls les fichiers ZIP sont acceptés'), false);
        }
    }
});

// =============================================
// BASE DE DONNÉES
// =============================================

const db = new sqlite3.Database('./flyhost.db');

db.serialize(() => {
    console.log('🔄 Initialisation de la base de données...');

    // =============================================
    // TABLE USERS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        public_id TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        api_key TEXT UNIQUE NOT NULL,
        api_key_last_reset DATETIME DEFAULT CURRENT_TIMESTAMP,
        api_calls_today INTEGER DEFAULT 0,
        api_calls_date DATE DEFAULT CURRENT_DATE,
        
        coins INTEGER DEFAULT 10,
        role TEXT DEFAULT 'user',
        current_plan TEXT DEFAULT 'free',
        
        referral_code TEXT UNIQUE,
        referred_by INTEGER,
        
        pterodactyl_user_id INTEGER,
        banned BOOLEAN DEFAULT FALSE,
        ban_reason TEXT,
        ban_expires DATETIME,
        
        daily_login_streak INTEGER DEFAULT 0,
        last_daily_login DATE,
        total_login_days INTEGER DEFAULT 0,
        account_created DATE DEFAULT CURRENT_DATE,
        
        badges TEXT DEFAULT '[]',
        level INTEGER DEFAULT 1,
        experience INTEGER DEFAULT 0,
        
        email_verified BOOLEAN DEFAULT FALSE,
        email_verification_code TEXT,
        email_verification_code_expires DATETIME,
        
        reset_password_code TEXT,
        reset_password_code_expires DATETIME,
        
        admin_expires_at DATETIME,
        admin_access_active BOOLEAN DEFAULT FALSE,
        
        last_login DATETIME,
        last_ip TEXT,
        newsletter_subscribed BOOLEAN DEFAULT TRUE,
        free_server_created BOOLEAN DEFAULT FALSE,
        
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        
        FOREIGN KEY(referred_by) REFERENCES users(id)
    )`);

    // =============================================
    // TABLE API_KEYS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        key TEXT UNIQUE NOT NULL,
        name TEXT,
        role_level TEXT NOT NULL DEFAULT 'user',
        api_key_type TEXT DEFAULT 'user',
        webhook_url TEXT,
        telegram_chat_id TEXT,
        whatsapp_number TEXT,
        description TEXT,
        
        can_create_server BOOLEAN DEFAULT FALSE,
        can_delete_server BOOLEAN DEFAULT FALSE,
        can_view_servers BOOLEAN DEFAULT TRUE,
        can_power_server BOOLEAN DEFAULT FALSE,
        can_deploy BOOLEAN DEFAULT FALSE,
        can_manage_users BOOLEAN DEFAULT FALSE,
        can_manage_credits BOOLEAN DEFAULT FALSE,
        can_view_stats BOOLEAN DEFAULT TRUE,
        
        requests_per_day INTEGER DEFAULT 100,
        requests_today INTEGER DEFAULT 0,
        requests_date DATE DEFAULT CURRENT_DATE,
        
        allowed_ips TEXT DEFAULT '[]',
        last_used DATETIME,
        last_ip TEXT,
        
        is_active BOOLEAN DEFAULT TRUE,
        expires_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // =============================================
    // TABLE SERVERS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        
        server_type TEXT NOT NULL,
        server_name TEXT NOT NULL,
        server_status TEXT DEFAULT 'creating',
        
        server_identifier TEXT UNIQUE,
        pterodactyl_id INTEGER,
        
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        email TEXT NOT NULL,
        
        is_ephemeral BOOLEAN DEFAULT FALSE,
        promo_code_used TEXT,
        
        expires_at DATETIME,
        is_active BOOLEAN DEFAULT TRUE,
        is_admin_server BOOLEAN DEFAULT FALSE,
        
        warning_sent BOOLEAN DEFAULT FALSE,
        deletion_scheduled BOOLEAN DEFAULT FALSE,
        
        last_activity DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // =============================================
    // TABLE PROMO_CODES
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS promo_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        
        server_type TEXT NOT NULL,
        duration_hours INTEGER NOT NULL,
        max_uses INTEGER NOT NULL,
        current_uses INTEGER DEFAULT 0,
        
        created_by INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        is_active BOOLEAN DEFAULT TRUE,
        
        description TEXT,
        
        FOREIGN KEY(created_by) REFERENCES users(id)
    )`);

    // =============================================
    // TABLE PROMO_CODE_USES
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS promo_code_uses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        promo_code_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        server_id INTEGER NOT NULL,
        used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        
        FOREIGN KEY(promo_code_id) REFERENCES promo_codes(id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(server_id) REFERENCES servers(id)
    )`);

    // =============================================
    // TABLE API_LOGS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS api_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        endpoint TEXT NOT NULL,
        method TEXT NOT NULL,
        ip TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // =============================================
    // TABLE TRANSACTIONS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        
        plan_key TEXT NOT NULL,
        server_name TEXT,
        amount INTEGER NOT NULL,
        panel_name TEXT,
        phone_number TEXT,
        payment_url TEXT,
        moneyfusion_token TEXT,
        
        status TEXT DEFAULT 'pending',
        payment_id TEXT UNIQUE,
        transaction_id TEXT,
        payment_method TEXT,
        
        is_renewal BOOLEAN DEFAULT FALSE,
        renewed_server_id INTEGER,
        promo_code_used TEXT,
        
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        completed_at DATETIME,
        
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // =============================================
    // TABLE SERVER_TRANSFERS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS server_transfers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER NOT NULL,
        from_user_id INTEGER NOT NULL,
        to_user_id INTEGER NOT NULL,
        transferred_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        
        FOREIGN KEY(server_id) REFERENCES servers(id),
        FOREIGN KEY(from_user_id) REFERENCES users(id),
        FOREIGN KEY(to_user_id) REFERENCES users(id)
    )`);

    // =============================================
    // TABLE REFERRALS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS referrals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        referrer_id INTEGER NOT NULL,
        referred_id INTEGER NOT NULL,
        reward_claimed BOOLEAN DEFAULT FALSE,
        coins_rewarded INTEGER DEFAULT 10,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        
        FOREIGN KEY(referrer_id) REFERENCES users(id),
        FOREIGN KEY(referred_id) REFERENCES users(id)
    )`);

    // =============================================
    // TABLE DAILY_REWARDS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS daily_rewards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        reward_date DATE NOT NULL,
        coins_earned INTEGER DEFAULT 5,
        streak_count INTEGER DEFAULT 1,
        bonus_applied BOOLEAN DEFAULT FALSE,
        claimed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        
        UNIQUE(user_id, reward_date),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // =============================================
    // TABLE USER_ACTIVITIES
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS user_activities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        activity_type TEXT NOT NULL,
        coins_earned INTEGER DEFAULT 0,
        description TEXT,
        metadata TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // =============================================
    // TABLE SERVER_LOGS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS server_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        status TEXT,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        
        FOREIGN KEY(server_id) REFERENCES servers(id)
    )`);

    // =============================================
    // TABLE SYSTEM_LOGS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS system_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        log_type TEXT NOT NULL,
        message TEXT NOT NULL,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // =============================================
    // TABLE ADMIN_ACTIONS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS admin_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER NOT NULL,
        action_type TEXT NOT NULL,
        target_type TEXT,
        target_id INTEGER,
        description TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        
        FOREIGN KEY(admin_id) REFERENCES users(id)
    )`);

    // =============================================
    // TABLE SYSTEM_SETTINGS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_by INTEGER,
        
        FOREIGN KEY(updated_by) REFERENCES users(id)
    )`);

    // =============================================
    // TABLE PANELS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS panels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        panel_type TEXT NOT NULL,
        panel_name TEXT NOT NULL,
        pterodactyl_id INTEGER,
        server_identifier TEXT UNIQUE,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        email TEXT NOT NULL,
        allocations TEXT,
        expires_at DATETIME,
        is_active BOOLEAN DEFAULT TRUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // =============================================
    // TABLE DEPLOYMENTS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS deployments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        deploy_type TEXT NOT NULL,
        deploy_source TEXT,
        status TEXT DEFAULT 'pending',
        build_log TEXT DEFAULT '',
        env_vars TEXT DEFAULT '{}',
        flyhost_config TEXT DEFAULT '{}',
        git_branch TEXT DEFAULT 'main',
        git_commit TEXT,
        auto_deploy BOOLEAN DEFAULT FALSE,
        last_deployed DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(server_id) REFERENCES servers(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // =============================================
    // TABLE GITHUB_CONNECTIONS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS github_connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        github_id INTEGER,
        github_username TEXT,
        github_email TEXT,
        access_token TEXT,
        connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // =============================================
    // TABLE DEPLOYMENT_SNAPSHOTS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS deployment_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        deployment_id INTEGER NOT NULL,
        commit_hash TEXT,
        snapshot_path TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(deployment_id) REFERENCES deployments(id)
    )`);

    // =============================================
    // TABLE TICKETS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'open',
        priority TEXT DEFAULT 'normal',
        admin_response TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // =============================================
    // TABLE USER_CREDITS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS user_credits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        balance DECIMAL(10,2) DEFAULT 0.00,
        currency TEXT DEFAULT 'XOF',
        total_purchased DECIMAL(10,2) DEFAULT 0.00,
        total_spent DECIMAL(10,2) DEFAULT 0.00,
        last_purchase DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // =============================================
    // TABLE CREDIT_TRANSACTIONS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS credit_transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        balance_after DECIMAL(10,2) NOT NULL,
        description TEXT,
        payment_id TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS coin_transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        amount INTEGER NOT NULL,
        balance_after INTEGER,
        description TEXT,
        reference_id TEXT,
        ip TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_coin_tx_user ON coin_transactions(user_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_coin_tx_type ON coin_transactions(type)`);

    // =============================================
    // TABLE API_USAGE_LOGS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS api_usage_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_key_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        endpoint TEXT NOT NULL,
        method TEXT NOT NULL,
        ip TEXT,
        status_code INTEGER,
        response_time INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(api_key_id) REFERENCES api_keys(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // =============================================
    // TABLE COIN_MARKET
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS coin_market (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        seller_id INTEGER NOT NULL,
        amount INTEGER NOT NULL,
        price_per_coin INTEGER NOT NULL,
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(seller_id) REFERENCES users(id)
    )`);

    // =============================================
    // TABLE MISSIONS
    // =============================================
    db.run(`CREATE TABLE IF NOT EXISTS missions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        mission_id TEXT NOT NULL,
        completed BOOLEAN DEFAULT FALSE,
        reward_claimed BOOLEAN DEFAULT FALSE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, mission_id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // =============================================
    // TABLES POUR LE CHAT GLOBAL
    // =============================================

    // TABLE CHAT_MESSAGES (avec support des réponses)
    db.run(`CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        content TEXT,
        media_type TEXT,
        media_url TEXT,
        media_size INTEGER,
        reply_to INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(reply_to) REFERENCES chat_messages(id)
    )`);

    // TABLE CHAT_REACTIONS (NOUVELLE)
    db.run(`CREATE TABLE IF NOT EXISTS chat_reactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        emoji TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(message_id, user_id, emoji),
        FOREIGN KEY(message_id) REFERENCES chat_messages(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // TABLE CHAT_PINNED_MESSAGES (NOUVELLE)
    db.run(`CREATE TABLE IF NOT EXISTS chat_pinned_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id INTEGER NOT NULL UNIQUE,
        pinned_by INTEGER NOT NULL,
        pinned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(message_id) REFERENCES chat_messages(id) ON DELETE CASCADE,
        FOREIGN KEY(pinned_by) REFERENCES users(id)
    )`);

    // TABLE CHAT_SETTINGS (existante)
    db.run(`CREATE TABLE IF NOT EXISTS chat_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        restriction_enabled BOOLEAN DEFAULT FALSE,
        media_disabled BOOLEAN DEFAULT FALSE,
        reactions_disabled BOOLEAN DEFAULT FALSE,
        updated_by INTEGER,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(updated_by) REFERENCES users(id)
    )`);

    // TABLE CHAT_MUTES (existante)
    db.run(`CREATE TABLE IF NOT EXISTS chat_mutes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL UNIQUE,
        muted_by INTEGER NOT NULL,
        reason TEXT,
        muted_until DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(muted_by) REFERENCES users(id)
    )`);

    // TABLE CHAT_SPEAK_REQUESTS (existante)
    db.run(`CREATE TABLE IF NOT EXISTS chat_speak_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        status TEXT DEFAULT 'pending',
        resolved_by INTEGER,
        resolved_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(resolved_by) REFERENCES users(id)
    )`);

    // =============================================
    // TABLES REVENDEUR
    // =============================================

    // TABLE RESELLER_PROFILES (existante)
    db.run(`CREATE TABLE IF NOT EXISTS reseller_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        business_name TEXT,
        commission_rate DECIMAL(5,2) DEFAULT 15.00,
        commission_balance DECIMAL(10,2) DEFAULT 0.00,
        total_earned DECIMAL(10,2) DEFAULT 0.00,
        total_withdrawn DECIMAL(10,2) DEFAULT 0.00,
        contract_accepted BOOLEAN DEFAULT FALSE,
        contract_accepted_at DATETIME,
        contract_ip TEXT,
        active BOOLEAN DEFAULT TRUE,
        affiliate_code TEXT UNIQUE,
        custom_domain TEXT,
        support_email TEXT,
        max_clients INTEGER DEFAULT 100,
        bulk_discount_rate DECIMAL(5,2) DEFAULT 10.00,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // TABLE WITHDRAWAL_REQUESTS (existante)
    db.run(`CREATE TABLE IF NOT EXISTS withdrawal_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reseller_id INTEGER NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        status TEXT DEFAULT 'pending',
        payment_method TEXT NOT NULL,
        payment_details TEXT NOT NULL,
        admin_note TEXT,
        processed_by INTEGER,
        processed_at DATETIME,
        reference TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(reseller_id) REFERENCES users(id),
        FOREIGN KEY(processed_by) REFERENCES users(id)
    )`);

    // TABLE RESELLER_CLIENTS (existante)
    db.run(`CREATE TABLE IF NOT EXISTS reseller_clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reseller_id INTEGER NOT NULL,
        client_id INTEGER NOT NULL,
        acquisition_source TEXT DEFAULT 'affiliate',
        affiliate_code_used TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(reseller_id, client_id),
        FOREIGN KEY(reseller_id) REFERENCES users(id),
        FOREIGN KEY(client_id) REFERENCES users(id)
    )`);

    // TABLE COMMISSION_LOGS (existante)
    db.run(`CREATE TABLE IF NOT EXISTS commission_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reseller_id INTEGER NOT NULL,
        client_id INTEGER NOT NULL,
        transaction_id INTEGER,
        amount DECIMAL(10,2) NOT NULL,
        rate DECIMAL(5,2) NOT NULL,
        base_amount DECIMAL(10,2) NOT NULL,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(reseller_id) REFERENCES users(id),
        FOREIGN KEY(client_id) REFERENCES users(id)
    )`);

    // TABLE BULK_PURCHASES (existante)
    db.run(`CREATE TABLE IF NOT EXISTS bulk_purchases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reseller_id INTEGER NOT NULL,
        plan_key TEXT NOT NULL,
        quantity INTEGER NOT NULL,
        unit_price INTEGER NOT NULL,
        total_price INTEGER NOT NULL,
        discount_applied DECIMAL(5,2) DEFAULT 0,
        coins_credited INTEGER NOT NULL,
        status TEXT DEFAULT 'completed',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(reseller_id) REFERENCES users(id)
    )`);

    // TABLE RESELLER_PROMO_CODES (existante)
    db.run(`CREATE TABLE IF NOT EXISTS reseller_promo_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reseller_id INTEGER NOT NULL,
        code TEXT UNIQUE NOT NULL,
        server_type TEXT NOT NULL,
        duration_hours INTEGER NOT NULL,
        max_uses INTEGER NOT NULL,
        current_uses INTEGER DEFAULT 0,
        coins_cost INTEGER NOT NULL,
        is_active BOOLEAN DEFAULT TRUE,
        expires_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(reseller_id) REFERENCES users(id)
    )`);

    // TABLE RESELLER_NOTIFICATIONS (existante)
    db.run(`CREATE TABLE IF NOT EXISTS reseller_notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reseller_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        read BOOLEAN DEFAULT FALSE,
        metadata TEXT DEFAULT '{}',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(reseller_id) REFERENCES users(id)
    )`);

    // =============================================
    // NOUVELLES TABLES V2
    // =============================================

    db.run(`CREATE TABLE IF NOT EXISTS announcements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        type TEXT DEFAULT 'info',
        active BOOLEAN DEFAULT TRUE,
        created_by INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS user_notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        type TEXT DEFAULT 'info',
        link TEXT,
        is_read BOOLEAN DEFAULT FALSE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
    db.run('CREATE INDEX IF NOT EXISTS idx_user_notifications_user ON user_notifications(user_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_user_notifications_read ON user_notifications(is_read)');

    db.run(`CREATE TABLE IF NOT EXISTS ticket_replies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id INTEGER NOT NULL,
        user_id INTEGER,
        is_admin BOOLEAN DEFAULT FALSE,
        message TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(ticket_id) REFERENCES tickets(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS custom_templates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reseller_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        category TEXT DEFAULT 'other',
        game TEXT NOT NULL,
        ram_mb INTEGER DEFAULT 512,
        disk_mb INTEGER DEFAULT 1024,
        cpu INTEGER DEFAULT 100,
        docker_image TEXT,
        startup TEXT,
        env_vars TEXT,
        is_public INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(reseller_id) REFERENCES users(id)
    )`);

    // =============================================
    // TABLES V3 - NOUVELLES FONCTIONNALITÉS
    // =============================================

    db.run(`CREATE TABLE IF NOT EXISTS admin_audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER,
        admin_name TEXT,
        action TEXT NOT NULL,
        target_type TEXT,
        target_id INTEGER,
        details TEXT,
        ip TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS server_activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER NOT NULL,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(server_id) REFERENCES servers(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS server_shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER NOT NULL,
        owner_id INTEGER NOT NULL,
        shared_with_email TEXT NOT NULL,
        shared_with_id INTEGER,
        permission TEXT DEFAULT 'view',
        status TEXT DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(server_id) REFERENCES servers(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS server_reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
        comment TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(server_id, user_id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS forum_threads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        category TEXT DEFAULT 'general',
        author_id INTEGER NOT NULL,
        pinned INTEGER DEFAULT 0,
        locked INTEGER DEFAULT 0,
        views INTEGER DEFAULT 0,
        replies_count INTEGER DEFAULT 0,
        last_reply_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(author_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS forum_posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        thread_id INTEGER NOT NULL,
        author_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        likes INTEGER DEFAULT 0,
        is_solution INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(thread_id) REFERENCES forum_threads(id),
        FOREIGN KEY(author_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS challenges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        type TEXT DEFAULT 'monthly',
        reward_coins INTEGER DEFAULT 0,
        reward_badge TEXT,
        target_value INTEGER DEFAULT 1,
        target_metric TEXT,
        month TEXT,
        active INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS user_challenges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        challenge_id INTEGER NOT NULL,
        progress INTEGER DEFAULT 0,
        completed INTEGER DEFAULT 0,
        completed_at DATETIME,
        reward_claimed INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, challenge_id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        plan_name TEXT NOT NULL,
        price_per_month INTEGER NOT NULL,
        coins_per_month INTEGER DEFAULT 0,
        started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        next_billing_at DATETIME,
        active INTEGER DEFAULT 1,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS marketplace_listings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        seller_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        category TEXT DEFAULT 'template',
        price_coins INTEGER NOT NULL,
        game TEXT,
        content TEXT,
        thumbnail TEXT,
        downloads INTEGER DEFAULT 0,
        rating REAL DEFAULT 0,
        active INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(seller_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS marketplace_purchases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        listing_id INTEGER NOT NULL,
        buyer_id INTEGER NOT NULL,
        coins_spent INTEGER NOT NULL,
        purchased_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS invoices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        transaction_id INTEGER,
        amount INTEGER NOT NULL,
        currency TEXT DEFAULT 'XOF',
        description TEXT,
        status TEXT DEFAULT 'paid',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS restart_schedules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER NOT NULL UNIQUE,
        schedule TEXT,
        day_of_week INTEGER,
        hour INTEGER DEFAULT 3,
        last_restart_at DATETIME,
        FOREIGN KEY(server_id) REFERENCES servers(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS server_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER NOT NULL,
        cpu REAL DEFAULT 0,
        ram_mb REAL DEFAULT 0,
        disk_mb REAL DEFAULT 0,
        net_rx_kb REAL DEFAULT 0,
        net_tx_kb REAL DEFAULT 0,
        recorded_at DATETIME DEFAULT (datetime('now')),
        FOREIGN KEY(server_id) REFERENCES servers(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS server_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER NOT NULL,
        alert_type TEXT NOT NULL,
        sent_at DATETIME DEFAULT (datetime('now'))
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS server_envvars (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER NOT NULL,
        key_name TEXT NOT NULL,
        value TEXT,
        updated_at DATETIME DEFAULT (datetime('now')),
        UNIQUE(server_id, key_name)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS deploy_webhooks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER NOT NULL UNIQUE,
        token TEXT UNIQUE NOT NULL,
        branch TEXT DEFAULT 'main',
        repo_url TEXT,
        last_deploy_at DATETIME,
        created_at DATETIME DEFAULT (datetime('now'))
    )`);

    // =============================================
    // AJOUT DES COLONNES MANQUANTES
    // =============================================

    // Ajouter env_type à transactions si pas existant
    db.run(`ALTER TABLE transactions ADD COLUMN env_type TEXT DEFAULT 'nodejs'`, (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.error('Erreur ajout colonne env_type:', err);
        }
    });

    // Ajouter reply_to à chat_messages si pas existant
    db.run(`ALTER TABLE chat_messages ADD COLUMN reply_to INTEGER`, (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.error('Erreur ajout colonne reply_to:', err);
        }
    });

    // Ajouter reactions_disabled à chat_settings
    db.run(`ALTER TABLE chat_settings ADD COLUMN reactions_disabled BOOLEAN DEFAULT FALSE`, (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.error('Erreur ajout colonne reactions_disabled:', err);
        }
    });

    // Ajouter les colonnes à api_keys
    db.run(`ALTER TABLE api_keys ADD COLUMN api_key_type TEXT DEFAULT 'user'`, (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.error('Erreur ajout colonne api_key_type:', err);
        }
    });
    db.run(`ALTER TABLE api_keys ADD COLUMN webhook_url TEXT`, (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.error('Erreur ajout colonne webhook_url:', err);
        }
    });
    db.run(`ALTER TABLE api_keys ADD COLUMN telegram_chat_id TEXT`, (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.error('Erreur ajout colonne telegram_chat_id:', err);
        }
    });
    db.run(`ALTER TABLE api_keys ADD COLUMN whatsapp_number TEXT`, (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.error('Erreur ajout colonne whatsapp_number:', err);
        }
    });
    db.run(`ALTER TABLE api_keys ADD COLUMN description TEXT`, (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.error('Erreur ajout colonne description:', err);
        }
    });

    // Nouvelles colonnes servers
    ['auto_renew INTEGER DEFAULT 0', 'backup_schedule TEXT DEFAULT NULL', 'warning_sent_3d INTEGER DEFAULT 0', 'last_backup_at DATETIME DEFAULT NULL', "env_type TEXT DEFAULT 'nodejs'", 'alloc_port INTEGER DEFAULT NULL', 'alloc_ip TEXT DEFAULT NULL', 'custom_subdomain TEXT DEFAULT NULL', 'custom_domain TEXT DEFAULT NULL'].forEach(col => {
        db.run(`ALTER TABLE servers ADD COLUMN ${col}`, (err) => {});
    });
    // Nouvelles colonnes tickets
    ['status TEXT DEFAULT \'open\'', 'admin_reply TEXT DEFAULT NULL', 'replied_at DATETIME DEFAULT NULL', 'priority TEXT DEFAULT \'normal\'', 'category TEXT DEFAULT \'general\''].forEach(col => {
        db.run(`ALTER TABLE tickets ADD COLUMN ${col}`, (err) => {});
    });

    // =============================================
    // INDEX POUR TOUTES LES TABLES
    // =============================================

    const indexes = [
        // Index utilisateurs
        'CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)',
        'CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)',
        'CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key)',
        'CREATE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code)',
        
        // Index serveurs
        'CREATE INDEX IF NOT EXISTS idx_servers_user_id ON servers(user_id)',
        'CREATE INDEX IF NOT EXISTS idx_servers_expires_at ON servers(expires_at)',
        'CREATE INDEX IF NOT EXISTS idx_servers_status ON servers(server_status)',
        
        // Index codes promo
        'CREATE INDEX IF NOT EXISTS idx_promo_codes_code ON promo_codes(code)',
        'CREATE INDEX IF NOT EXISTS idx_promo_codes_active ON promo_codes(is_active)',
        
        // Index transactions
        'CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id)',
        'CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status)',
        'CREATE INDEX IF NOT EXISTS idx_transactions_payment_id ON transactions(payment_id)',
        'CREATE INDEX IF NOT EXISTS idx_transactions_moneyfusion_token ON transactions(moneyfusion_token)',
        
        // Index récompenses quotidiennes
        'CREATE INDEX IF NOT EXISTS idx_daily_rewards_user_date ON daily_rewards(user_id, reward_date)',
        
        // Index logs
        'CREATE INDEX IF NOT EXISTS idx_api_logs_user_date ON api_logs(user_id, created_at)',
        'CREATE INDEX IF NOT EXISTS idx_user_activities_user_id ON user_activities(user_id)',
        'CREATE INDEX IF NOT EXISTS idx_server_logs_server_id ON server_logs(server_id)',
        
        // Index panels
        'CREATE INDEX IF NOT EXISTS idx_panels_user_id ON panels(user_id)',
        'CREATE INDEX IF NOT EXISTS idx_panels_expires_at ON panels(expires_at)',
        
        // Index déploiements
        'CREATE INDEX IF NOT EXISTS idx_deployments_server_id ON deployments(server_id)',
        'CREATE INDEX IF NOT EXISTS idx_deployments_user_id ON deployments(user_id)',
        'CREATE INDEX IF NOT EXISTS idx_deployments_status ON deployments(status)',
        
        // Index GitHub
        'CREATE INDEX IF NOT EXISTS idx_github_connections_user_id ON github_connections(user_id)',
        
        // Index API Keys
        'CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id)',
        'CREATE INDEX IF NOT EXISTS idx_api_keys_key ON api_keys(key)',
        'CREATE INDEX IF NOT EXISTS idx_api_usage_logs_api_key_id ON api_usage_logs(api_key_id)',
        
        // Index tickets
        'CREATE INDEX IF NOT EXISTS idx_tickets_user_id ON tickets(user_id)',
        
        // Index crédits
        'CREATE INDEX IF NOT EXISTS idx_user_credits_user_id ON user_credits(user_id)',
        'CREATE INDEX IF NOT EXISTS idx_credit_transactions_user_id ON credit_transactions(user_id)',
        
        // Index marché
        'CREATE INDEX IF NOT EXISTS idx_coin_market_seller_id ON coin_market(seller_id)',
        
        // Index missions
        'CREATE INDEX IF NOT EXISTS idx_missions_user_id ON missions(user_id)',
        
        // Index snapshots
        'CREATE INDEX IF NOT EXISTS idx_deployment_snapshots_deployment_id ON deployment_snapshots(deployment_id)',
        
        // Index CHAT
        'CREATE INDEX IF NOT EXISTS idx_chat_messages_user_id ON chat_messages(user_id)',
        'CREATE INDEX IF NOT EXISTS idx_chat_messages_created_at ON chat_messages(created_at)',
        'CREATE INDEX IF NOT EXISTS idx_chat_messages_reply_to ON chat_messages(reply_to)',
        'CREATE INDEX IF NOT EXISTS idx_chat_reactions_message ON chat_reactions(message_id)',
        'CREATE INDEX IF NOT EXISTS idx_chat_reactions_user ON chat_reactions(user_id)',
        'CREATE INDEX IF NOT EXISTS idx_chat_mutes_user_id ON chat_mutes(user_id)',
        'CREATE INDEX IF NOT EXISTS idx_chat_speak_requests_user_id ON chat_speak_requests(user_id)',
        'CREATE INDEX IF NOT EXISTS idx_chat_speak_requests_status ON chat_speak_requests(status)',
        'CREATE INDEX IF NOT EXISTS idx_chat_pinned_messages_message ON chat_pinned_messages(message_id)',
        
        // Index REVENDEUR
        'CREATE INDEX IF NOT EXISTS idx_reseller_profiles_user ON reseller_profiles(user_id)',
        'CREATE INDEX IF NOT EXISTS idx_reseller_profiles_affiliate ON reseller_profiles(affiliate_code)',
        'CREATE INDEX IF NOT EXISTS idx_reseller_clients_reseller ON reseller_clients(reseller_id)',
        'CREATE INDEX IF NOT EXISTS idx_reseller_clients_client ON reseller_clients(client_id)',
        'CREATE INDEX IF NOT EXISTS idx_commission_logs_reseller ON commission_logs(reseller_id)',
        'CREATE INDEX IF NOT EXISTS idx_commission_logs_client ON commission_logs(client_id)',
        'CREATE INDEX IF NOT EXISTS idx_withdrawal_reseller ON withdrawal_requests(reseller_id)',
        'CREATE INDEX IF NOT EXISTS idx_withdrawal_status ON withdrawal_requests(status)',
        'CREATE INDEX IF NOT EXISTS idx_bulk_purchases_reseller ON bulk_purchases(reseller_id)',
        'CREATE INDEX IF NOT EXISTS idx_reseller_promo_codes_reseller ON reseller_promo_codes(reseller_id)',
        'CREATE INDEX IF NOT EXISTS idx_reseller_promo_codes_code ON reseller_promo_codes(code)',
        'CREATE INDEX IF NOT EXISTS idx_reseller_notifications_reseller ON reseller_notifications(reseller_id)',
        'CREATE INDEX IF NOT EXISTS idx_reseller_notifications_read ON reseller_notifications(read)'
    ];

    indexes.forEach(sql => {
        db.run(sql, (err) => {
            if (err && !err.message.includes('already exists')) {
                console.error(`❌ Erreur création index:`, err.message);
            }
        });
    });

    // =============================================
    // PARAMÈTRES PAR DÉFAUT
    // =============================================

    const defaultSettings = [
        ['maintenance_mode', 'false'],
        ['registration_enabled', 'true'],
        ['default_coins_on_register', '10'],
        ['daily_reward_base', '5'],
        ['daily_reward_streak_bonus', '2'],
        ['referral_reward', '10'],
        ['max_servers_per_user_free', '1'],
        ['max_servers_per_user_paid', '10']
    ];

    defaultSettings.forEach(([key, value]) => {
        db.run('INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)', [key, value]);
    });

    // =============================================
    // INITIALISER LES PARAMÈTRES DU CHAT
    // =============================================

    db.get('SELECT * FROM chat_settings WHERE id = 1', [], (err, row) => {
        if (!row) {
            db.run('INSERT INTO chat_settings (id, restriction_enabled, media_disabled, reactions_disabled) VALUES (1, 0, 0, 0)');
            console.log('✅ Paramètres du chat initialisés');
        }
    });

    // =============================================
    // CRÉATION DU SUPERADMIN PAR DÉFAUT
    // =============================================

    bcrypt.hash('JESUS', 12, (err, hashedPassword) => {
        if (err) return console.error('❌ Erreur création superadmin:', err);
        
        const adminApiKey = 'FLYHOST_SUPERADMIN_' + crypto.randomBytes(32).toString('hex');
        const adminReferralCode = generateReferralCode('superadmin');
        const publicId = crypto.randomUUID();
        
        db.run(`INSERT OR IGNORE INTO users (
                public_id, username, email, password, api_key, coins, role, 
                current_plan, referral_code, badges, email_verified, 
                admin_expires_at, admin_access_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                publicId, 
                'superadmin', 
                'admin@flyhost.site', 
                hashedPassword,
                adminApiKey, 
                999999, 
                'superadmin', 
                'admin', 
                adminReferralCode, 
                JSON.stringify(['admin-assistant', 'beta-tester', 'premium']), 
                true,
                '2099-12-31 23:59:59',
                true
            ],
            function(err) {
                if (err && !err.message.includes('UNIQUE')) {
                    console.error('❌ Erreur insertion superadmin:', err);
                } else {
                    console.log('✅ Superadmin créé avec succès');
                    // Auto-créer le profil revendeur du superadmin s'il n'existe pas
                    db.get('SELECT id FROM users WHERE email = ?', ['admin@flyhost.site'], (e2, adminUser) => {
                        if (!adminUser) return;
                        db.get('SELECT id FROM reseller_profiles WHERE user_id = ?', [adminUser.id], (e3, existingProfile) => {
                            if (existingProfile) return;
                            db.run(
                                `INSERT INTO reseller_profiles (user_id, business_name, commission_rate, commission_balance, total_earned, total_withdrawn, contract_accepted, contract_accepted_at, active, affiliate_code, max_clients, bulk_discount_rate)
                                 VALUES (?, 'FLYHOST Admin', 30, 0, 0, 0, 1, datetime('now'), 1, ?, 1000, 20)`,
                                [adminUser.id, 'ADMIN' + Math.random().toString(36).substring(2, 8).toUpperCase()],
                                (e4) => { if (!e4) console.log('✅ Profil revendeur superadmin créé'); }
                            );
                        });
                    });
                }
            }
        );
    });

    console.log('✅ Base de données initialisée avec toutes les tables chat et revendeur');

    // Charger le mapping egg depuis system_settings (remplace les valeurs par défaut)
    const eggKeys = ['egg_nodejs','egg_python','egg_php','egg_java','egg_static','egg_discord',
                     'docker_nodejs','docker_python','docker_php','docker_java','docker_static'];
    const eggPlaceholders = eggKeys.map(()=>'?').join(',');
    db.all(`SELECT key, value FROM system_settings WHERE key IN (${eggPlaceholders})`, eggKeys, (eErr, rows) => {
        if (eErr || !rows || !rows.length) return;
        const techMap   = { egg_nodejs:'nodejs', egg_python:'python', egg_php:'php', egg_java:'java', egg_static:'static', egg_discord:'discord' };
        const dockerMap = { docker_nodejs:'nodejs', docker_python:'python', docker_php:'php', docker_java:'java', docker_static:'static' };
        rows.forEach(({ key, value }) => {
            if (techMap[key]  && TECH_ENVIRONMENTS[techMap[key]])  TECH_ENVIRONMENTS[techMap[key]].egg          = parseInt(value) || TECH_ENVIRONMENTS[techMap[key]].egg;
            if (dockerMap[key] && TECH_ENVIRONMENTS[dockerMap[key]]) TECH_ENVIRONMENTS[dockerMap[key]].docker_image = value || TECH_ENVIRONMENTS[dockerMap[key]].docker_image;
        });
        console.log('✅ Egg mapping chargé depuis la base de données');
    });
});

// =============================================
// FONCTIONS UTILITAIRES
// =============================================

function generatePublicId() { 
    return 'usr_' + crypto.randomBytes(16).toString('hex'); 
}

function generateApiKey(username) {
    const timestamp = Date.now().toString(36);
    const random = crypto.randomBytes(16).toString('hex');
    const cleanUsername = username.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
    return `${cleanUsername}_${timestamp}_${random}`;
}

// Nouvelle fonction pour générer des API keys typées
function generateTypedApiKey(type, username) {
    const prefix = type === 'superadmin' ? 'FLYHOST_SA' : type === 'reseller' ? 'FLYHOST_RS' : 'FLYHOST_US';
    const timestamp = Date.now().toString(36).toUpperCase();
    const random = crypto.randomBytes(20).toString('hex').toUpperCase();
    const clean = username.replace(/[^a-zA-Z0-9]/g, '').slice(0, 8).toUpperCase();
    return `${prefix}_${clean}_${timestamp}_${random}`;
}

function getApiKeyPermissions(keyType, userRole) {
    if (userRole === 'superadmin' || keyType === 'superadmin') return API_KEY_PERMISSIONS.superadmin;
    if (userRole === 'admin' || keyType === 'reseller') return API_KEY_PERMISSIONS.reseller;
    return API_KEY_PERMISSIONS.user;
}

function generateReferralCode(username) {
    const cleanUsername = username.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
    const digits = Math.floor(1000 + Math.random() * 9000);
    return `${cleanUsername}${digits}`;
}

function generateAffiliateCode() {
    return 'AFF_' + crypto.randomBytes(6).toString('hex').toUpperCase();
}

function generateServerIdentifier() { 
    return 'srv_' + crypto.randomBytes(12).toString('hex'); 
}

function generateVerificationCode() { 
    return Math.floor(100000 + Math.random() * 900000).toString(); 
}

function generatePromoCode(prefix = 'FLY') {
    const random = crypto.randomBytes(4).toString('hex').toUpperCase();
    const timestamp = Date.now().toString(36).slice(-3).toUpperCase();
    return `${prefix}-${random}${timestamp}`;
}

function getCurrentDate() {
    const now = new Date();
    return now.toISOString().split('T')[0];
}

const emailTransporter = nodemailer.createTransport({
    host: EMAIL_CONFIG.host,
    port: EMAIL_CONFIG.port,
    secure: EMAIL_CONFIG.secure,
    auth: EMAIL_CONFIG.auth
});

emailTransporter.verify((error, success) => {
    if (error) {
        console.error('❌ Erreur configuration email:', error);
    } else {
        console.log('✅ Serveur email configuré');
    }
});

async function sendEmail(to, subject, html) {
    try {
        const mailOptions = {
            from: EMAIL_CONFIG.from,
            to,
            subject,
            html
        };
        await emailTransporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        console.error('❌ Erreur envoi email:', error);
        return false;
    }
}

async function sendVerificationEmail(email, username, verificationCode) {
    const html = `
        <div style="font-family: Arial; max-width: 600px; margin: 0 auto; padding: 20px; background: #0f172a; color: #fff; border-radius: 10px;">
            <h1 style="color: #6366f1;">Bienvenue ${username} !</h1>
            <p>Voici votre code de vérification :</p>
            <div style="background: #1e293b; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
                <h2 style="color: #6366f1; font-size: 32px; letter-spacing: 5px;">${verificationCode}</h2>
            </div>
            <p>Ce code expirera dans 15 minutes.</p>
            <p style="color: #94a3b8; font-size: 12px; margin-top: 20px;">FLYHOST - Hébergement de serveurs</p>
        </div>
    `;
    return await sendEmail(email, '🔐 Code de Vérification FLYHOST', html);
}

async function sendPasswordResetEmail(email, username, resetCode) {
    const html = `
        <div style="font-family: Arial; max-width: 600px; margin: 0 auto; padding: 20px; background: #0f172a; color: #fff; border-radius: 10px;">
            <h1 style="color: #6366f1;">Réinitialisation de mot de passe</h1>
            <p>Bonjour ${username},</p>
            <p>Voici votre code de réinitialisation :</p>
            <div style="background: #1e293b; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
                <h2 style="color: #6366f1; font-size: 32px; letter-spacing: 5px;">${resetCode}</h2>
            </div>
            <p>Ce code expirera dans 15 minutes.</p>
            <p style="color: #94a3b8; font-size: 12px; margin-top: 20px;">FLYHOST - Hébergement de serveurs</p>
        </div>
    `;
    return await sendEmail(email, '🔐 Réinitialisation de mot de passe FLYHOST', html);
}

async function sendPromoCodeEmail(email, username, promoCode, serverType, duration) {
    const html = `
        <div style="font-family: Arial; max-width: 600px; margin: 0 auto; padding: 20px; background: #0f172a; color: #fff; border-radius: 10px;">
            <h1 style="color: #10b981;">🎁 Code Promo Spécial !</h1>
            <p>Bonjour ${username},</p>
            <p>Vous avez reçu un code promo pour un serveur ${serverType} !</p>
            <div style="background: #1e293b; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
                <h2 style="color: #10b981; font-size: 32px; letter-spacing: 5px;">${promoCode}</h2>
                <p style="color: #94a3b8;">Durée: ${duration} heures</p>
            </div>
            <a href="https://flihost.site/dashboard" style="display: inline-block; background: #6366f1; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Utiliser maintenant</a>
            <p style="color: #94a3b8; font-size: 12px; margin-top: 20px;">FLYHOST - Hébergement de serveurs</p>
        </div>
    `;
    return await sendEmail(email, '🎁 Votre code promo FLYHOST', html);
}

async function sendPaymentConfirmation(transaction, user) {
    const html = `
        <div style="font-family: Arial; max-width: 600px; margin: 0 auto; padding: 20px; background: #0f172a; color: #fff; border-radius: 10px;">
            <h1 style="color: #10b981;">✅ Paiement Confirmé !</h1>
            <p>Bonjour ${user.username},</p>
            <p>Votre paiement a été traité avec succès.</p>
            <div style="background: #1e293b; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <p><strong>Montant:</strong> ${transaction.amount} coins</p>
                <p><strong>Transaction ID:</strong> ${transaction.transaction_id || 'N/A'}</p>
                <p><strong>Date:</strong> ${new Date(transaction.completed_at || Date.now()).toLocaleString('fr-FR')}</p>
                ${transaction.plan_key && transaction.plan_key !== 'coin_purchase' ? `<p><strong>Plan:</strong> ${transaction.plan_key}</p>` : ''}
                ${transaction.panel_name ? `<p><strong>Panel:</strong> ${transaction.panel_name}</p>` : ''}
            </div>
            <a href="https://flihost.site/dashboard" style="display: inline-block; background: #6366f1; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Tableau de bord</a>
            <p style="color: #94a3b8; font-size: 12px; margin-top: 20px;">FLYHOST - Hébergement de serveurs</p>
        </div>
    `;
    return await sendEmail(user.email, '✅ Confirmation de paiement FLYHOST', html);
}

async function sendResellerWeeklyReport(reseller) {
    const html = `
        <div style="font-family: Arial; max-width: 600px; margin: 0 auto; padding: 20px; background: #0f172a; color: #fff; border-radius: 10px;">
            <h1 style="color: #6366f1;">📊 Rapport Hebdomadaire</h1>
            <p>Bonjour ${reseller.username},</p>
            <p>Voici votre récapitulatif de la semaine :</p>
            <div style="background: #1e293b; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <p><strong>Solde commissions:</strong> ${reseller.commission_balance} XOF</p>
                <p><strong>Total gagné:</strong> ${reseller.total_earned} XOF</p>
                <p><strong>Retraits effectués:</strong> ${reseller.total_withdrawn} XOF</p>
            </div>
            <a href="https://flihost.site/reseller/dashboard" style="display: inline-block; background: #6366f1; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Tableau de bord revendeur</a>
            <p style="color: #94a3b8; font-size: 12px; margin-top: 20px;">FLYHOST - Programme Revendeur</p>
        </div>
    `;
    return await sendEmail(reseller.email, '📊 Rapport hebdomadaire FLYHOST Revendeur', html);
}

// =============================================
// MIDDLEWARES
// =============================================

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            success: false,
            error: 'Token requis',
            code: 'TOKEN_REQUIRED'
        });
    }

    jwt.verify(token, WEB_CONFIG.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({
                success: false,
                error: 'Token invalide',
                code: 'INVALID_TOKEN'
            });
        }

        db.get('SELECT banned, ban_expires FROM users WHERE id = ?', [user.userId], (err, row) => {
            if (err || !row) {
                return res.status(403).json({
                    success: false,
                    error: 'Utilisateur non trouvé',
                    code: 'USER_NOT_FOUND'
                });
            }
            
            if (row.banned) {
                const now = new Date();
                const banExpires = row.ban_expires ? new Date(row.ban_expires) : null;
                
                if (banExpires && banExpires > now) {
                    return res.status(403).json({
                        success: false,
                        error: `Compte suspendu jusqu'au ${banExpires.toLocaleDateString()}`,
                        code: 'ACCOUNT_BANNED',
                        ban_expires: banExpires
                    });
                } else if (row.banned && !banExpires) {
                    return res.status(403).json({
                        success: false,
                        error: 'Compte suspendu définitivement',
                        code: 'ACCOUNT_BANNED_PERMANENT'
                    });
                }
            }
            
            req.user = user;
            next();
        });
    });
}

// Middleware API Key enrichi avec permissions
async function authenticateApiKey(req, res, next) {
    const apiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '') || req.query.api_key;

    if (!apiKey) {
        return res.status(401).json({ 
            success: false, 
            error: 'API Key requise', 
            code: 'API_KEY_REQUIRED' 
        });
    }

    db.get(
        `SELECT ak.*, u.username, u.email, u.role, u.banned, u.coins
         FROM api_keys ak
         JOIN users u ON ak.user_id = u.id
         WHERE ak.key = ? AND ak.is_active = 1`,
        [apiKey],
        async (err, keyData) => {
            if (err || !keyData) {
                return res.status(401).json({ 
                    success: false, 
                    error: 'API Key invalide', 
                    code: 'INVALID_API_KEY' 
                });
            }

            if (keyData.banned) {
                return res.status(403).json({ 
                    success: false, 
                    error: 'Compte suspendu', 
                    code: 'ACCOUNT_BANNED' 
                });
            }

            if (keyData.expires_at && new Date(keyData.expires_at) < new Date()) {
                return res.status(401).json({ 
                    success: false, 
                    error: 'API Key expirée', 
                    code: 'API_KEY_EXPIRED' 
                });
            }

            // Vérification IP
            const allowedIps = JSON.parse(keyData.allowed_ips || '[]');
            if (allowedIps.length > 0 && !allowedIps.includes(req.ip)) {
                return res.status(403).json({ 
                    success: false, 
                    error: 'IP non autorisée', 
                    code: 'IP_NOT_ALLOWED' 
                });
            }

            // Rate limiting
            const today = getCurrentDate();
            if (keyData.requests_date !== today) {
                db.run('UPDATE api_keys SET requests_today = 0, requests_date = ? WHERE id = ?', [today, keyData.id]);
                keyData.requests_today = 0;
            }
            if (keyData.requests_today >= keyData.requests_per_day) {
                return res.status(429).json({ 
                    success: false, 
                    error: 'Limite quotidienne atteinte', 
                    code: 'DAILY_LIMIT_REACHED' 
                });
            }

            // Détermine le type de clé et les permissions
            const keyType = keyData.api_key_type || (keyData.role === 'superadmin' ? 'superadmin' : keyData.role === 'admin' ? 'reseller' : 'user');
            const permissions = getApiKeyPermissions(keyType, keyData.role);

            db.run(`UPDATE api_keys SET requests_today = requests_today + 1, last_used = CURRENT_TIMESTAMP, last_ip = ? WHERE id = ?`, [req.ip, keyData.id]);
            db.run(`INSERT INTO api_usage_logs (api_key_id, user_id, endpoint, method, ip) VALUES (?, ?, ?, ?, ?)`, [keyData.id, keyData.user_id, req.originalUrl, req.method, req.ip]);

            req.apiKey = keyData;
            req.apiKeyType = keyType;
            req.permissions = permissions;
            req.user = { userId: keyData.user_id, role: keyData.role, username: keyData.username };
            next();
        }
    );
}

// Middleware de vérification de permission spécifique
function requirePermission(permission) {
    return (req, res, next) => {
        if (!req.permissions || !req.permissions[permission]) {
            return res.status(403).json({
                success: false,
                error: `Permission manquante: ${permission}`,
                code: 'PERMISSION_DENIED',
                required_permission: permission
            });
        }
        next();
    };
}

function requireInternalAccess(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    // Accepte le mot de passe interne
    if (token === WEB_CONFIG.INTERNAL_PASSWORD) return next();

    // Accepte aussi un JWT superadmin valide
    if (token) {
        try {
            const decoded = jwt.verify(token, WEB_CONFIG.JWT_SECRET);
            if (decoded.role === 'superadmin') {
                req.user = decoded;
                return next();
            }
        } catch(e) {}
    }

    return res.status(401).json({
        success: false,
        error: 'Accès interne non autorisé',
        code: 'INTERNAL_ACCESS_DENIED'
    });
}

function requireEmailVerification(req, res, next) {
    if (process.env.NODE_ENV !== 'production') return next();
    const userId = req.user.userId;
    db.get('SELECT email_verified FROM users WHERE id = ?', [userId], (err, row) => {
        if (err || !row) {
            return res.status(403).json({
                success: false,
                error: 'Utilisateur non trouvé',
                code: 'USER_NOT_FOUND'
            });
        }
        if (!row.email_verified) {
            return res.status(403).json({
                success: false,
                error: 'Email non vérifié',
                code: 'EMAIL_NOT_VERIFIED'
            });
        }
        next();
    });
}

function requireAdmin(req, res, next) {
    const userId = req.user.userId;
    db.get('SELECT role FROM users WHERE id = ?', [userId], (err, row) => {
        if (err || !row || (row.role !== 'admin' && row.role !== 'superadmin')) {
            return res.status(403).json({
                success: false,
                error: 'Droits administrateur requis',
                code: 'ADMIN_REQUIRED'
            });
        }
        next();
    });
}

function requireSuperAdmin(req, res, next) {
    const userId = req.user.userId;
    db.get('SELECT role FROM users WHERE id = ?', [userId], (err, row) => {
        if (err || !row || row.role !== 'superadmin') {
            return res.status(403).json({
                success: false,
                error: 'Droits superadmin requis',
                code: 'SUPERADMIN_REQUIRED'
            });
        }
        next();
    });
}

function logApiCall(req, res, next) {
    if (req.user) {
        const userId = req.user.userId;
        const endpoint = req.originalUrl;
        const method = req.method;
        const ip = req.ip;

        db.run(
            'INSERT INTO api_logs (user_id, endpoint, method, ip) VALUES (?, ?, ?, ?)',
            [userId, endpoint, method, ip]
        );
    }
    next();
}

function checkApiRateLimit(req, res, next) {
    // Rate limiting interne désactivé — aucune restriction pour les utilisateurs du dashboard
    // Le rate limiting IP global (express-rate-limit) protège contre les abus externes
    next();
}

// =============================================
// FONCTIONS PTERODACTYL
// =============================================

async function callPterodactylAPI(endpoint, method = 'GET', data = null) {
    const url = `${PTERODACTYL_CONFIG.url}${endpoint}`;
    const options = {
        method,
        headers: {
            'Authorization': `Bearer ${PTERODACTYL_CONFIG.applicationApiKey}`,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    };
    if (data) options.body = JSON.stringify(data);

    try {
        const response = await fetch(url, options);
        const text = await response.text();
        let body;
        try { body = text ? JSON.parse(text) : null; } catch (e) { body = text; }

        if (!response.ok) {
            throw new Error(`Pterodactyl API error: ${response.status} - ${JSON.stringify(body)}`);
        }
        return body;
    } catch (error) {
        console.error('❌ Erreur API Pterodactyl:', error);
        throw error;
    }
}

async function callPterodactylClientAPI(endpoint, method = 'GET', data = null) {
    const url = `${PTERODACTYL_CONFIG.url}${endpoint}`;
    const options = {
        method,
        headers: {
            'Authorization': `Bearer ${PTERODACTYL_CONFIG.clientApiKey}`,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    };
    if (data) options.body = JSON.stringify(data);

    try {
        const response = await fetch(url, options);
        const text = await response.text();
        let body;
        try { body = text ? JSON.parse(text) : null; } catch (e) { body = text; }

        if (!response.ok) {
            throw new Error(`Pterodactyl Client API error: ${response.status} - ${JSON.stringify(body)}`);
        }
        return body;
    } catch (error) {
        console.error('❌ Erreur Client API Pterodactyl:', error);
        throw error;
    }
}

// =============================================
// REMPLACE la fonction uploadZipToPterodactyl
// dans ton index.js par celle-ci :
// =============================================

async function waitForServerOnline(serverIdentifier, maxWaitMs = 60000) {
    const interval = 4000;
    let waited = 0;
    while (waited < maxWaitMs) {
        const st = await getServerPowerStatus(serverIdentifier);
        if (st.status === 'running') return true;
        await new Promise(r => setTimeout(r, interval));
        waited += interval;
    }
    return false;
}

function buildZipFromDir(sourceDir, outputPath) {
    const zip = new AdmZip();
    function addDir(dirPath, zipBase) {
        const entries = fs.readdirSync(dirPath, { withFileTypes: true });
        for (const entry of entries) {
            if (entry.name === 'node_modules' || entry.name === '.git') continue;
            const fullPath = path.join(dirPath, entry.name);
            if (entry.isDirectory()) {
                addDir(fullPath, zipBase ? `${zipBase}/${entry.name}` : entry.name);
            } else {
                zip.addLocalFile(fullPath, zipBase || '');
            }
        }
    }
    addDir(sourceDir, '');
    zip.writeZip(outputPath);
}

async function cleanServerFiles(serverIdentifier) {
    try {
        const listResp = await callPterodactylClientAPI(
            `/api/client/servers/${serverIdentifier}/files/list?directory=%2F`
        );
        const items = (listResp?.data || []).map(f => f.attributes?.name).filter(Boolean);
        const toDelete = items.filter(name => name !== '.env' && name !== '.npm');
        if (toDelete.length === 0) return;
        await callPterodactylClientAPI(
            `/api/client/servers/${serverIdentifier}/files/delete`,
            'POST',
            { root: '/', files: toDelete }
        );
        console.log(`🗑️ Anciens fichiers supprimés: ${toDelete.join(', ')}`);
    } catch (e) {
        console.warn(`⚠️ Nettoyage serveur ignoré: ${e.message}`);
    }
}

async function uploadZipToPterodactyl(serverIdentifier, zipPath) {
// Étape 1 : Obtenir l’URL signée (avec axios au lieu de fetch)
console.log(`🔄 Obtention URL d'upload pour ${serverIdentifier}...`);

const uploadUrlResponse = await axios.get(
    `${PTERODACTYL_CONFIG.url}/api/client/servers/${serverIdentifier}/files/upload`,
    {
        headers: {
            'Authorization': `Bearer ${PTERODACTYL_CONFIG.clientApiKey}`,
            'Accept': 'application/json',
        },
        httpsAgent: new https.Agent({ rejectUnauthorized: false })
    }
);

const signedUrl = uploadUrlResponse.data?.attributes?.url;

if (!signedUrl) {
    throw new Error(`URL signée non trouvée: ${JSON.stringify(uploadUrlResponse.data)}`);
}

console.log(`✅ URL signée obtenue pour ${serverIdentifier}`);
console.log(`📤 Upload vers: ${signedUrl.substring(0, 80)}...`);

// Étape 2 : Uploader le ZIP via FormData avec axios (pas fetch)
const FormData = (await import('form-data')).default;
const form = new FormData();
const zipBuffer = fs.readFileSync(zipPath);
const filename = path.basename(zipPath);

form.append('files', zipBuffer, {
    filename: filename,
    contentType: 'application/zip',
    knownLength: zipBuffer.length
});

const uploadResponse = await axios.post(signedUrl, form, {
    headers: {
        ...form.getHeaders(),
    },
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    maxContentLength: Infinity,
    maxBodyLength: Infinity,
    timeout: 120000, // 2 minutes
});

console.log(`✅ ZIP uploadé avec succès vers ${serverIdentifier} (status: ${uploadResponse.status})`);

// Étape 3 : Décompresser le ZIP sur le serveur (API Pterodactyl)
await new Promise(resolve => setTimeout(resolve, 2000)); // attendre que le fichier soit dispo

try {
    console.log(`📂 Décompression du ZIP sur le serveur...`);
    await callPterodactylClientAPI(
        `/api/client/servers/${serverIdentifier}/files/decompress`,
        'POST',
        {
            root: '/',
            file: filename
        }
    );
    console.log(`✅ ZIP décompressé avec succès`);
    
    // Supprimer le ZIP après extraction
    await new Promise(resolve => setTimeout(resolve, 3000));
    try {
        await callPterodactylClientAPI(
            `/api/client/servers/${serverIdentifier}/files/delete`,
            'POST',
            { root: '/', files: [filename] }
        );
        console.log(`🗑️ ZIP supprimé après extraction`);
    } catch(e) {
        console.log(`⚠️ Impossible de supprimer le ZIP: ${e.message}`);
    }
} catch (decompressErr) {
    console.error(`⚠️ Erreur décompression: ${decompressErr.message}`);
    // Ne pas throw ici, le fichier est quand même uploadé
}

return true;

}

async function saveSnapshot(serverIdentifier, deploymentId) {
    try {
        const snapshotPath = `/tmp/snapshot-${deploymentId}-${Date.now()}.zip`;
        const files = await callPterodactylClientAPI(
            `/api/client/servers/${serverIdentifier}/files/list?directory=/`
        );
        
        const zip = new AdmZip();
        for (const file of files.data || []) {
            if (!file.is_file) continue;
            const content = await callPterodactylClientAPI(
                `/api/client/servers/${serverIdentifier}/files/contents?file=/${file.name}`
            );
            zip.addFile(file.name, Buffer.from(content, 'utf8'));
        }
        zip.writeZip(snapshotPath);
        
        db.run(
            'INSERT INTO deployment_snapshots (deployment_id, snapshot_path) VALUES (?, ?)',
            [deploymentId, snapshotPath]
        );
        
        return snapshotPath;
    } catch (error) {
        console.error('❌ Erreur sauvegarde snapshot:', error);
    }
}

async function createPterodactylUser(username = null, userId = null) {
    try {
        const maxRetries = 3;
        let retries = 0;
        
        while (retries < maxRetries) {
            let finalUsername;
            
            if (retries === 0) {
                finalUsername = username ? 
                    username.replace(/[^a-z0-9]/g, '').toLowerCase().slice(0, 10) + 
                    Math.floor(Math.random() * 10000) : 
                    'user' + Math.floor(Math.random() * 1000000);
            } else {
                finalUsername = 'user' + Date.now() + Math.floor(Math.random() * 1000);
            }
            
            const email = userId ? `user${userId}@flyhost.local` : `${finalUsername}@flyhost.local`;
            const password = crypto.randomBytes(8).toString('hex');

            const payload = {
                username: finalUsername,
                email: email,
                first_name: finalUsername.slice(0, 10),
                last_name: 'FLYHOST',
                password: password,
                root_admin: false,
                language: 'en'
            };

            try {
                const result = await callPterodactylAPI('/api/application/users', 'POST', payload);

                if (result.errors) {
                    retries++;
                    continue;
                }

                return {
                    id: result.attributes.id,
                    username: result.attributes.username,
                    email: result.attributes.email,
                    password: password
                };
                
            } catch (error) {
                retries++;
                if (retries >= maxRetries) throw error;
            }
        }
        
        throw new Error('Impossible de créer un utilisateur');
    } catch (error) {
        console.error('❌ Erreur création utilisateur Pterodactyl:', error);
        throw error;
    }
}

async function createPterodactylServer(serverData) {
    try {
        const {
            name,
            userId,
            eggId,
            env_type = 'nodejs',
            memory,
            disk,
            cpu,
            locationId = 1
        } = serverData;

        // Résoudre la config tech en fonction de env_type
        const techCfg = TECH_ENVIRONMENTS[env_type] || TECH_ENVIRONMENTS.nodejs;
        const { startup: techStartup, env: techEnv, docker_image: techDockerOverride, egg: techEggOverride } = buildStartupCommand(env_type, techCfg.default_start, techCfg.default_build);
        const resolvedEgg = eggId || techEggOverride || techCfg.egg;
        const resolvedDockerImage = techDockerOverride || techCfg.docker_image;

        const payload = {
            name: name,
            description: 'FLYHOST Server',
            user: parseInt(userId),
            egg: parseInt(resolvedEgg),
            docker_image: resolvedDockerImage,
            startup: techStartup,
            environment: { INST: 'FLYHOST', ...techEnv },

            limits: {
                memory: parseInt(memory),
                swap: 0,
                disk: parseInt(disk),
                io: 500,
                cpu: parseInt(cpu)
            },

            feature_limits: {
                databases: 5,
                backups: 5,
                allocations: 1
            },

            deploy: {
                locations: [parseInt(locationId)],
                dedicated_ip: false,
                port_range: []
            }
        };

        const result = await callPterodactylAPI('/api/application/servers', 'POST', payload);

        if (result.errors) {
            throw new Error(result.errors[0]?.detail || JSON.stringify(result.errors));
        }

        const serverId = result.attributes.id;

        // Patch startup command to ensure the correct one is used (egg default may override)
        try {
            await callPterodactylAPI(`/api/application/servers/${serverId}/startup`, 'PATCH', {
                startup: techStartup,
                environment: techEnv,
                egg: parseInt(resolvedEgg),
                image: techCfg.docker_image,
                skip_scripts: false
            });
            console.log(`✅ Startup command patché pour ${techCfg.name} (egg ${resolvedEgg})`);
        } catch (patchErr) {
            console.warn(`⚠️ Impossible de patcher le startup: ${patchErr.message}`);
        }

        // Récupérer le port alloué depuis l'API application
        let alloc_port = null;
        let alloc_ip = null;
        try {
            const serverDetails = await callPterodactylAPI(`/api/application/servers/${serverId}?include=allocations`);
            const allocData = serverDetails.attributes?.relationships?.allocations?.data || [];
            const primary = allocData.find(a => a.attributes?.is_default) || allocData[0];
            if (primary) {
                alloc_port = primary.attributes.port;
                alloc_ip = primary.attributes.ip || '0.0.0.0';
            }
        } catch (allocErr) {
            console.warn(`⚠️ Impossible de récupérer le port d'allocation: ${allocErr.message}`);
        }

        return {
            id: result.attributes.id,
            uuid: result.attributes.uuid,
            identifier: result.attributes.identifier,
            name: result.attributes.name,
            alloc_port,
            alloc_ip
        };

    } catch (error) {
        console.error('❌ Erreur création serveur Pterodactyl:', error);
        throw error;
    }
}

async function deletePterodactylServer(serverId) {
    try {
        if (!serverId) return true;
        await callPterodactylAPI(`/api/application/servers/${serverId}`, 'DELETE');
        return true;
    } catch (error) {
        if (error.message.includes('404')) return true;
        console.error('❌ Erreur suppression serveur:', error);
        return false;
    }
}

async function getServerPowerStatus(serverIdentifier) {
    try {
        // ✅ Vérifier que serverIdentifier est valide
        if (!serverIdentifier || serverIdentifier.length < 5) {
            console.warn(`⚠️ Identifiant de serveur invalide: ${serverIdentifier}`);
            return { status: 'unknown', raw_status: 'invalid', resources: null };
        }
        
        const data = await callPterodactylClientAPI(
            `/api/client/servers/${serverIdentifier}/resources`
        );
        
        // Statuts possibles: 'running', 'starting', 'stopping', 'offline', 
        // 'installing', 'install-failed', 'suspended', 'restoring-backup'
        const rawStatus = data.attributes.current_state;
        
        // ✅ Normalisation des statuts
        let normalizedStatus;
        switch(rawStatus) {
            case 'running':
            case 'starting':
                normalizedStatus = 'running';
                break;
            case 'offline':
            case 'stopped':
            case 'stopping':
                normalizedStatus = 'stopped';
                break;
            case 'installing':
                normalizedStatus = 'installing';
                break;
            case 'install-failed':
            case 'suspended':
                normalizedStatus = 'error';
                break;
            default:
                normalizedStatus = 'unknown';
        }
        
        // Formatage des ressources
        const resources = data.attributes.resources ? {
            cpu: parseFloat(data.attributes.resources.cpu_absolute || 0),
            memory: data.attributes.resources.memory_bytes || 0,
            disk: data.attributes.resources.disk_bytes || 0,
            uptime: data.attributes.resources.uptime || 0
        } : null;
        
        return {
            status: normalizedStatus,
            raw_status: rawStatus,
            resources: resources
        };
    } catch (error) {
        console.error(`❌ Erreur récupération statut pour ${serverIdentifier}:`, error.message);
        return { 
            status: 'unknown', 
            raw_status: 'error', 
            resources: null,
            error: error.message
        };
    }
}

async function sendPowerAction(serverIdentifier, action) {
    try {
        console.log(`📤 Envoi action ${action} à ${serverIdentifier}`);
        
        // ✅ Vérifier que l'action est valide pour Pterodactyl
        const validActions = ['start', 'stop', 'restart', 'kill'];
        if (!validActions.includes(action)) {
            throw new Error(`Action invalide: ${action}`);
        }
        
        // ✅ Appel à l'API Pterodactyl
        await callPterodactylClientAPI(
            `/api/client/servers/${serverIdentifier}/power`,
            'POST',
            { signal: action }
        );
        
        console.log(`✅ Action ${action} envoyée avec succès à ${serverIdentifier}`);
        return true;
    } catch (error) {
        console.error(`❌ Erreur action power ${action} pour ${serverIdentifier}:`, error.message);
        
        // ✅ Analyser l'erreur pour un meilleur diagnostic
        if (error.message.includes('404')) {
            console.error(`❌ Serveur ${serverIdentifier} non trouvé sur Pterodactyl`);
        } else if (error.message.includes('403')) {
            console.error(`❌ Permission refusée pour ${serverIdentifier}`);
        }
        
        return false;
    }
}

async function getServerAllocations(serverId) {
    try {
        const data = await callPterodactylAPI(`/api/application/servers/${serverId}/allocations`);
        return data.data.map(a => a.attributes);
    } catch (error) {
        console.error('❌ Erreur récupération allocations:', error);
        return [];
    }
}

async function getServerByIdAndUser(serverId, userId) {
    return new Promise((resolve) => {
        db.get('SELECT * FROM servers WHERE id = ? AND user_id = ?', [serverId, userId], (err, row) => {
            resolve(row || null);
        });
    });
}

function execAsync(command) {
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
            if (error) {
                reject(error);
            } else {
                resolve({ stdout, stderr });
            }
        });
    });
}

async function logDeployment(deploymentId, serverId, level, message) {
    await new Promise((resolve) => {
        db.run(
            'UPDATE deployments SET build_log = build_log || ? WHERE id = ?',
            [message + '\n', deploymentId],
            resolve
        );
    });
    
    if (global.broadcastLog) {
        global.broadcastLog(serverId, { level, message });
    }
}

// =============================================
// FONCTIONS DE DÉPLOIEMENT
// =============================================

/**
 * Détecte si le serveur est configuré avec le mauvais environnement et le corrige automatiquement.
 * Appelé au début de chaque déploiement ZIP/GitHub.
 */
async function autoSwitchEnvironment({ deploymentId, serverId, pterodactylId, detectedTech, extractedDir }) {
    const server = await new Promise(r => db.get('SELECT env_type FROM servers WHERE id = ?', [serverId], (e, row) => r(row)));
    const currentTech = server?.env_type || 'nodejs';

    if (currentTech === detectedTech) return; // Rien à faire

    await logDeployment(deploymentId, serverId, 'warn',
        `⚠️ Mauvais environnement détecté ! Serveur configuré en "${currentTech}" mais le projet est en "${detectedTech}". Correction automatique en cours...`
    );

    // Construire la bonne commande de démarrage selon la technologie détectée
    let startCmd = '';
    let builtStartup = '';
    let builtEnv = {};
    let builtEggOverride = null;
    let builtImgOverride = null;

    if (detectedTech === 'python') {
        // Détecter uvicorn vs flask vs plain python
        let usesUvicorn = false, usesFlask = false;
        let entryFile = 'main.py';

        if (extractedDir) {
            // Chercher requirements.txt pour détecter uvicorn/flask
            const reqPath = ['requirements.txt', 'backend/requirements.txt', 'server/requirements.txt']
                .map(p => path.join(extractedDir, p)).find(p => { try { return require('fs').statSync(p).isFile(); } catch(_) { return false; } });
            if (reqPath) {
                const reqContent = require('fs').readFileSync(reqPath, 'utf8').toLowerCase();
                usesUvicorn = reqContent.includes('uvicorn') || reqContent.includes('fastapi');
                usesFlask = reqContent.includes('flask') || reqContent.includes('gunicorn');
            }

            // Trouver le fichier d'entrée Python
            const pythonCandidates = [
                'backend/server.py','backend/app.py','backend/main.py',
                'server/server.py','server/app.py','server/main.py',
                'app.py','server.py','main.py','run.py','start.py'
            ];
            const fs = require('fs');
            const found = pythonCandidates.find(c => { try { return fs.statSync(path.join(extractedDir, c)).isFile(); } catch(_) { return false; } });
            if (found) entryFile = found;
        }

        const techCfg = TECH_ENVIRONMENTS.python;
        // Commande pip unifiée : python3 -m pip (car pip3/pip absents de l'image Node.js yolks)
        const _reqDir = entryFile.includes('/') ? entryFile.split('/').slice(0,-1).join('/') + '/' : '';
        const _pipCmd = `python3 -m ensurepip --upgrade 2>/dev/null || true; python3 -m pip install -r ${_reqDir}requirements.txt --quiet 2>&1 || true`;
        if (usesUvicorn) {
            // Déduire le module uvicorn depuis le chemin du fichier
            const module = entryFile.replace(/\//g, '.').replace(/\.py$/, '') + ':app';
            builtStartup = `cd /home/container && ${_pipCmd}; python -m uvicorn ${module} --host 0.0.0.0 --port \${SERVER_PORT:-8080}`;
            startCmd = `uvicorn ${module}`;
        } else if (usesFlask) {
            builtStartup = `cd /home/container && ${_pipCmd}; python3 /home/container/${entryFile}`;
            startCmd = `python ${entryFile}`;
        } else {
            builtStartup = techCfg.startup;
            startCmd = `python ${entryFile}`;
        }
        builtEnv = { ...techCfg.env, PY_FILE: entryFile, REQUIREMENTS_FILE: 'requirements.txt', PY_PACKAGES: '' };

    } else if (detectedTech === 'php') {
        // Détecter le doc root : public/ pour Laravel/Symfony, sinon racine
        let phpDocRoot = '.';
        if (extractedDir) {
            const _fs = require('fs');
            const publicCandidates = ['public/index.php', 'public_html/index.php', 'web/index.php', 'www/index.php'];
            if (publicCandidates.some(c => { try { return _fs.statSync(path.join(extractedDir, c)).isFile(); } catch(_) { return false; } })) {
                phpDocRoot = publicCandidates.find(c => { try { return _fs.statSync(path.join(extractedDir, c)).isFile(); } catch(_) { return false; } }).split('/')[0];
            }
        }
        const { startup, env, egg: _eggOvr, docker_image: _imgOvr } = buildStartupCommand(detectedTech, phpDocRoot === '.' ? '' : `php -S 0.0.0.0:\${SERVER_PORT} -t ${phpDocRoot}`, '');
        builtStartup = startup;
        builtEnv = { ...env, DOCUMENT_ROOT: phpDocRoot };
        if (_eggOvr) builtEggOverride = _eggOvr;
        if (_imgOvr) builtImgOverride = _imgOvr;
    } else {
        const { startup, env, egg: _eggOvr, docker_image: _imgOvr } = buildStartupCommand(detectedTech, '', '');
        builtStartup = startup;
        builtEnv = env;
        if (_eggOvr) builtEggOverride = _eggOvr;
        if (_imgOvr) builtImgOverride = _imgOvr;
    }

    const techCfg = TECH_ENVIRONMENTS[detectedTech] || TECH_ENVIRONMENTS.nodejs;

    // Mettre à jour Pterodactyl
    try {
        await callPterodactylAPI(`/api/application/servers/${pterodactylId}/startup`, 'PATCH', {
            startup: builtStartup,
            environment: builtEnv,
            egg: builtEggOverride || techCfg.egg,
            image: builtImgOverride || techCfg.docker_image,
            skip_scripts: false
        });
        await logDeployment(deploymentId, serverId, 'success',
            `✅ Environnement mis à jour : "${currentTech}" → "${detectedTech}" (egg #${techCfg.egg})`
        );
    } catch (e) {
        await logDeployment(deploymentId, serverId, 'warn', `⚠️ Mise à jour Pterodactyl échouée: ${e.message}`);
    }

    // Mettre à jour la DB
    await new Promise(r => db.run('UPDATE servers SET env_type = ? WHERE id = ?', [detectedTech, serverId], r));
}

async function deployFromGitHub({ deploymentId, serverId, serverIdentifier, pterodactylId, repoUrl, branch, envVars, flyhostConfig, accessToken }) {
const tmpDir = `/tmp/flyhost-deploy-${deploymentId}`;

try {
    await saveSnapshot(serverIdentifier, deploymentId);
    
    await logDeployment(deploymentId, serverId, 'info', `🚀 Déploiement GitHub démarré (branche: ${branch})`);
    
    fs.mkdirSync(tmpDir, { recursive: true });
    
    let cloneUrl = repoUrl;
    if (accessToken) {
        const match = repoUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
        if (match) {
            const [, owner, repoName] = match;
            cloneUrl = `https://${accessToken}@github.com/${owner}/${repoName.replace(/\.git$/, '')}.git`;
        }
    }
    
    await logDeployment(deploymentId, serverId, 'info', `📦 Clonage du dépôt...`);
    await execAsync(`git clone --branch ${branch} --depth 1 ${cloneUrl} ${tmpDir}`);
    
    const { stdout } = await execAsync(`cd ${tmpDir} && git rev-parse --short HEAD`);
    const commitHash = stdout.trim();
    await new Promise((resolve) => {
        db.run('UPDATE deployments SET git_commit = ? WHERE id = ?', [commitHash, deploymentId], resolve);
    });
    await logDeployment(deploymentId, serverId, 'info', `📌 Commit: ${commitHash}`);
    
    const envContent = Object.entries(envVars).map(([key, value]) => `${key}=${value}`).join('\n');
    fs.writeFileSync(path.join(tmpDir, '.env'), envContent);
    
    const { stdout: sizeOutput } = await execAsync(`du -sm ${tmpDir} | cut -f1`);
    const sizeMB = parseInt(sizeOutput.trim());
    if (sizeMB > MAX_DEPLOY_SIZE_MB) {
        throw new Error(`Projet trop volumineux: ${sizeMB} MB (max ${MAX_DEPLOY_SIZE_MB} MB)`);
    }
    
    await logDeployment(deploymentId, serverId, 'info', `📦 Création du ZIP...`);
    const zipOutput = `${tmpDir}.zip`;
    buildZipFromDir(tmpDir, zipOutput);

    await logDeployment(deploymentId, serverId, 'info', `🧹 Nettoyage des anciens fichiers...`);
    await cleanServerFiles(serverIdentifier);
    await logDeployment(deploymentId, serverId, 'info', `📤 Upload du ZIP vers Pterodactyl...`);
    await uploadZipToPterodactyl(serverIdentifier, zipOutput);
    await logDeployment(deploymentId, serverId, 'info', `📂 Extraction automatique sur le serveur...`);

    // Auto-correction environnement si mismatch entre serveur et projet détecté
    const _techType = flyhostConfig?.env_type || flyhostConfig?.runtime || 'nodejs';
    await autoSwitchEnvironment({ deploymentId, serverId, pterodactylId, detectedTech: _techType, extractedDir: tmpDir });
    const _techCfg = TECH_ENVIRONMENTS[_techType] || TECH_ENVIRONMENTS.nodejs;

    if (pterodactylId && flyhostConfig.start) {
        const { startup: builtStartup, env: builtEnv, egg: _eggOvr2, docker_image: _imgOvr2 } = buildStartupCommand(_techType, flyhostConfig.start, flyhostConfig.build);
        try {
            await callPterodactylAPI(`/api/application/servers/${pterodactylId}/startup`, 'PATCH', {
                startup: builtStartup,
                environment: builtEnv,
                egg: _eggOvr2 || _techCfg.egg, image: _imgOvr2 || _techCfg.docker_image, skip_scripts: false
            });
            await logDeployment(deploymentId, serverId, 'info', `⚙️ Démarrage configuré: ${flyhostConfig.start}`);
        } catch (e) {
            await logDeployment(deploymentId, serverId, 'warn', `⚠️ Config startup ignorée: ${e.message}`);
        }
    }
    
    // Build (npm install etc.) - nécessite que le serveur soit ON
    if (flyhostConfig.build && flyhostConfig.build.trim() !== '') {
        await logDeployment(deploymentId, serverId, 'info', `🔨 Démarrage du serveur pour le build...`);
        
        const statusBefore = await getServerPowerStatus(serverIdentifier);
        if (statusBefore.status !== 'running') {
            await sendPowerAction(serverIdentifier, 'start');
        }

        const online = await waitForServerOnline(serverIdentifier, 60000);
        if (!online) {
            await logDeployment(deploymentId, serverId, 'warn', `⚠️ Serveur non démarré après 60s — build ignoré`);
        } else {
            await logDeployment(deploymentId, serverId, 'info', `🔨 Build: ${flyhostConfig.build}`);
            try {
                await callPterodactylClientAPI(
                    `/api/client/servers/${serverIdentifier}/command`,
                    'POST',
                    { command: flyhostConfig.build }
                );
                await logDeployment(deploymentId, serverId, 'success', `✅ Build terminé`);
                await new Promise(resolve => setTimeout(resolve, 5000));
            } catch (err) {
                await logDeployment(deploymentId, serverId, 'error', `❌ Erreur build: ${err.message}`);
            }
        }
    }
    
    // Démarrer ou redémarrer selon l'état actuel
    await logDeployment(deploymentId, serverId, 'info', `🔄 Démarrage du serveur...`);
    try {
        const currentStatus = await getServerPowerStatus(serverIdentifier);
        if (currentStatus.status === 'running') {
            await sendPowerAction(serverIdentifier, 'restart');
        } else {
            await sendPowerAction(serverIdentifier, 'start');
        }
    } catch (startErr) {
        await logDeployment(deploymentId, serverId, 'warn', `⚠️ Impossible de démarrer le serveur: ${startErr.message}`);
    }
    
    await new Promise((resolve) => {
        db.run(
            'UPDATE deployments SET status = "deployed", last_deployed = CURRENT_TIMESTAMP WHERE id = ?',
            [deploymentId],
            resolve
        );
    });
    await new Promise((resolve) => {
        db.run('UPDATE servers SET server_status = "stopped" WHERE id = ?', [serverId], resolve);
    });
    
    await logDeployment(deploymentId, serverId, 'success', `✅ Fichiers déployés avec succès ! Démarrez le serveur manuellement si nécessaire.`);
    if (global.broadcastDeployStatus) {
        global.broadcastDeployStatus(serverId, 'success', 'Déploiement terminé !');
    }
    
} catch (error) {
    await logDeployment(deploymentId, serverId, 'error', `❌ Erreur: ${error.message}`);
    await new Promise((resolve) => {
        db.run('UPDATE deployments SET status = "failed" WHERE id = ?', [deploymentId], resolve);
    });
    if (global.broadcastDeployFailed) {
        await global.broadcastDeployFailed(serverId, deploymentId, error.message, typeof _techType !== 'undefined' ? _techType : 'nodejs');
    }
} finally {
    try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
        fs.rmSync(`${tmpDir}.zip`, { force: true });
    } catch (e) {
        console.error('Erreur nettoyage:', e);
    }
}

}

async function deployFromZip({ deploymentId, serverId, serverIdentifier, pterodactylId, zipPath, envVars, flyhostConfig }) {
const tmpDir = `/tmp/flyhost-deploy-${deploymentId}`;

try {
    await saveSnapshot(serverIdentifier, deploymentId);
    
    await logDeployment(deploymentId, serverId, 'info', `📦 Déploiement ZIP démarré`);
    
    fs.mkdirSync(tmpDir, { recursive: true });
    
    const zip = new AdmZip(zipPath);
    zip.extractAllTo(tmpDir, true);
    await logDeployment(deploymentId, serverId, 'success', `✅ Archive extraite`);

    // Aplatir le ZIP si tous les fichiers sont dans un sous-dossier unique (ex: "hackeur MD/")
    const topItems = fs.readdirSync(tmpDir);
    if (topItems.length === 1) {
        const singleItem = path.join(tmpDir, topItems[0]);
        const stat = fs.statSync(singleItem);
        if (stat.isDirectory()) {
            await logDeployment(deploymentId, serverId, 'info', `📁 Sous-dossier "${topItems[0]}" détecté — mise à plat automatique`);
            const innerItems = fs.readdirSync(singleItem);
            for (const item of innerItems) {
                fs.renameSync(path.join(singleItem, item), path.join(tmpDir, item));
            }
            fs.rmdirSync(singleItem);
        }
    }

    // Supprimer node_modules du ZIP uploadé — binaires natifs incompatibles (ex: sharp compilé sur Windows/Mac)
    // npm install s'exécutera sur le serveur Linux et recompilera tout correctement
    const nodeModulesDir = path.join(tmpDir, 'node_modules');
    if (fs.existsSync(nodeModulesDir)) {
        await logDeployment(deploymentId, serverId, 'info', `🗑️ Suppression de node_modules (sera réinstallé nativement sur le serveur)...`);
        fs.rmSync(nodeModulesDir, { recursive: true, force: true });
    }
    for (const lockFile of ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']) {
        const lp = path.join(tmpDir, lockFile);
        if (fs.existsSync(lp)) fs.unlinkSync(lp);
    }

    const envContent = Object.entries(envVars).map(([key, value]) => `${key}=${value}`).join('\n');
    fs.writeFileSync(path.join(tmpDir, '.env'), envContent);
    
    const { stdout: sizeOutput } = await execAsync(`du -sm ${tmpDir} | cut -f1`);
    const sizeMB = parseInt(sizeOutput.trim());
    if (sizeMB > MAX_DEPLOY_SIZE_MB) {
        throw new Error(`Projet trop volumineux: ${sizeMB} MB (max ${MAX_DEPLOY_SIZE_MB} MB)`);
    }
    
    await logDeployment(deploymentId, serverId, 'info', `📦 Création du ZIP...`);
    const zipOutput = `${tmpDir}.zip`;
    buildZipFromDir(tmpDir, zipOutput);

    await logDeployment(deploymentId, serverId, 'info', `🧹 Nettoyage des anciens fichiers...`);
    await cleanServerFiles(serverIdentifier);
    await logDeployment(deploymentId, serverId, 'info', `📤 Upload du ZIP vers Pterodactyl...`);
    await uploadZipToPterodactyl(serverIdentifier, zipOutput);
    await logDeployment(deploymentId, serverId, 'info', `📂 Extraction automatique sur le serveur...`);

    // Auto-correction environnement si mismatch entre serveur et projet détecté
    const _techType = flyhostConfig?.env_type || flyhostConfig?.runtime || 'nodejs';

    // Pour PHP : détection du doc root avant de construire le startup
    if (_techType === 'php') {
        const _phpPublicCandidates = ['public/index.php','public_html/index.php','web/index.php','www/index.php'];
        const _phpDocRoot = _phpPublicCandidates.find(c => { try { return fs.statSync(path.join(tmpDir, c)).isFile(); } catch(_) { return false; } })?.split('/')[0] || '.';
        if (_phpDocRoot !== '.') {
            flyhostConfig.start = `php -S 0.0.0.0:\${SERVER_PORT} -t ${_phpDocRoot}`;
            await logDeployment(deploymentId, serverId, 'info', `🐘 PHP: doc root → "${_phpDocRoot}/" (public/index.php détecté)`);
        } else if (!flyhostConfig.start || flyhostConfig.start === 'php -S 0.0.0.0:${SERVER_PORT}') {
            flyhostConfig.start = 'php -S 0.0.0.0:${SERVER_PORT} -t .';
        }
    }

    await autoSwitchEnvironment({ deploymentId, serverId, pterodactylId, detectedTech: _techType, extractedDir: tmpDir });
    const _techCfg = TECH_ENVIRONMENTS[_techType] || TECH_ENVIRONMENTS.nodejs;

    if (pterodactylId && flyhostConfig.start) {
        const { startup: builtStartup, env: builtEnv, egg: _eggOvr3, docker_image: _imgOvr3 } = buildStartupCommand(_techType, flyhostConfig.start, flyhostConfig.build);
        try {
            await callPterodactylAPI(`/api/application/servers/${pterodactylId}/startup`, 'PATCH', {
                startup: builtStartup,
                environment: builtEnv,
                egg: _eggOvr3 || _techCfg.egg, image: _imgOvr3 || _techCfg.docker_image, skip_scripts: false
            });
            await logDeployment(deploymentId, serverId, 'info', `⚙️ Démarrage configuré: ${flyhostConfig.start}`);
        } catch (e) {
            await logDeployment(deploymentId, serverId, 'warn', `⚠️ Config startup ignorée: ${e.message}`);
        }
    }
    
    // Build - nécessite que le serveur soit ON
    if (flyhostConfig.build && flyhostConfig.build.trim() !== '') {
        await logDeployment(deploymentId, serverId, 'info', `🔨 Démarrage du serveur pour le build...`);

        const statusBefore = await getServerPowerStatus(serverIdentifier);
        if (statusBefore.status !== 'running') {
            await sendPowerAction(serverIdentifier, 'start');
        }

        const online = await waitForServerOnline(serverIdentifier, 60000);
        if (!online) {
            await logDeployment(deploymentId, serverId, 'warn', `⚠️ Serveur non démarré après 60s — build ignoré`);
        } else {
            await logDeployment(deploymentId, serverId, 'info', `🔨 Build: ${flyhostConfig.build}`);
            try {
                await callPterodactylClientAPI(
                    `/api/client/servers/${serverIdentifier}/command`,
                    'POST',
                    { command: flyhostConfig.build }
                );
                await logDeployment(deploymentId, serverId, 'success', `✅ Build terminé`);
                await new Promise(resolve => setTimeout(resolve, 5000));
            } catch (err) {
                await logDeployment(deploymentId, serverId, 'error', `❌ Erreur build: ${err.message}`);
            }
        }
    }
    
    // Démarrer ou redémarrer selon l'état actuel
    await logDeployment(deploymentId, serverId, 'info', `🔄 Démarrage du serveur...`);
    try {
        const currentStatus = await getServerPowerStatus(serverIdentifier);
        if (currentStatus.status === 'running') {
            await sendPowerAction(serverIdentifier, 'restart');
        } else {
            await sendPowerAction(serverIdentifier, 'start');
        }
    } catch (startErr) {
        await logDeployment(deploymentId, serverId, 'warn', `⚠️ Impossible de démarrer le serveur: ${startErr.message}`);
    }
    
    await new Promise((resolve) => {
        db.run(
            'UPDATE deployments SET status = "deployed", last_deployed = CURRENT_TIMESTAMP WHERE id = ?',
            [deploymentId],
            resolve
        );
    });
    await new Promise((resolve) => {
        db.run('UPDATE servers SET server_status = "stopped" WHERE id = ?', [serverId], resolve);
    });
    
    await logDeployment(deploymentId, serverId, 'success', `✅ Fichiers déployés avec succès ! Démarrez le serveur manuellement si nécessaire.`);
    if (global.broadcastDeployStatus) {
        global.broadcastDeployStatus(serverId, 'success', 'Déploiement ZIP terminé !');
    }
    
} catch (error) {
    await logDeployment(deploymentId, serverId, 'error', `❌ Erreur: ${error.message}`);
    await new Promise((resolve) => {
        db.run('UPDATE deployments SET status = "failed" WHERE id = ?', [deploymentId], resolve);
    });
    if (global.broadcastDeployStatus) {
        global.broadcastDeployStatus(serverId, 'failed', error.message);
    }
} finally {
    try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
        fs.rmSync(zipPath, { force: true });
    } catch (e) {
        console.error('Erreur nettoyage:', e);
    }
}

}

async function deployFromTemplate({ deploymentId, serverId, serverIdentifier, pterodactylId, templateUrl, envVars, flyhostConfig }) {
const tmpDir = `/tmp/flyhost-deploy-${deploymentId}`;

try {
    await saveSnapshot(serverIdentifier, deploymentId);
    
    await logDeployment(deploymentId, serverId, 'info', `📦 Déploiement Template démarré (${templateUrl})`);
    
    fs.mkdirSync(tmpDir, { recursive: true });
    
    const match = templateUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
    if (!match) {
        throw new Error('URL GitHub invalide');
    }
    
    const [, owner, repoName] = match;
    const cleanRepo = repoName.replace(/\.git$/, '');
    const branch = flyhostConfig.default_branch || 'main';
    
    await logDeployment(deploymentId, serverId, 'info', `📦 Clonage du template depuis ${owner}/${cleanRepo} (branche: ${branch})...`);
    await execAsync(`git clone --branch ${branch} --depth 1 https://github.com/${owner}/${cleanRepo}.git ${tmpDir}`);
    
    const { stdout } = await execAsync(`cd ${tmpDir} && git rev-parse --short HEAD`);
    const commitHash = stdout.trim();
    await new Promise((resolve) => {
        db.run('UPDATE deployments SET git_commit = ? WHERE id = ?', [commitHash, deploymentId], resolve);
    });
    await logDeployment(deploymentId, serverId, 'info', `📌 Commit: ${commitHash}`);
    
    const envContent = Object.entries(envVars).map(([key, value]) => `${key}=${value}`).join('\n');
    fs.writeFileSync(path.join(tmpDir, '.env'), envContent);
    
    const { stdout: sizeOutput } = await execAsync(`du -sm ${tmpDir} | cut -f1`);
    const sizeMB = parseInt(sizeOutput.trim());
    if (sizeMB > MAX_DEPLOY_SIZE_MB) {
        throw new Error(`Projet trop volumineux: ${sizeMB} MB (max ${MAX_DEPLOY_SIZE_MB} MB)`);
    }
    
    await logDeployment(deploymentId, serverId, 'info', `📦 Création du ZIP...`);
    const zipOutput = `${tmpDir}.zip`;
    buildZipFromDir(tmpDir, zipOutput);

    await logDeployment(deploymentId, serverId, 'info', `🧹 Nettoyage des anciens fichiers...`);
    await cleanServerFiles(serverIdentifier);
    await logDeployment(deploymentId, serverId, 'info', `📤 Upload du ZIP vers Pterodactyl...`);
    await uploadZipToPterodactyl(serverIdentifier, zipOutput);
    await logDeployment(deploymentId, serverId, 'info', `📂 Extraction automatique sur le serveur...`);

    // Auto-correction environnement si mismatch entre serveur et projet détecté
    const _techType = flyhostConfig?.env_type || flyhostConfig?.runtime || 'nodejs';

    // Pour PHP : détection du doc root avant de construire le startup
    if (_techType === 'php') {
        const _phpPublicCandidates = ['public/index.php','public_html/index.php','web/index.php','www/index.php'];
        const _phpDocRoot = _phpPublicCandidates.find(c => { try { return fs.statSync(path.join(tmpDir, c)).isFile(); } catch(_) { return false; } })?.split('/')[0] || '.';
        if (_phpDocRoot !== '.') {
            flyhostConfig.start = `php -S 0.0.0.0:\${SERVER_PORT} -t ${_phpDocRoot}`;
            await logDeployment(deploymentId, serverId, 'info', `🐘 PHP: doc root → "${_phpDocRoot}/" (public/index.php détecté)`);
        } else if (!flyhostConfig.start || flyhostConfig.start === 'php -S 0.0.0.0:${SERVER_PORT}') {
            flyhostConfig.start = 'php -S 0.0.0.0:${SERVER_PORT} -t .';
        }
    }

    await autoSwitchEnvironment({ deploymentId, serverId, pterodactylId, detectedTech: _techType, extractedDir: tmpDir });
    const _techCfg = TECH_ENVIRONMENTS[_techType] || TECH_ENVIRONMENTS.nodejs;

    if (pterodactylId && flyhostConfig.start) {
        const { startup: builtStartup, env: builtEnv, egg: _eggOvr3, docker_image: _imgOvr3 } = buildStartupCommand(_techType, flyhostConfig.start, flyhostConfig.build);
        try {
            await callPterodactylAPI(`/api/application/servers/${pterodactylId}/startup`, 'PATCH', {
                startup: builtStartup,
                environment: builtEnv,
                egg: _eggOvr3 || _techCfg.egg, image: _imgOvr3 || _techCfg.docker_image, skip_scripts: false
            });
            await logDeployment(deploymentId, serverId, 'info', `⚙️ Démarrage configuré: ${flyhostConfig.start}`);
        } catch (e) {
            await logDeployment(deploymentId, serverId, 'warn', `⚠️ Config startup ignorée: ${e.message}`);
        }
    }
    
    // Build - nécessite que le serveur soit ON
    if (flyhostConfig.build && flyhostConfig.build.trim() !== '') {
        await logDeployment(deploymentId, serverId, 'info', `🔨 Démarrage du serveur pour le build...`);

        const statusBefore = await getServerPowerStatus(serverIdentifier);
        if (statusBefore.status !== 'running') {
            await sendPowerAction(serverIdentifier, 'start');
        }

        const online = await waitForServerOnline(serverIdentifier, 60000);
        if (!online) {
            await logDeployment(deploymentId, serverId, 'warn', `⚠️ Serveur non démarré après 60s — build ignoré`);
        } else {
            await logDeployment(deploymentId, serverId, 'info', `🔨 Build: ${flyhostConfig.build}`);
            try {
                await callPterodactylClientAPI(
                    `/api/client/servers/${serverIdentifier}/command`,
                    'POST',
                    { command: flyhostConfig.build }
                );
                await logDeployment(deploymentId, serverId, 'success', `✅ Build terminé`);
                await new Promise(resolve => setTimeout(resolve, 5000));
            } catch (err) {
                await logDeployment(deploymentId, serverId, 'error', `❌ Erreur build: ${err.message}`);
            }
        }
    }
    
    // Démarrer ou redémarrer selon l'état actuel
    await logDeployment(deploymentId, serverId, 'info', `🔄 Démarrage du serveur...`);
    try {
        const currentStatus = await getServerPowerStatus(serverIdentifier);
        if (currentStatus.status === 'running') {
            await sendPowerAction(serverIdentifier, 'restart');
        } else {
            await sendPowerAction(serverIdentifier, 'start');
        }
    } catch (startErr) {
        await logDeployment(deploymentId, serverId, 'warn', `⚠️ Impossible de démarrer le serveur: ${startErr.message}`);
    }
    
    await new Promise((resolve) => {
        db.run(
            'UPDATE deployments SET status = "deployed", last_deployed = CURRENT_TIMESTAMP WHERE id = ?',
            [deploymentId],
            resolve
        );
    });
    await new Promise((resolve) => {
        db.run('UPDATE servers SET server_status = "stopped" WHERE id = ?', [serverId], resolve);
    });
    
    await logDeployment(deploymentId, serverId, 'success', `✅ Fichiers déployés avec succès ! Démarrez le serveur manuellement si nécessaire.`);
    if (global.broadcastDeployStatus) {
        global.broadcastDeployStatus(serverId, 'success', 'Déploiement template terminé !');
    }
    
} catch (error) {
    await logDeployment(deploymentId, serverId, 'error', `❌ Erreur: ${error.message}`);
    await new Promise((resolve) => {
        db.run('UPDATE deployments SET status = "failed" WHERE id = ?', [deploymentId], resolve);
    });
    if (global.broadcastDeployFailed) {
        await global.broadcastDeployFailed(serverId, deploymentId, error.message, typeof _techType !== 'undefined' ? _techType : 'nodejs');
    }
} finally {
    try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
        fs.rmSync(`${tmpDir}.zip`, { force: true });
    } catch (e) {
        console.error('Erreur nettoyage:', e);
    }
}

}

function deployWithTimeout(deployFn) {
    return Promise.race([
        deployFn(),
        new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Timeout déploiement (10 min)')), DEPLOY_TIMEOUT)
        )
    ]);
}

function logSystem(logType, message, details = null) {
    db.run(
        'INSERT INTO system_logs (log_type, message, details) VALUES (?, ?, ?)',
        [logType, message, details]
    );
}

function logAdminAction(adminId, actionType, targetType, targetId, description, ip = null, userAgent = null) {
    db.run(
        'INSERT INTO admin_actions (admin_id, action_type, target_type, target_id, description, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [adminId, actionType, targetType, targetId, description, ip, userAgent]
    );
}

function updateUserBadges(userId) {
    db.get(
        'SELECT total_login_days, coins, role, account_created FROM users WHERE id = ?',
        [userId],
        (err, user) => {
            if (err || !user) return;

            const badges = [];
            const accountAge = Math.floor((new Date() - new Date(user.account_created)) / (1000 * 60 * 60 * 24));

            if (accountAge >= 0) badges.push('newcomer');
            if (accountAge >= 7) badges.push('bronze');
            if (accountAge >= 30) badges.push('silver');
            if (accountAge >= 60) badges.push('gold');
            if (accountAge >= 90 && user.coins >= 1000) badges.push('vip');
            if (user.coins >= 5000) badges.push('premium');
            if (user.role === 'admin' || user.role === 'superadmin') badges.push('admin-assistant');
            if (user.total_login_days >= 100) badges.push('beta-tester');

            db.run('UPDATE users SET badges = ? WHERE id = ?', [JSON.stringify(badges), userId]);
        }
    );
}

// =============================================
// FONCTIONS DE COMMISSION REVENDEUR
// =============================================

async function processResellerCommission(clientUserId, baseAmount, transactionId) {
    // Cherche si ce client appartient à un revendeur
    const resellerClient = await new Promise(r =>
        db.get(
            `SELECT rc.reseller_id, rp.commission_rate
             FROM reseller_clients rc
             JOIN reseller_profiles rp ON rc.reseller_id = rp.user_id
             WHERE rc.client_id = ? AND rp.active = 1`,
            [clientUserId], (e, row) => r(row)
        )
    );

    if (!resellerClient) return; // Pas de revendeur associé

    const commissionAmount = parseFloat((baseAmount * resellerClient.commission_rate / 100).toFixed(2));

    // Crédite la commission
    db.run(
        `UPDATE reseller_profiles SET
         commission_balance = commission_balance + ?,
         total_earned = total_earned + ?
         WHERE user_id = ?`,
        [commissionAmount, commissionAmount, resellerClient.reseller_id]
    );

    // Log de commission
    db.run(
        `INSERT INTO commission_logs
         (reseller_id, client_id, transaction_id, amount, rate, base_amount, description)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [resellerClient.reseller_id, clientUserId, transactionId, commissionAmount,
         resellerClient.commission_rate, baseAmount, `Commission sur achat client #${clientUserId}`]
    );

    // Notification temps réel au revendeur
    if (global.sendNotification) {
        global.sendNotification(resellerClient.reseller_id, {
            title: '💰 Nouvelle commission !',
            message: `+${commissionAmount} XOF de commission sur une vente client`,
            type: 'success',
            metadata: { amount: commissionAmount, client_id: clientUserId }
        });
    }

    logSystem('financial', 'Commission créditée', {
        reseller_id: resellerClient.reseller_id,
        client_id: clientUserId,
        amount: commissionAmount,
        rate: resellerClient.commission_rate
    });
}

// =============================================
// TÂCHES AUTOMATIQUES (CRON)
// =============================================

async function checkAndResetDailyRewards() {
    console.log('🔄 Vérification des récompenses quotidiennes...');
    
    const today = getCurrentDate();
    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];

    db.all(
        'SELECT id, daily_login_streak, last_daily_login FROM users WHERE last_daily_login IS NOT NULL',
        [],
        (err, users) => {
            if (err) {
                console.error('❌ Erreur récupération utilisateurs:', err);
                return;
            }

            for (const user of users) {
                if (user.last_daily_login !== yesterday && user.last_daily_login !== today) {
                    db.run(
                        'UPDATE users SET daily_login_streak = 0 WHERE id = ?',
                        [user.id]
                    );
                }
            }
        }
    );
}

async function checkServerStatus() {
    console.log('🔄 Vérification du statut des serveurs...');
    
    db.all(
        'SELECT id, server_identifier, server_status FROM servers WHERE is_active = 1',
        async (err, servers) => {
            if (err) {
                console.error('❌ Erreur récupération serveurs:', err);
                return;
            }

            for (const server of servers) {
                try {
                    const status = await getServerPowerStatus(server.server_identifier);
                    
                    if (status.status !== server.server_status) {
                        db.run(
                            'UPDATE servers SET server_status = ?, last_activity = CURRENT_TIMESTAMP WHERE id = ?',
                            [status.status, server.id]
                        );
                        
                        db.run(
                            'INSERT INTO server_logs (server_id, action, status, details) VALUES (?, ?, ?, ?)',
                            [server.id, 'status_change', status.status, JSON.stringify(status.resources)]
                        );
                    }
                } catch (error) {
                    console.error(`❌ Erreur vérification serveur ${server.id}:`, error);
                }
            }
        }
    );
}

async function sendExpirationWarnings() {
    console.log('⏰ Vérification des serveurs expirant bientôt...');
    
    const warningThreshold = new Date();
    warningThreshold.setHours(warningThreshold.getHours() + 24);

    db.all(
        `SELECT s.*, u.username, u.email 
         FROM servers s 
         JOIN users u ON s.user_id = u.id 
         WHERE s.expires_at <= ? AND s.warning_sent = 0 AND s.is_active = 1`,
        [warningThreshold.toISOString()],
        async (err, servers) => {
            if (err) {
                console.error('❌ Erreur récupération serveurs:', err);
                return;
            }

            for (const server of servers) {
                try {
                    const expiresAt = new Date(server.expires_at);
                    const hoursLeft = Math.ceil((expiresAt - new Date()) / (1000 * 60 * 60));

                    const html = `
                        <div style="font-family: Arial; max-width: 600px; margin: 0 auto; padding: 20px; background: #0f172a; color: #fff; border-radius: 10px;">
                            <h1 style="color: #f59e0b;">⚠️ Alerte d'Expiration</h1>
                            <p>Bonjour ${server.username},</p>
                            <p>Votre serveur <strong>"${server.server_name}"</strong> expire dans <strong>${hoursLeft} heures</strong>.</p>
                            <div style="background: #1e293b; padding: 20px; border-radius: 8px; margin: 20px 0;">
                                <p><strong>Serveur:</strong> ${server.server_name}</p>
                                <p><strong>Type:</strong> ${server.server_type}</p>
                                <p><strong>Expire le:</strong> ${new Date(server.expires_at).toLocaleString('fr-FR')}</p>
                                <p><strong>Prix renouvellement:</strong> ${PLAN_COINS_PRICES[server.server_type] || 0} coins</p>
                            </div>
                            <a href="https://flihost.site/dashboard" style="display: inline-block; background: #6366f1; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Renouveler</a>
                            <p style="color: #94a3b8; font-size: 12px; margin-top: 20px;">FLYHOST - Hébergement de serveurs</p>
                        </div>
                    `;

                    await sendEmail(server.email, `⚠️ Votre serveur "${server.server_name}" expire bientôt !`, html);

                    db.run('UPDATE servers SET warning_sent = 1 WHERE id = ?', [server.id]);
                    
                    if (global.sendNotification) {
                        global.sendNotification(server.user_id, {
                            title: '⚠️ Serveur expire bientôt',
                            message: `Votre serveur "${server.server_name}" expire dans ${hoursLeft} heures`,
                            type: 'warning'
                        });
                    }
                } catch (error) {
                    console.error(`❌ Erreur envoi avertissement:`, error);
                }
            }
        }
    );
}

async function deleteExpiredServers() {
    console.log('🗑️ Suppression des serveurs expirés...');
    
    const now = new Date();

    db.all(
        `SELECT s.*, u.username, u.email 
         FROM servers s 
         JOIN users u ON s.user_id = u.id 
         WHERE s.expires_at <= ? AND s.is_active = 1`,
        [now.toISOString()],
        async (err, servers) => {
            if (err) {
                console.error('❌ Erreur récupération serveurs:', err);
                return;
            }

            for (const server of servers) {
                try {
                    db.run('UPDATE servers SET is_active = 0, server_status = "deleted" WHERE id = ?', [server.id]);

                    const deleteSuccess = await deletePterodactylServer(server.pterodactyl_id);

                    if (deleteSuccess) {
                        db.run(
                            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
                            [server.id, 'deleted', 'Serveur supprimé après expiration']
                        );

                        const html = `
                            <div style="font-family: Arial; max-width: 600px; margin: 0 auto; padding: 20px; background: #0f172a; color: #fff; border-radius: 10px;">
                                <h1 style="color: #ef4444;">🗑️ Serveur supprimé</h1>
                                <p>Bonjour ${server.username},</p>
                                <p>Votre serveur <strong>"${server.server_name}"</strong> a été supprimé car il a expiré.</p>
                                <p>Vous pouvez en créer un nouveau sur votre tableau de bord.</p>
                                <a href="https://flihost.site/dashboard" style="display: inline-block; background: #6366f1; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Tableau de bord</a>
                                <p style="color: #94a3b8; font-size: 12px; margin-top: 20px;">FLYHOST - Hébergement de serveurs</p>
                            </div>
                        `;

                        await sendEmail(server.email, `🗑️ Votre serveur "${server.server_name}" a été supprimé`, html);
                        console.log(`✅ Serveur ${server.server_name} supprimé`);
                    }
                } catch (error) {
                    console.error(`❌ Erreur suppression serveur:`, error);
                }
            }
        }
    );
}

async function cleanupUnverifiedAccounts() {
    console.log('🧹 Nettoyage des comptes non vérifiés...');
    
    const threeDaysAgo = new Date();
    threeDaysAgo.setDate(threeDaysAgo.getDate() - 3);

    db.all(
        `SELECT id FROM users WHERE email_verified = 0 AND created_at <= ?`,
        [threeDaysAgo.toISOString()],
        async (err, users) => {
            if (err) {
                console.error('❌ Erreur récupération comptes:', err);
                return;
            }

            for (const user of users) {
                try {
                    db.all('SELECT pterodactyl_id FROM servers WHERE user_id = ?', [user.id], async (err, servers) => {
                        if (!err && servers) {
                            for (const server of servers) {
                                if (server.pterodactyl_id) {
                                    await deletePterodactylServer(server.pterodactyl_id);
                                }
                            }
                        }

                        db.run('DELETE FROM servers WHERE user_id = ?', [user.id]);
                        db.run('DELETE FROM panels WHERE user_id = ?', [user.id]);
                        db.run('DELETE FROM transactions WHERE user_id = ?', [user.id]);
                        db.run('DELETE FROM referrals WHERE referrer_id = ? OR referred_id = ?', [user.id, user.id]);
                        db.run('DELETE FROM daily_rewards WHERE user_id = ?', [user.id]);
                        db.run('DELETE FROM user_activities WHERE user_id = ?', [user.id]);
                        db.run('DELETE FROM api_logs WHERE user_id = ?', [user.id]);
                        db.run('DELETE FROM github_connections WHERE user_id = ?', [user.id]);
                        db.run('DELETE FROM deployments WHERE user_id = ?', [user.id]);
                        db.run('DELETE FROM api_keys WHERE user_id = ?', [user.id]);
                        db.run('DELETE FROM user_credits WHERE user_id = ?', [user.id]);
                        db.run('DELETE FROM tickets WHERE user_id = ?', [user.id]);
                        db.run('DELETE FROM users WHERE id = ?', [user.id]);

                        console.log(`✅ Compte ${user.id} supprimé`);
                    });
                } catch (error) {
                    console.error(`❌ Erreur suppression compte:`, error);
                }
            }
        }
    );
}

// Helper global : créer une notification in-app pour un utilisateur
function createUserNotification(userId, title, message, type = 'info', link = null) {
    if (!userId) return;
    db.run(`INSERT INTO user_notifications (user_id, title, message, type, link) VALUES (?,?,?,?,?)`,
        [userId, title, message, type, link || null],
        err => { if (err) console.error('Notif error:', err.message); });
}

function initializeCronJobs() {
    console.log('⏰ Initialisation des tâches automatiques...');

    cron.schedule('0 0 * * *', () => {
        console.log('🔄 Réinitialisation des streaks...');
        checkAndResetDailyRewards();
    });

    cron.schedule('*/5 * * * *', () => {
        checkServerStatus();
    });

    cron.schedule('0 */6 * * *', () => {
        console.log('🔄 Vérification périodique des serveurs...');
        sendExpirationWarnings();
    });

    cron.schedule('0 * * * *', () => {
        console.log('🕘 Vérification et suppression des serveurs expirés...');
        deleteExpiredServers();
    });

    cron.schedule('0 10 * * *', () => {
        console.log('🕙 Nettoyage des comptes non vérifiés...');
        cleanupUnverifiedAccounts();
    });

    // Nouveaux cron jobs
    cron.schedule('0 0 * * *', async () => {
        console.log('🔄 Vérification expiration grades admin (revendeurs)...');
        db.all(
            `SELECT id FROM users WHERE role = 'admin' AND admin_expires_at < datetime('now')`,
            [],
            (err, users) => {
                users?.forEach(user => {
                    db.run(`UPDATE users SET role = 'user', admin_access_active = 0 WHERE id = ?`, [user.id]);
                    db.run(`UPDATE reseller_profiles SET active = 0 WHERE user_id = ?`, [user.id]);
                    logSystem('reseller', 'Grade admin expiré', { user_id: user.id });
                });
            }
        );
    });
    
    // Nettoyage des fichiers médias du chat (tous les jours à 3h du matin)
cron.schedule('0 3 * * *', () => {
    console.log('🧹 Nettoyage des fichiers médias du chat...');

    // Récupérer tous les chemins de médias dans la base
    db.all('SELECT media_url FROM chat_messages WHERE media_url IS NOT NULL', [], (err, messages) => {
        if (err) return;

        const usedFiles = new Set(messages.map(m => path.basename(m.media_url)));

        // Lire tous les fichiers du dossier uploads/chat
        fs.readdir(CHAT_CONFIG.upload_dir, (err, files) => {
            if (err) return;

            let deletedCount = 0;
            files.forEach(file => {
                // Ne pas supprimer les fichiers récents (< 24h)
                const filePath = path.join(CHAT_CONFIG.upload_dir, file);
                const stats = fs.statSync(filePath);
                const ageHours = (Date.now() - stats.mtimeMs) / (1000 * 60 * 60);

                if (!usedFiles.has(file) && ageHours > 24) {
                    fs.unlink(filePath, (err) => {
                        if (!err) deletedCount++;
                    });
                }
            });

            console.log(`✅ ${deletedCount} fichiers médias nettoyés`);
        });
    });
});

    cron.schedule('0 9 * * 1', async () => {
        console.log('📊 Envoi rapports hebdomadaires aux revendeurs...');
        db.all(
            `SELECT u.email, u.username, rp.commission_balance, rp.total_earned, rp.total_withdrawn
             FROM reseller_profiles rp
             JOIN users u ON rp.user_id = u.id
             WHERE rp.active = 1`,
            [],
            async (err, resellers) => {
                for (const reseller of resellers || []) {
                    await sendResellerWeeklyReport(reseller);
                }
            }
        );
    });

    // ===== AUTO-RENOUVELLEMENT (tous les jours à 8h) =====
    cron.schedule('0 8 * * *', async () => {
        console.log('🔄 Auto-renouvellement des serveurs...');
        const now = new Date();
        const tomorrow = new Date(now.getTime() + 24 * 3600 * 1000);
        db.all(
            `SELECT s.*, u.coins, u.email, u.username FROM servers s JOIN users u ON s.user_id = u.id
             WHERE s.auto_renew = 1 AND s.is_active = 1 AND s.expires_at <= ? AND s.server_type != 'free'`,
            [tomorrow.toISOString()],
            async (err, servers) => {
                for (const srv of servers || []) {
                    const plan = PLANS_CONFIG[srv.server_type];
                    if (!plan) continue;
                    if (srv.coins < plan.price) {
                        await sendEmail(srv.email, '⚠️ Auto-renouvellement échoué - Coins insuffisants',
                            `<div style="font-family:Arial;max-width:600px;margin:0 auto;padding:20px;background:#0f172a;color:#fff;border-radius:10px;">
                            <h1 style="color:#ef4444;">❌ Renouvellement impossible</h1>
                            <p>Bonjour ${srv.username},</p>
                            <p>Le renouvellement automatique de votre serveur <strong>"${srv.server_name}"</strong> a échoué car vous n'avez pas assez de coins (${srv.coins}/${plan.price} coins requis).</p>
                            <a href="https://flihost.site/payment" style="background:#6366f1;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;">Acheter des coins</a></div>`);
                        continue;
                    }
                    const newExpiry = new Date(srv.expires_at);
                    newExpiry.setDate(newExpiry.getDate() + plan.duration);
                    db.run('UPDATE users SET coins = coins - ? WHERE id = ?', [plan.price, srv.user_id]);
                    db.run('UPDATE servers SET expires_at = ?, warning_sent = 0, warning_sent_3d = 0 WHERE id = ?', [newExpiry.toISOString(), srv.id]);
                    db.run('INSERT INTO user_activities (user_id, activity_type, coins_earned, description) VALUES (?,?,?,?)',
                        [srv.user_id, 'auto_renew', -plan.price, `Auto-renouvellement serveur "${srv.server_name}"`]);
                    createUserNotification(srv.user_id, `✅ Serveur "${srv.server_name}" renouvelé`,
                        `Votre serveur a été renouvelé automatiquement jusqu'au ${newExpiry.toLocaleDateString('fr-FR')}. ${plan.price} coins déduits.`,
                        'success', '/dashboard');
                    await sendEmail(srv.email, `✅ Serveur "${srv.server_name}" renouvelé automatiquement`,
                        `<div style="font-family:Arial;max-width:600px;margin:0 auto;padding:20px;background:#0f172a;color:#fff;border-radius:10px;">
                        <h1 style="color:#10b981;">✅ Renouvellement automatique réussi</h1>
                        <p>Bonjour ${srv.username}, votre serveur <strong>"${srv.server_name}"</strong> a été renouvelé jusqu'au ${newExpiry.toLocaleDateString('fr-FR')}.</p>
                        <p style="color:#94a3b8;">Coins déduits : ${plan.price}</p></div>`);
                }
            }
        );
    });

    // ===== ALERTE J-3 (tous les jours à 9h30) =====
    cron.schedule('30 9 * * *', () => {
        const d3 = new Date();
        d3.setDate(d3.getDate() + 3);
        db.all(
            `SELECT s.*, u.email, u.username FROM servers s JOIN users u ON s.user_id = u.id
             WHERE s.is_active = 1 AND s.warning_sent_3d = 0 AND date(s.expires_at) = date(?)`,
            [d3.toISOString()],
            async (err, servers) => {
                for (const srv of servers || []) {
                    createUserNotification(srv.user_id,
                        `🟠 Serveur "${srv.server_name}" expire dans 3 jours`,
                        `Votre serveur expire le ${new Date(srv.expires_at).toLocaleDateString('fr-FR')}. Rechargez vos coins pour éviter la perte de données.`,
                        'warning', '/payment');
                    await sendEmail(srv.email, `⏰ Votre serveur "${srv.server_name}" expire dans 3 jours`,
                        `<div style="font-family:Arial;max-width:600px;margin:0 auto;padding:20px;background:#0f172a;color:#fff;border-radius:10px;">
                        <h1 style="color:#f59e0b;">⏰ Expiration dans 3 jours</h1>
                        <p>Bonjour ${srv.username}, votre serveur <strong>"${srv.server_name}"</strong> expire le ${new Date(srv.expires_at).toLocaleDateString('fr-FR')}.</p>
                        <p>Renouvelez-le dès maintenant pour ne pas perdre vos données.</p>
                        <a href="https://flihost.site/payment" style="display:inline-block;background:#6366f1;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;">Renouveler mon serveur</a></div>`);
                    db.run('UPDATE servers SET warning_sent_3d = 1 WHERE id = ?', [srv.id]);
                }
            }
        );
    });

    // ===== BACKUP PLANIFIÉ (toutes les heures) =====
    cron.schedule('0 * * * *', async () => {
        const now = new Date();
        const hour = now.getHours();
        db.all(
            `SELECT * FROM servers WHERE backup_schedule IS NOT NULL AND is_active = 1`,
            [],
            async (err, servers) => {
                for (const srv of servers || []) {
                    const sched = srv.backup_schedule;
                    let shouldBackup = false;
                    if (sched === 'hourly') shouldBackup = true;
                    if (sched === 'daily' && hour === 3) shouldBackup = true;
                    if (sched === 'weekly' && now.getDay() === 1 && hour === 3) shouldBackup = true;
                    if (!shouldBackup) continue;
                    try {
                        const pteroId = srv.server_identifier;
                        await callPterodactylAPI(`/api/client/servers/${pteroId}/backups`, 'POST', {});
                        db.run('UPDATE servers SET last_backup_at = ? WHERE id = ?', [now.toISOString(), srv.id]);
                        db.run('INSERT INTO server_logs (server_id, action, details) VALUES (?,?,?)',
                            [srv.id, 'auto_backup', `Backup automatique (${sched})`]);
                        console.log(`✅ Backup auto serveur ${srv.id} (${sched})`);
                    } catch(e) { console.error(`❌ Backup auto serveur ${srv.id}:`, e.message); }
                }
            }
        );
    });

    // Cron abonnement mensuel - vérifier les abonnements à renouveler
    cron.schedule('0 1 * * *', () => {
        const now = new Date();
        db.all(`SELECT s.*, u.coins FROM subscriptions s JOIN users u ON s.user_id = u.id WHERE s.active = 1 AND s.next_billing_at <= ?`,
            [now.toISOString()], (err, subs) => {
                for (const sub of subs || []) {
                    if (sub.coins >= sub.price_per_month) {
                        db.run('UPDATE users SET coins = coins - ? WHERE id = ?', [sub.price_per_month, sub.user_id]);
                        const nextBilling = new Date(sub.next_billing_at);
                        nextBilling.setMonth(nextBilling.getMonth() + 1);
                        db.run('UPDATE subscriptions SET next_billing_at = ?, coins_per_month = ? WHERE id = ?',
                            [nextBilling.toISOString(), sub.coins_per_month, sub.id]);
                        if (sub.coins_per_month > 0) {
                            db.run('UPDATE users SET coins = coins + ? WHERE id = ?', [sub.coins_per_month, sub.user_id]);
                        }
                        console.log(`✅ Abonnement renouvelé user ${sub.user_id} plan ${sub.plan_name}`);
                    } else {
                        db.run('UPDATE subscriptions SET active = 0 WHERE id = ?', [sub.id]);
                        console.log(`⚠️ Abonnement annulé user ${sub.user_id} (coins insuffisants)`);
                    }
                }
            });
    });

    // Cron collecte métriques CPU/RAM toutes les 5 minutes
    cron.schedule('*/5 * * * *', async () => {
        db.all(`SELECT id, server_identifier FROM servers WHERE is_active = 1 AND server_identifier IS NOT NULL AND server_status = 'running'`,
            [], async (err, servers) => {
                for (const srv of servers || []) {
                    try {
                        const result = await callPterodactylClientAPI(`/api/client/servers/${srv.server_identifier}/resources`);
                        const attrs = result?.attributes || {};
                        const cpu = attrs.cpu_absolute || 0;
                        const ram = Math.round((attrs.memory_bytes || 0) / 1024 / 1024);
                        const disk = Math.round((attrs.disk_bytes || 0) / 1024 / 1024);
                        const rx = Math.round((attrs.network_rx_bytes || 0) / 1024);
                        const tx = Math.round((attrs.network_tx_bytes || 0) / 1024);
                        db.run(`INSERT INTO server_metrics (server_id, cpu, ram_mb, disk_mb, net_rx_kb, net_tx_kb) VALUES (?,?,?,?,?,?)`,
                            [srv.id, cpu, ram, disk, rx, tx]);
                        // Nettoyer métriques > 7 jours
                        db.run(`DELETE FROM server_metrics WHERE server_id = ? AND recorded_at < datetime('now', '-7 days')`, [srv.id]);
                        // Alerte CPU > 90%
                        if (cpu > 90) {
                            db.get(`SELECT id FROM server_alerts WHERE server_id = ? AND alert_type = 'cpu_high' AND sent_at > datetime('now', '-1 hour')`,
                                [srv.id], (e2, existing) => {
                                    if (!existing) {
                                        db.run(`INSERT INTO server_alerts (server_id, alert_type) VALUES (?, 'cpu_high')`, [srv.id]);
                                        db.get('SELECT u.email, u.username FROM servers s JOIN users u ON s.user_id = u.id WHERE s.id = ?', [srv.id], async (e3, owner) => {
                                            if (owner) {
                                                await sendEmail(owner.email, '⚠️ CPU élevé sur votre serveur FLYHOST',
                                                    `<p>Bonjour ${owner.username},</p><p>Votre serveur consomme actuellement <strong>${cpu.toFixed(1)}%</strong> de CPU.</p><p>Pensez à optimiser votre serveur ou à upgrader votre plan.</p>`).catch(() => {});
                                            }
                                        });
                                    }
                                });
                        }
                    } catch(e) {}
                }
            });
    });

    // Cron alertes crash serveur (toutes les 5 min)
    cron.schedule('*/5 * * * *', async () => {
        db.all(`SELECT s.id, s.server_identifier, s.server_name, u.email, u.username 
                FROM servers s JOIN users u ON s.user_id = u.id 
                WHERE s.is_active = 1 AND s.server_identifier IS NOT NULL AND s.server_status = 'running'`,
            [], async (err, servers) => {
                for (const srv of servers || []) {
                    try {
                        const result = await callPterodactylClientAPI(`/api/client/servers/${srv.server_identifier}/resources`);
                        const state = result?.attributes?.current_state;
                        if (state === 'offline' || state === 'stopping') {
                            db.run(`UPDATE servers SET server_status = 'stopped' WHERE id = ?`, [srv.id]);
                            db.get(`SELECT id FROM server_alerts WHERE server_id = ? AND alert_type = 'crash' AND sent_at > datetime('now', '-30 minutes')`,
                                [srv.id], async (e2, existing) => {
                                    if (!existing) {
                                        db.run(`INSERT INTO server_alerts (server_id, alert_type) VALUES (?, 'crash')`, [srv.id]);
                                        await sendEmail(srv.email, `🔴 Votre serveur "${srv.server_name}" s'est arrêté`,
                                            `<p>Bonjour ${srv.username},</p><p>Votre serveur <strong>${srv.server_name}</strong> s'est arrêté de manière inattendue.</p><p><a href="/server/${srv.id}" style="background:#6366f1;color:white;padding:10px 20px;border-radius:8px;text-decoration:none;">Redémarrer le serveur</a></p>`).catch(() => {});
                                    }
                                });
                        }
                    } catch(e) {}
                }
            });
    });

    // createUserNotification définie au niveau module (voir plus bas)

    // Helper : email + notif alerte expiration
    async function sendExpiryAlert(srv, alertType, daysLeft) {
        db.get(`SELECT id FROM server_alerts WHERE server_id = ? AND alert_type = ? AND sent_at > datetime('now', '-${daysLeft * 24 - 2} hours')`,
            [srv.id, alertType], async (e2, existing) => {
                if (!existing) {
                    db.run(`INSERT INTO server_alerts (server_id, alert_type) VALUES (?, ?)`, [srv.id, alertType]);
                    const expiresAt = new Date(srv.expires_at).toLocaleString('fr-FR');
                    const urgency = daysLeft <= 1 ? '🔴 URGENT' : daysLeft <= 3 ? '🟠 Important' : '🟡 Information';
                    // Email
                    await sendEmail(srv.email, `⏰ Votre serveur "${srv.server_name}" expire dans ${daysLeft}j`,
                        `<p>Bonjour ${srv.username},</p>
                        <p>${urgency} - Votre serveur <strong>${srv.server_name}</strong> expire le <strong>${expiresAt}</strong>.</p>
                        <p>Rechargez vos coins ou activez l'auto-renouvellement pour ne pas perdre votre serveur.</p>
                        <p><a href="/payment" style="background:#6366f1;color:white;padding:10px 20px;border-radius:8px;text-decoration:none;">Recharger mes coins</a></p>`).catch(() => {});
                    // Notification in-app
                    createUserNotification(srv.user_id,
                        `⏰ Serveur "${srv.server_name}" expire dans ${daysLeft}j`,
                        `Votre serveur expire le ${expiresAt}. Rechargez vos coins pour le renouveler.`,
                        daysLeft <= 1 ? 'warning' : 'info', '/dashboard');
                }
            });
    }

    // Cron alerte expiration 24h, 3j, 7j (toutes les heures)
    cron.schedule('0 * * * *', () => {
        const now = Date.now();
        const windows = [
            { hours: 24, alertType: 'expiry_24h', label: 1 },
            { hours: 72, alertType: 'expiry_3d', label: 3 },
            { hours: 168, alertType: 'expiry_7d', label: 7 },
        ];
        for (const win of windows) {
            const future = new Date(now + win.hours * 3600 * 1000).toISOString();
            const pastWindow = new Date(now + (win.hours - 1) * 3600 * 1000).toISOString();
            db.all(`SELECT s.id, s.server_name, s.expires_at, s.user_id, u.email, u.username
                    FROM servers s JOIN users u ON s.user_id = u.id
                    WHERE s.is_active = 1 AND s.expires_at IS NOT NULL
                      AND s.expires_at <= ? AND s.expires_at > ?`,
                [future, pastWindow], (err, servers) => {
                    for (const srv of servers || []) {
                        sendExpiryAlert(srv, win.alertType, win.label).catch(() => {});
                    }
                });
        }
    });

    // Cron redémarrage planifié
    cron.schedule('0 * * * *', async () => {
        const now = new Date();
        const hour = now.getHours();
        const day = now.getDay();
        db.all(`SELECT rs.*, s.server_identifier FROM restart_schedules rs JOIN servers s ON rs.server_id = s.id`,
            [], async (err, schedules) => {
                for (const sc of schedules || []) {
                    let shouldRestart = false;
                    if (sc.schedule === 'daily' && hour === sc.hour) shouldRestart = true;
                    if (sc.schedule === 'weekly' && day === sc.day_of_week && hour === sc.hour) shouldRestart = true;
                    if (!shouldRestart) continue;
                    try {
                        await callPterodactylClientAPI(`/api/client/servers/${sc.server_identifier}/power`, 'POST', { signal: 'restart' });
                        db.run('UPDATE restart_schedules SET last_restart_at = ? WHERE id = ?', [now.toISOString(), sc.id]);
                        db.run('INSERT INTO server_activity_logs (server_id, action, details) VALUES (?,?,?)',
                            [sc.server_id, 'AUTO_RESTART', `Redémarrage planifié (${sc.schedule})`]);
                        console.log(`✅ Redémarrage auto serveur ${sc.server_id}`);
                    } catch(e) { console.error(`❌ Redémarrage auto serveur ${sc.server_id}:`, e.message); }
                }
            });
    });

    console.log('✅ Tâches automatiques initialisées');
}

// =============================================
// ROUTES D'AUTHENTIFICATION
// =============================================

app.post('/api/register', async (req, res) => {
    const { username, email, password, referral_code, affiliate_code, ref } = req.body;

    try {
        if (!username || !email || !password) {
            return res.status(400).json({
                success: false,
                error: 'Tous les champs sont requis',
                code: 'MISSING_FIELDS'
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                success: false,
                error: 'Le mot de passe doit contenir au moins 6 caractères',
                code: 'PASSWORD_TOO_SHORT'
            });
        }

        if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
            return res.status(400).json({
                success: false,
                error: 'Nom d\'utilisateur invalide (3-20 caractères, lettres, chiffres et _ uniquement)',
                code: 'INVALID_USERNAME'
            });
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({
                success: false,
                error: 'Email invalide',
                code: 'INVALID_EMAIL'
            });
        }

        const settings = await new Promise((resolve) => {
            db.get('SELECT value FROM system_settings WHERE key = "registration_enabled"', [], (err, row) => {
                resolve(row?.value === 'true');
            });
        });

        if (!settings) {
            return res.status(403).json({
                success: false,
                error: 'Les inscriptions sont temporairement désactivées',
                code: 'REGISTRATION_DISABLED'
            });
        }

        const defaultCoins = await new Promise((resolve) => {
            db.get('SELECT value FROM system_settings WHERE key = "default_coins_on_register"', [], (err, row) => {
                resolve(parseInt(row?.value) || 10);
            });
        });

        const hashedPassword = await bcrypt.hash(password, 12);
        const apiKey = generateApiKey(username);
        const userReferralCode = generateReferralCode(username);
        const publicId = generatePublicId();
        const verificationCode = generateVerificationCode();

        const devMode = process.env.NODE_ENV !== 'production';
        const verifExpires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
        db.run(
            `INSERT INTO users (
                public_id, username, email, password, api_key, coins, referral_code, 
                email_verification_code, email_verification_code_expires, email_verified
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [publicId, username, email, hashedPassword, apiKey, defaultCoins, userReferralCode, verificationCode, verifExpires, devMode ? 1 : 0],
            async function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(400).json({
                            success: false,
                            error: 'Nom d\'utilisateur ou email déjà utilisé',
                            code: 'DUPLICATE_USER'
                        });
                    }
                    console.error('❌ Erreur inscription:', err);
                    return res.status(500).json({
                        success: false,
                        error: 'Erreur base de données',
                        code: 'DATABASE_ERROR'
                    });
                }

                const userId = this.lastID;

                db.run(`INSERT INTO user_credits (user_id, balance) VALUES (?, ?)`, [userId, CREDITS_CONFIG.default_on_register]);

                await sendVerificationEmail(email, username, verificationCode);

                // Gestion du parrainage classique
                if (referral_code) {
                    db.get('SELECT id, username, referred_by FROM users WHERE referral_code = ?', [referral_code], (err, referrer) => {
                        if (referrer && referrer.id !== userId) {
                            const rewardL1 = 10;
                            const rewardL2 = 5;
                            const rewardL3 = 2;
                            // Niveau 1 - parrain direct
                            db.run('UPDATE users SET coins = coins + ? WHERE id = ?', [rewardL1, referrer.id]);
                            db.run('UPDATE users SET coins = coins + ? WHERE id = ?', [rewardL1, userId]);
                            db.run('INSERT INTO referrals (referrer_id, referred_id, coins_rewarded) VALUES (?, ?, ?)',
                                [referrer.id, userId, rewardL1]);
                            db.run('INSERT INTO user_activities (user_id, activity_type, coins_earned, description) VALUES (?, ?, ?, ?)',
                                [referrer.id, 'referral', rewardL1, `Parrainage niveau 1 de ${username}`]);
                            // Niveau 2 - parrain du parrain
                            if (referrer.referred_by) {
                                db.run('UPDATE users SET coins = coins + ? WHERE id = ?', [rewardL2, referrer.referred_by]);
                                db.run('INSERT INTO user_activities (user_id, activity_type, coins_earned, description) VALUES (?, ?, ?, ?)',
                                    [referrer.referred_by, 'referral', rewardL2, `Parrainage niveau 2 de ${username}`]);
                                // Niveau 3 - parrain du parrain du parrain
                                db.get('SELECT referred_by FROM users WHERE id = ?', [referrer.referred_by], (e2, lvl2) => {
                                    if (lvl2?.referred_by) {
                                        db.run('UPDATE users SET coins = coins + ? WHERE id = ?', [rewardL3, lvl2.referred_by]);
                                        db.run('INSERT INTO user_activities (user_id, activity_type, coins_earned, description) VALUES (?, ?, ?, ?)',
                                            [lvl2.referred_by, 'referral', rewardL3, `Parrainage niveau 3 de ${username}`]);
                                    }
                                });
                            }
                        }
                    });
                }

                // NOUVEAU : Gestion de l'affiliation revendeur
                const affCode = affiliate_code || ref;
                if (affCode) {
                    db.get(
                        `SELECT rp.user_id as reseller_id
                         FROM reseller_profiles rp
                         WHERE rp.affiliate_code = ? AND rp.active = 1`,
                        [affCode],
                        (err, reseller) => {
                            if (reseller) {
                                // Lie le nouveau client au revendeur
                                db.run(
                                    `INSERT OR IGNORE INTO reseller_clients
                                     (reseller_id, client_id, acquisition_source, affiliate_code_used)
                                     VALUES (?, ?, 'affiliate', ?)`,
                                    [reseller.reseller_id, userId, affCode]
                                );
                                // Bonus inscription pour le revendeur (50 coins)
                                db.run(
                                    `UPDATE reseller_profiles SET commission_balance = commission_balance + 50
                                     WHERE user_id = ?`,
                                    [reseller.reseller_id]
                                );
                                logSystem('reseller', 'Nouveau client affilié', {
                                    reseller_id: reseller.reseller_id,
                                    client_id: userId
                                });
                            }
                        }
                    );
                }

                logSystem('user_registered', `Nouvel utilisateur: ${username}`, { userId });

                res.json({
                    success: true,
                    message: 'Compte créé! Vérifiez votre email pour le code.',
                    requiresVerification: true
                });
            }
        );
    } catch (error) {
        console.error('❌ Erreur inscription:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur serveur',
            code: 'INTERNAL_ERROR'
        });
    }
});

app.post('/api/resend-verification', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, error: 'Email requis' });
    db.get('SELECT id, username, email_verified FROM users WHERE email = ?', [email], async (err, user) => {
        if (err || !user) return res.status(404).json({ success: false, error: 'Compte introuvable' });
        if (user.email_verified) return res.status(400).json({ success: false, error: 'Email déjà vérifié' });
        const newCode = generateVerificationCode();
        const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
        db.run('UPDATE users SET email_verification_code = ?, email_verification_code_expires = ? WHERE id = ?',
            [newCode, expires, user.id], async () => {
                try { await sendVerificationEmail(email, user.username, newCode); } catch(e) {}
                res.json({ success: true, message: 'Code renvoyé' });
            });
    });
});

app.post('/api/verify-email', async (req, res) => {
    const { email, code } = req.body;

    if (!email || !code) {
        return res.status(400).json({
            success: false,
            error: 'Email et code requis',
            code: 'MISSING_FIELDS'
        });
    }

    db.get(
        'SELECT id, username, email_verification_code, email_verification_code_expires, public_id FROM users WHERE email = ?',
        [email],
        async (err, user) => {
            if (err || !user) {
                return res.status(404).json({
                    success: false,
                    error: 'Utilisateur non trouvé',
                    code: 'USER_NOT_FOUND'
                });
            }

            const now = new Date();
            const rawExpires = user.email_verification_code_expires || '';
            const normalizedExpires = rawExpires.endsWith('Z') || rawExpires.includes('+') ? rawExpires : rawExpires + 'Z';
            const codeExpires = new Date(normalizedExpires);

            if (now > codeExpires) {
                return res.status(400).json({
                    success: false,
                    error: 'Code expiré. Cliquez sur "Renvoyer le code" pour en recevoir un nouveau.',
                    code: 'CODE_EXPIRED'
                });
            }

            if (user.email_verification_code !== code) {
                return res.status(400).json({
                    success: false,
                    error: 'Code incorrect',
                    code: 'INVALID_CODE'
                });
            }

            db.run(
                'UPDATE users SET email_verified = TRUE, email_verification_code = NULL, email_verification_code_expires = NULL, coins = coins + 5 WHERE id = ?',
                [user.id],
                async (err) => {
                    if (err) {
                        return res.status(500).json({
                            success: false,
                            error: 'Erreur base de données',
                            code: 'DATABASE_ERROR'
                        });
                    }

                    db.run(
                        'INSERT INTO user_activities (user_id, activity_type, coins_earned, description) VALUES (?, ?, ?, ?)',
                        [user.id, 'email_verification', 5, 'Bonus vérification email']
                    );

                    db.run(
                        `UPDATE user_credits SET balance = balance + ? WHERE user_id = ?`,
                        [CREDITS_CONFIG.bonus_email_verify, user.id]
                    );

                    const welcomeHtml = `
                        <div style="font-family: Arial; max-width: 600px; margin: 0 auto; padding: 20px; background: #0f172a; color: #fff; border-radius: 10px;">
                            <h1 style="color: #6366f1;">Bienvenue ${user.username} !</h1>
                            <p>Votre compte FLYHOST est maintenant activé.</p>
                            <div style="background: #1e293b; padding: 20px; border-radius: 8px; margin: 20px 0;">
                                <p><strong>ID:</strong> ${user.public_id}</p>
                                <p><strong>Email:</strong> ${email}</p>
                                <p><strong>Coins:</strong> 15 (10 + 5 bonus vérification)</p>
                            </div>
                            <p>Vous pouvez maintenant créer votre premier serveur !</p>
                            <a href="https://flihost.site/dashboard" style="display: inline-block; background: #6366f1; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Tableau de bord</a>
                            <p style="color: #94a3b8; font-size: 12px; margin-top: 20px;">FLYHOST - Hébergement de serveurs</p>
                        </div>
                    `;

                    await sendEmail(email, '🎉 Bienvenue sur FLYHOST !', welcomeHtml);

                    res.json({
                        success: true,
                        message: 'Email vérifié avec succès!',
                        coinsBonus: 5
                    });
                }
            );
        }
    );
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
            if (err || !user) {
                return res.status(400).json({
                    success: false,
                    error: 'Email ou mot de passe incorrect',
                    code: 'INVALID_CREDENTIALS'
                });
            }

            if (user.banned) {
                const now = new Date();
                const banExpires = user.ban_expires ? new Date(user.ban_expires) : null;
                
                if (banExpires && banExpires > now) {
                    return res.status(403).json({
                        success: false,
                        error: `Compte suspendu jusqu'au ${banExpires.toLocaleDateString()}`,
                        code: 'ACCOUNT_BANNED',
                        ban_expires: banExpires
                    });
                } else if (user.banned && !banExpires) {
                    return res.status(403).json({
                        success: false,
                        error: 'Compte suspendu définitivement',
                        code: 'ACCOUNT_BANNED_PERMANENT'
                    });
                }
            }

            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(400).json({
                    success: false,
                    error: 'Email ou mot de passe incorrect',
                    code: 'INVALID_CREDENTIALS'
                });
            }

            if (!user.email_verified && process.env.NODE_ENV === 'production') {
                return res.status(403).json({
                    success: false,
                    error: 'Email non vérifié',
                    requiresVerification: true,
                    code: 'EMAIL_NOT_VERIFIED'
                });
            }

            const today = getCurrentDate();
            let coinsReward = 0;
            let streakCount = user.daily_login_streak || 0;

            if (user.last_daily_login !== today) {
                const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
                
                const [baseReward, streakBonus] = await Promise.all([
                    new Promise(r => db.get('SELECT value FROM system_settings WHERE key = "daily_reward_base"', [], (e, row) => r(parseInt(row?.value) || 5))),
                    new Promise(r => db.get('SELECT value FROM system_settings WHERE key = "daily_reward_streak_bonus"', [], (e, row) => r(parseInt(row?.value) || 2)))
                ]);

                if (user.last_daily_login === yesterday) {
                    streakCount = (user.daily_login_streak || 0) + 1;
                    coinsReward = baseReward + streakBonus;
                } else {
                    streakCount = 1;
                    coinsReward = baseReward;
                }

                const accountAge = Math.floor((new Date() - new Date(user.account_created)) / (1000 * 60 * 60 * 24));
                if (accountAge === 365) coinsReward += 50;
                else if (accountAge === 100) coinsReward += 30;
                else if ((user.total_login_days + 1) % 7 === 0) coinsReward += 10;

                db.run(
                    `UPDATE users SET 
                        daily_login_streak = ?, 
                        last_daily_login = ?, 
                        total_login_days = total_login_days + 1, 
                        coins = coins + ?,
                        last_login = CURRENT_TIMESTAMP,
                        last_ip = ?
                    WHERE id = ?`,
                    [streakCount, today, coinsReward, req.ip, user.id]
                );

                db.run(
                    'INSERT INTO daily_rewards (user_id, reward_date, coins_earned, streak_count) VALUES (?, ?, ?, ?)',
                    [user.id, today, coinsReward, streakCount]
                );

                db.run(
                    'INSERT INTO user_activities (user_id, activity_type, coins_earned, description) VALUES (?, ?, ?, ?)',
                    [user.id, 'daily_login', coinsReward, `Connexion quotidienne - Série: ${streakCount} jours`]
                );

                user.coins += coinsReward;
            } else {
                db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP, last_ip = ? WHERE id = ?', [req.ip, user.id]);
            }

            updateUserBadges(user.id);

            const token = jwt.sign(
                { 
                    userId: user.id, 
                    username: user.username, 
                    email: user.email, 
                    role: user.role 
                },
                WEB_CONFIG.JWT_SECRET,
                { expiresIn: '24h' }
            );

            db.all(
                'SELECT id, server_name, server_type, env_type, server_status, expires_at, created_at, is_active, is_ephemeral FROM servers WHERE user_id = ? ORDER BY created_at DESC',
                [user.id],
                (err, servers) => {
                    res.json({
                        success: true,
                        token,
                        user: {
                            id: user.id,
                            publicId: user.public_id,
                            username: user.username,
                            email: user.email,
                            apiKey: user.api_key,
                            apiCallsToday: user.api_calls_today,
                            apiCallsLimit: PLANS_CONFIG[user.current_plan]?.api_calls_per_day || 50,
                            coins: user.coins,
                            role: user.role,
                            current_plan: user.current_plan,
                            referral_code: user.referral_code,
                            daily_login_streak: streakCount,
                            total_login_days: user.total_login_days + (user.last_daily_login !== today ? 1 : 0),
                            badges: JSON.parse(user.badges || '[]'),
                            level: user.level,
                            experience: user.experience,
                            email_verified: user.email_verified,
                            free_server_created: user.free_server_created
                        },
                        servers: servers || [],
                        daily_reward: coinsReward > 0 ? coinsReward : 0
                    });
                }
            );
        });
    } catch (error) {
        console.error('❌ Erreur login:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur serveur',
            code: 'INTERNAL_ERROR'
        });
    }
});

app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({
            success: false,
            error: 'Email requis',
            code: 'EMAIL_REQUIRED'
        });
    }

    db.get('SELECT id, username FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
            return res.status(500).json({
                success: false,
                error: 'Erreur serveur',
                code: 'SERVER_ERROR'
            });
        }

        if (!user) {
            return res.json({
                success: true,
                message: 'Si un compte existe avec cet email, un code de réinitialisation a été envoyé.'
            });
        }

        const resetCode = generateVerificationCode();
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

        db.run(
            'UPDATE users SET reset_password_code = ?, reset_password_code_expires = ? WHERE id = ?',
            [resetCode, expiresAt.toISOString(), user.id],
            async (err) => {
                if (err) {
                    return res.status(500).json({
                        success: false,
                        error: 'Erreur génération code',
                        code: 'CODE_GENERATION_ERROR'
                    });
                }

                await sendPasswordResetEmail(email, user.username, resetCode);

                res.json({
                    success: true,
                    message: 'Si un compte existe avec cet email, un code de réinitialisation a été envoyé.'
                });
            }
        );
    });
});

app.post('/api/reset-password', async (req, res) => {
    const { email, code, newPassword } = req.body;

    if (!email || !code || !newPassword) {
        return res.status(400).json({
            success: false,
            error: 'Email, code et nouveau mot de passe requis',
            code: 'MISSING_FIELDS'
        });
    }

    if (newPassword.length < 6) {
        return res.status(400).json({
            success: false,
            error: 'Le mot de passe doit contenir au moins 6 caractères',
            code: 'PASSWORD_TOO_SHORT'
        });
    }

    db.get(
        'SELECT id, reset_password_code, reset_password_code_expires FROM users WHERE email = ?',
        [email],
        async (err, user) => {
            if (err || !user) {
                return res.status(404).json({
                    success: false,
                    error: 'Utilisateur non trouvé',
                    code: 'USER_NOT_FOUND'
                });
            }

            const now = new Date();
            const codeExpires = new Date(user.reset_password_code_expires);

            if (now > codeExpires) {
                return res.status(400).json({
                    success: false,
                    error: 'Code expiré',
                    code: 'CODE_EXPIRED'
                });
            }

            if (user.reset_password_code !== code) {
                return res.status(400).json({
                    success: false,
                    error: 'Code incorrect',
                    code: 'INVALID_CODE'
                });
            }

            try {
                const hashedPassword = await bcrypt.hash(newPassword, 12);

                db.run(
                    'UPDATE users SET password = ?, reset_password_code = NULL, reset_password_code_expires = NULL WHERE id = ?',
                    [hashedPassword, user.id],
                    (err) => {
                        if (err) {
                            return res.status(500).json({
                                success: false,
                                error: 'Erreur réinitialisation',
                                code: 'PASSWORD_RESET_ERROR'
                            });
                        }

                        res.json({
                            success: true,
                            message: 'Mot de passe réinitialisé avec succès'
                        });
                    }
                );
            } catch (error) {
                res.status(500).json({
                    success: false,
                    error: 'Erreur traitement',
                    code: 'PASSWORD_HASH_ERROR'
                });
            }
        }
    );
});

// =============================================
// ROUTES UTILISATEUR
// =============================================

app.get('/api/user/me', authenticateToken, logApiCall, (req, res) => {
    const userId = req.user.userId;
    
    db.get(
        `SELECT id, public_id, username, email, coins, role, current_plan, referral_code, 
                created_at, last_login, api_key, api_calls_today, daily_login_streak, 
                total_login_days, badges, level, experience, free_server_created 
         FROM users WHERE id = ?`,
        [userId],
        (err, user) => {
            if (err || !user) {
                return res.status(404).json({
                    success: false,
                    error: 'Utilisateur non trouvé',
                    code: 'USER_NOT_FOUND'
                });
            }
            
            db.all(
                'SELECT id, server_name, server_type, env_type, server_status, expires_at, created_at, is_active, is_ephemeral FROM servers WHERE user_id = ? ORDER BY created_at DESC',
                [userId],
                (err, servers) => {
                    if (err) {
                        return res.status(500).json({
                            success: false,
                            error: 'Erreur base de données',
                            code: 'DATABASE_ERROR'
                        });
                    }
                    
                    res.json({ 
                        success: true, 
                        user: {
                            ...user,
                            api_calls_limit: PLANS_CONFIG[user.current_plan]?.api_calls_per_day || 50
                        }, 
                        servers: servers || [] 
                    });
                }
            );
        }
    );
});

app.post('/api/user/regenerate-api-key', authenticateToken, requireEmailVerification, (req, res) => {
    const userId = req.user.userId;
    
    db.get('SELECT username FROM users WHERE id = ?', [userId], (err, user) => {
        if (err || !user) {
            return res.status(404).json({
                success: false,
                error: 'Utilisateur non trouvé',
                code: 'USER_NOT_FOUND'
            });
        }

        const newApiKey = generateApiKey(user.username);

        db.run(
            'UPDATE users SET api_key = ?, api_key_last_reset = CURRENT_TIMESTAMP WHERE id = ?',
            [newApiKey, userId],
            function(err) {
                if (err) {
                    return res.status(500).json({
                        success: false,
                        error: 'Erreur régénération clé API',
                        code: 'API_KEY_REGENERATION_ERROR'
                    });
                }

                db.run(
                    'INSERT INTO user_activities (user_id, activity_type, description) VALUES (?, ?, ?)',
                    [userId, 'api_key_regenerated', 'Régénération de la clé API']
                );

                res.json({
                    success: true,
                    message: 'Clé API régénérée avec succès',
                    new_api_key: newApiKey
                });
            }
        );
    });
});

app.get('/api/user/activities', authenticateToken, logApiCall, (req, res) => {
    const userId = req.user.userId;
    const { limit = 20, offset = 0 } = req.query;

    db.all(
        'SELECT * FROM user_activities WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?',
        [userId, parseInt(limit), parseInt(offset)],
        (err, activities) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    error: 'Erreur récupération activités',
                    code: 'ACTIVITIES_FETCH_ERROR'
                });
            }

            db.get(
                'SELECT COUNT(*) as total FROM user_activities WHERE user_id = ?',
                [userId],
                (err, count) => {
                    res.json({
                        success: true,
                        activities: activities || [],
                        total: count?.total || 0,
                        limit: parseInt(limit),
                        offset: parseInt(offset)
                    });
                }
            );
        }
    );
});

app.get('/api/user/stats', authenticateToken, logApiCall, (req, res) => {
    const userId = req.user.userId;

    Promise.all([
        new Promise(r => db.get('SELECT COUNT(*) as total FROM servers WHERE user_id = ?', [userId], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as active FROM servers WHERE user_id = ? AND is_active = 1', [userId], (e, row) => r(row?.active || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM transactions WHERE user_id = ?', [userId], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT SUM(amount) as total_spent FROM transactions WHERE user_id = ? AND status = "completed"', [userId], (e, row) => r(row?.total_spent || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as referrals FROM referrals WHERE referrer_id = ?', [userId], (e, row) => r(row?.referrals || 0))),
        new Promise(r => db.get('SELECT SUM(coins_earned) as total_coins_earned FROM user_activities WHERE user_id = ? AND coins_earned > 0', [userId], (e, row) => r(row?.total_coins_earned || 0)))
    ]).then(([totalServers, activeServers, totalTransactions, totalSpent, totalReferrals, totalCoinsEarned]) => {
        res.json({
            success: true,
            stats: {
                servers: {
                    total: totalServers,
                    active: activeServers
                },
                transactions: {
                    total: totalTransactions,
                    total_spent: totalSpent
                },
                referrals: totalReferrals,
                coins_earned_total: totalCoinsEarned
            }
        });
    }).catch(error => {
        console.error('❌ Erreur stats:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur récupération statistiques',
            code: 'STATS_FETCH_ERROR'
        });
    });
});

// =============================================
// ROUTES SERVEURS
// =============================================

app.get('/api/servers', authenticateToken, logApiCall, (req, res) => {
    const userId = req.user.userId;
    
    db.all(
        `SELECT id, server_name, server_type, env_type, server_status, expires_at, created_at, is_active, is_ephemeral,
                server_identifier, custom_subdomain, alloc_port, alloc_ip, custom_domain
         FROM servers WHERE user_id = ? ORDER BY created_at DESC`,
        [userId],
        (err, servers) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    error: 'Erreur récupération serveurs',
                    code: 'SERVERS_FETCH_ERROR'
                });
            }
            res.json({ success: true, servers: servers || [] });
        }
    );
});

app.get('/api/servers/:serverId', authenticateToken, logApiCall, async (req, res) => {
    const { serverId } = req.params;
    const userId = req.user.userId;

    db.get(
        'SELECT * FROM servers WHERE id = ? AND user_id = ?',
        [serverId, userId],
        async (err, server) => {
            if (err || !server) {
                return res.status(404).json({
                    success: false,
                    error: 'Serveur non trouvé',
                    code: 'SERVER_NOT_FOUND'
                });
            }

            try {
                const status = await getServerPowerStatus(server.server_identifier);
                
                if (status.status !== server.server_status) {
                    db.run(
                        'UPDATE servers SET server_status = ? WHERE id = ?',
                        [status.status, serverId]
                    );
                    server.server_status = status.status;
                }

                const expiresAt = new Date(server.expires_at);
                const now = new Date();
                const daysLeft = Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24));
                const hoursLeft = Math.ceil((expiresAt - now) / (1000 * 60 * 60));

                res.json({
                    success: true,
                    server: {
                        id: server.id,
                        name: server.server_name,
                        type: server.server_type,
                        env_type: server.env_type || 'nodejs',
                        status: server.server_status,
                        expires_at: server.expires_at,
                        days_left: daysLeft,
                        hours_left: hoursLeft,
                        created_at: server.created_at,
                        is_active: server.is_active,
                        is_ephemeral: server.is_ephemeral === 1,
                        resources: status.resources ? {
                            cpu_usage: parseFloat(status.resources.cpu.toFixed(2)),
                            memory_used_mb: Math.round(status.resources.memory / 1024 / 1024),
                            memory_limit_mb: PLANS_CONFIG[server.server_type]?.memory || 0,
                            disk_used_mb: Math.round(status.resources.disk / 1024 / 1024),
                            disk_limit_mb: PLANS_CONFIG[server.server_type]?.disk || 0,
                            uptime_seconds: status.resources.uptime,
                            uptime_formatted: formatUptime(status.resources.uptime)
                        } : null
                    }
                });
            } catch (error) {
                console.error('❌ Erreur récupération serveur:', error);
                res.status(500).json({
                    success: false,
                    error: 'Erreur récupération du serveur',
                    code: 'SERVER_FETCH_ERROR'
                });
            }
        }
    );
});

// ===== CREDENTIALS PANEL =====
app.get('/api/servers/:serverId/credentials', authenticateToken, (req, res) => {
    const { serverId } = req.params;
    const userId = req.user.userId;
    db.get(
        'SELECT username, password, email FROM servers WHERE id = ? AND user_id = ?',
        [serverId, userId],
        (err, server) => {
            if (err || !server) return res.status(404).json({ success: false, error: 'Serveur non trouvé' });
            res.json({
                success: true,
                credentials: {
                    panel_url: PTERODACTYL_CONFIG.url,
                    username: server.username,
                    password: server.password
                }
            });
        }
    );
});

app.post('/api/servers/create', authenticateToken, requireEmailVerification, async (req, res) => {
    const { plan, api_key, server_name, promo_code, env_type = 'nodejs' } = req.body;
    const userId = req.user.userId;

    try {
        if (!plan || !api_key) {
            return res.status(400).json({
                success: false,
                error: 'Plan et api_key requis',
                code: 'MISSING_FIELDS'
            });
        }

        if (!PLANS_CONFIG[plan]) {
            return res.status(400).json({
                success: false,
                error: 'Plan invalide',
                code: 'INVALID_PLAN'
            });
        }

        if (!server_name || server_name.length < 3 || server_name.length > 30) {
            return res.status(400).json({
                success: false,
                error: 'Nom du serveur invalide (3-30 caractères)',
                code: 'INVALID_SERVER_NAME'
            });
        }

        const user = await new Promise((resolve, reject) => {
            db.get(
                'SELECT api_key, username, coins, free_server_created, current_plan, role FROM users WHERE id = ?',
                [userId],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });

        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'Utilisateur non trouvé',
                code: 'USER_NOT_FOUND'
            });
        }

        if (user.api_key !== api_key) {
            return res.status(403).json({
                success: false,
                error: 'Clé API invalide',
                code: 'INVALID_API_KEY'
            });
        }

        const isAdmin = user.role === 'admin' || user.role === 'superadmin';

        const serverCount = await new Promise((resolve) => {
            db.get('SELECT COUNT(*) as count FROM servers WHERE user_id = ? AND is_active = 1', [userId], (err, row) => {
                resolve(row?.count || 0);
            });
        });

        const maxServers = PLANS_CONFIG[user.current_plan]?.max_servers || 1;

        if (!isAdmin) {
            if (serverCount >= maxServers) {
                return res.status(400).json({
                    success: false,
                    error: `Vous avez atteint le nombre maximum de serveurs (${maxServers})`,
                    code: 'MAX_SERVERS_REACHED'
                });
            }
        }

        let planConfig = PLANS_CONFIG[plan];
        let isEphemeral = false;
        let promoCodeId = null;
        let promoCodeData = null;

        if (promo_code) {
            promoCodeData = await new Promise((resolve) => {
                db.get(
                    'SELECT * FROM promo_codes WHERE code = ? AND is_active = 1 AND (expires_at IS NULL OR expires_at > datetime("now"))',
                    [promo_code],
                    (err, row) => {
                        resolve(row);
                    }
                );
            });

            if (!promoCodeData) {
                return res.status(400).json({
                    success: false,
                    error: 'Code promo invalide ou expiré',
                    code: 'INVALID_PROMO_CODE'
                });
            }

            if (promoCodeData.current_uses >= promoCodeData.max_uses) {
                return res.status(400).json({
                    success: false,
                    error: 'Ce code promo a atteint sa limite d\'utilisations',
                    code: 'PROMO_CODE_LIMIT_REACHED'
                });
            }

            if (promoCodeData.server_type !== plan) {
                return res.status(400).json({
                    success: false,
                    error: `Ce code promo est valide uniquement pour les serveurs ${promoCodeData.server_type}`,
                    code: 'PROMO_CODE_WRONG_TYPE'
                });
            }

            planConfig = { ...PLANS_CONFIG[plan] };
            isEphemeral = true;
            promoCodeId = promoCodeData.id;
        }

        if (!isAdmin) {
            if (plan !== 'free' && !promoCodeId) {
                if (user.coins < planConfig.price) {
                    return res.status(400).json({
                        success: false,
                        error: `Coins insuffisants. Il vous faut ${planConfig.price} coins, vous avez ${user.coins} coins.`,
                        code: 'INSUFFICIENT_COINS'
                    });
                }
            }
        }

        if (plan === 'free' && !isAdmin) {
            const freeCount = await new Promise(resolve =>
                db.get(`SELECT COUNT(*) as cnt FROM servers WHERE user_id = ? AND server_type = 'free' AND is_active = 1`, [userId], (e, r) => resolve(r?.cnt || 0))
            );
            if (user.free_server_created || freeCount > 0) {
                return res.status(400).json({
                    success: false,
                    error: 'Vous avez déjà utilisé votre serveur gratuit. Un seul serveur gratuit est autorisé par compte.',
                    code: 'FREE_SERVER_ALREADY_USED'
                });
            }
        }

        // --- Cooldown anti-spam : 10 secondes entre créations ---
        if (!isAdmin) {
            const lastCreation = await new Promise(resolve =>
                db.get(`SELECT created_at FROM servers WHERE user_id = ? ORDER BY created_at DESC LIMIT 1`, [userId], (e, r) => resolve(r))
            );
            if (lastCreation) {
                const secsSinceLast = (Date.now() - new Date(lastCreation.created_at).getTime()) / 1000;
                if (secsSinceLast < 10) {
                    return res.status(429).json({
                        success: false,
                        error: `Veuillez attendre ${Math.ceil(10 - secsSinceLast)} secondes avant de créer un nouveau serveur.`,
                        code: 'CREATION_COOLDOWN'
                    });
                }
            }
        }

        // --- Déduction atomique des coins AVANT création Pterodactyl ---
        // Utilise WHERE coins >= price pour éviter les race conditions
        let coinsDeducted = false;
        const paidPlan = !isAdmin && plan !== 'free' && !promoCodeId;
        if (paidPlan) {
            const result = await new Promise((resolve, reject) => {
                db.run(
                    'UPDATE users SET coins = coins - ? WHERE id = ? AND coins >= ?',
                    [planConfig.price, userId, planConfig.price],
                    function(err) { if (err) reject(err); else resolve(this.changes); }
                );
            });
            if (result === 0) {
                return res.status(400).json({
                    success: false,
                    error: `Coins insuffisants. Il vous faut ${planConfig.price} coins.`,
                    code: 'INSUFFICIENT_COINS'
                });
            }
            coinsDeducted = true;
            db.run(
                `INSERT INTO coin_transactions (user_id, type, amount, balance_after, description, reference_id) VALUES (?, 'debit', ?, (SELECT coins FROM users WHERE id = ?), ?, ?)`,
                [userId, -planConfig.price, userId, `Création serveur ${plan} "${server_name}"`, `server_create_${Date.now()}`]
            );
        }

        let pteroUser, pteroServer;
        try {
            pteroUser = await createPterodactylUser(user.username);
            pteroServer = await createPterodactylServer({
                name: `${server_name}-${plan}-${Date.now().toString().slice(-4)}`,
                userId: pteroUser.id,
                memory: planConfig.memory,
                disk: planConfig.disk,
                cpu: planConfig.cpu,
                env_type: TECH_ENVIRONMENTS[env_type] ? env_type : 'nodejs'
            });
        } catch (pteroErr) {
            if (coinsDeducted) {
                db.run('UPDATE users SET coins = coins + ? WHERE id = ?', [planConfig.price, userId]);
                db.run(
                    `INSERT INTO coin_transactions (user_id, type, amount, balance_after, description, reference_id) VALUES (?, 'refund', ?, (SELECT coins FROM users WHERE id = ?), ?, ?)`,
                    [userId, planConfig.price, userId, `Remboursement - échec création serveur ${plan}`, `refund_${Date.now()}`]
                );
            }
            throw pteroErr;
        }

        let expiresAt = new Date();
        if (promoCodeId) {
            expiresAt.setHours(expiresAt.getHours() + promoCodeData.duration_hours);
        } else if (plan === 'free') {
            expiresAt.setHours(expiresAt.getHours() + 24);
        } else {
            expiresAt.setDate(expiresAt.getDate() + planConfig.duration);
        }

        if (plan === 'free' && !isAdmin) {
            await new Promise((resolve) => {
                db.run('UPDATE users SET free_server_created = TRUE WHERE id = ?', [userId], resolve);
            });
        }

        const serverId = await new Promise((resolve, reject) => {
            db.run(
                `INSERT INTO servers (
                    user_id, server_type, server_name, server_identifier, pterodactyl_id, 
                    username, password, email, expires_at, server_status, is_ephemeral, promo_code_used, env_type, alloc_port, alloc_ip
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    userId,
                    plan,
                    server_name,
                    pteroServer.identifier,
                    pteroServer.id,
                    pteroUser.username,
                    pteroUser.password,
                    pteroUser.email,
                    expiresAt.toISOString(),
                    'running',
                    isEphemeral ? 1 : 0,
                    promo_code || null,
                    env_type || 'nodejs',
                    pteroServer.alloc_port || null,
                    pteroServer.alloc_ip || null
                ],
                function(err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                }
            );
        });

        if (promoCodeId) {
            await new Promise((resolve) => {
                db.run(
                    'UPDATE promo_codes SET current_uses = current_uses + 1 WHERE id = ?',
                    [promoCodeId],
                    resolve
                );
            });

            await new Promise((resolve) => {
                db.run(
                    'INSERT INTO promo_code_uses (promo_code_id, user_id, server_id) VALUES (?, ?, ?)',
                    [promoCodeId, userId, serverId],
                    resolve
                );
            });
        }

        await new Promise((resolve) => {
            db.run(
                'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
                [serverId, 'created', `Serveur ${plan} créé${promoCodeId ? ' avec code promo' : ''}`],
                resolve
            );
        });

        await new Promise((resolve) => {
            db.run(
                'INSERT INTO user_activities (user_id, activity_type, coins_earned, description) VALUES (?, ?, ?, ?)',
                [
                    userId, 
                    promoCodeId ? 'server_created_promo' : 'server_created', 
                    promoCodeId ? 0 : -planConfig.price,
                    `Création serveur ${plan} "${server_name}"${promoCodeId ? ' (code promo)' : ''}`
                ],
                resolve
            );
        });

        await new Promise((resolve) => {
            db.run(
                'UPDATE users SET experience = experience + 10 WHERE id = ?',
                [userId],
                resolve
            );
        });

        const emailHtml = `
            <div style="font-family: Arial; max-width: 600px; margin: 0 auto; padding: 20px; background: #0f172a; color: #fff; border-radius: 10px;">
                <h1 style="color: #10b981;">✅ Serveur créé avec succès !</h1>
                <p>Bonjour ${user.username},</p>
                <p>Votre serveur <strong>"${server_name}"</strong> a été créé avec succès. Voici vos informations d'accès au panel :</p>
                <div style="background: #1e293b; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #10b981;">
                    <p style="margin:0 0 8px;font-size:15px;font-weight:bold;color:#10b981;">🖥️ Accès au Panel Pterodactyl</p>
                    <p style="margin:6px 0;"><strong>Lien :</strong> <a href="${PTERODACTYL_CONFIG.url}" style="color:#6366f1;">${PTERODACTYL_CONFIG.url}</a></p>
                    <p style="margin:6px 0;"><strong>Nom d'utilisateur :</strong> <code style="background:#0f172a;padding:2px 6px;border-radius:4px;">${pteroUser.username}</code></p>
                    <p style="margin:6px 0;"><strong>Mot de passe :</strong> <code style="background:#0f172a;padding:2px 6px;border-radius:4px;">${pteroUser.password}</code></p>
                </div>
                <div style="background: #1e293b; padding: 16px; border-radius: 8px; margin: 16px 0;">
                    <p style="margin:4px 0;"><strong>Plan :</strong> ${plan}</p>
                    <p style="margin:4px 0;"><strong>Expire le :</strong> ${expiresAt.toLocaleString('fr-FR')}</p>
                    ${promoCodeId ? '<p style="margin:4px 0;"><strong>Code promo utilisé :</strong> ' + promo_code + '</p>' : ''}
                </div>
                <p style="background:#f59e0b22;color:#f59e0b;border-radius:6px;padding:10px;font-size:13px;">⚠️ Conservez ces informations en lieu sûr. Le mot de passe ne sera plus affiché après cette notification.</p>
                <a href="${PTERODACTYL_CONFIG.url}" style="display: inline-block; background: #10b981; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; margin: 8px 4px 0 0;">Accéder au panel</a>
                <a href="https://flihost.site/dashboard" style="display: inline-block; background: #6366f1; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; margin-top: 8px;">Mon Dashboard FLYHOST</a>
                <p style="color: #94a3b8; font-size: 12px; margin-top: 20px;">FLYHOST - Hébergement de serveurs</p>
            </div>
        `;

        await sendEmail(user.email, `✅ Votre serveur "${server_name}" a été créé !`, emailHtml);

        res.json({
            success: true,
            message: promoCodeId ? 'Serveur créé avec votre code promo !' : `Serveur "${server_name}" créé avec succès`,
            server: {
                id: serverId,
                name: server_name,
                type: plan,
                status: 'running',
                expires_at: expiresAt.toISOString(),
                created_at: new Date().toISOString(),
                is_ephemeral: isEphemeral,
                promo_code_used: promo_code
            },
            credentials: {
                server_id: serverId,
                panel_url: PTERODACTYL_CONFIG.url,
                username: pteroUser.username,
                password: pteroUser.password
            },
            coins_deducted: promoCodeId ? 0 : (plan !== 'free' ? planConfig.price : 0)
        });

    } catch (error) {
        console.error('❌ Erreur création serveur:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur création serveur: ' + error.message,
            code: 'SERVER_CREATION_ERROR'
        });
    }
});

// Dans la route /api/servers/:serverId/power
app.post('/api/servers/:serverId/power', authenticateToken, requireEmailVerification, logApiCall, async (req, res) => {
    const { serverId } = req.params;
    const { action } = req.body;
    const userId = req.user.userId;

    // Actions autorisées (Pterodactyl supporte start, stop, restart, kill)
    const validActions = ['start', 'stop', 'restart', 'kill'];
    if (!validActions.includes(action)) {
        return res.status(400).json({
            success: false,
            error: 'Action invalide. Les actions valides sont: start, stop, restart, kill',
            code: 'INVALID_ACTION',
            valid_actions: validActions
        });
    }

    db.get(
        'SELECT * FROM servers WHERE id = ? AND user_id = ? AND is_active = 1',
        [serverId, userId],
        async (err, server) => {
            if (err || !server) {
                return res.status(404).json({
                    success: false,
                    error: 'Serveur non trouvé',
                    code: 'SERVER_NOT_FOUND'
                });
            }

            try {
                console.log(`🔄 Envoi action ${action} au serveur ${server.server_identifier} (ID: ${serverId})`);
                
                // Envoyer un log initial
                if (global.broadcastLog) {
                    global.broadcastLog(serverId, {
                        level: 'info',
                        message: `⏳ Envoi de la commande ${action}...`
                    });
                }

                // ✅ Envoyer l'action à Pterodactyl (sans modification)
                const success = await sendPowerAction(server.server_identifier, action);

                if (success) {
                    // ✅ Attendre un peu que l'action prenne effet
                    await new Promise(resolve => setTimeout(resolve, 3000));
                    
                    // ✅ Vérifier le nouveau statut jusqu'à 5 fois
                    let newStatus = 'unknown';
                    let attempts = 0;
                    const maxAttempts = 5;
                    
                    while (attempts < maxAttempts) {
                        const statusResult = await getServerPowerStatus(server.server_identifier);
                        newStatus = statusResult.status;
                        
                        console.log(`📊 Tentative ${attempts + 1}/${maxAttempts}: Statut = ${newStatus}`);
                        
                        // Si le statut a changé et n'est pas "unknown", on sort
                        if (newStatus !== 'unknown' && newStatus !== server.server_status) {
                            break;
                        }
                        
                        attempts++;
                        if (attempts < maxAttempts) {
                            await new Promise(resolve => setTimeout(resolve, 2000));
                        }
                    }
                    
                    console.log(`✅ Action ${action} terminée, nouveau statut: ${newStatus}`);
                    
                    // ✅ Mettre à jour la base de données avec le vrai statut
                    db.run(
                        'UPDATE servers SET server_status = ?, last_activity = CURRENT_TIMESTAMP WHERE id = ?', 
                        [newStatus, serverId]
                    );
                    
                    db.run(
                        'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
                        [serverId, 'power', `Action: ${action} (nouveau statut: ${newStatus})`]
                    );

                    // Envoyer un log via WebSocket
                    if (global.broadcastLog) {
                        global.broadcastLog(serverId, {
                            level: newStatus === 'running' ? 'success' : 'info',
                            message: `✅ Action ${action} exécutée - Serveur ${newStatus}`
                        });
                    }

                    res.json({
                        success: true,
                        message: `Action ${action} exécutée`,
                        action,
                        status: newStatus,
                        details: `Le serveur est maintenant ${newStatus === 'running' ? 'en ligne' : newStatus === 'stopped' ? 'arrêté' : 'en attente'}`
                    });
                } else {
                    throw new Error('Échec de l\'action - Pterodactyl a retourné une erreur');
                }
            } catch (error) {
                console.error(`❌ Erreur power pour serveur ${serverId}:`, error);
                
                if (global.broadcastLog) {
                    global.broadcastLog(serverId, {
                        level: 'error',
                        message: `❌ Erreur action ${action}: ${error.message}`
                    });
                }
                
                res.status(500).json({
                    success: false,
                    error: 'Erreur lors de l\'action sur le serveur',
                    code: 'POWER_ACTION_ERROR',
                    details: error.message
                });
            }
        }
    );
});

app.get('/api/servers/:serverId/stats', authenticateToken, logApiCall, async (req, res) => {
    const { serverId } = req.params;
    const userId = req.user.userId;

    db.get(
        'SELECT * FROM servers WHERE id = ? AND user_id = ?',
        [serverId, userId],
        async (err, server) => {
            if (err || !server) {
                return res.status(404).json({
                    success: false,
                    error: 'Serveur non trouvé',
                    code: 'SERVER_NOT_FOUND'
                });
            }

            try {
                const status = await getServerPowerStatus(server.server_identifier);

                db.all(
                    'SELECT action, details, created_at FROM server_logs WHERE server_id = ? ORDER BY created_at DESC LIMIT 20',
                    [serverId],
                    (err, logs) => {
                        res.json({
                            success: true,
                            stats: {
                                status: status.status,
                                resources: status.resources ? {
                                    cpu_usage: parseFloat(status.resources.cpu.toFixed(2)),
                                    memory_used_mb: Math.round(status.resources.memory / 1024 / 1024),
                                    memory_limit_mb: PLANS_CONFIG[server.server_type]?.memory || 0,
                                    disk_used_mb: Math.round(status.resources.disk / 1024 / 1024),
                                    disk_limit_mb: PLANS_CONFIG[server.server_type]?.disk || 0,
                                    uptime_seconds: status.resources.uptime,
                                    uptime_formatted: formatUptime(status.resources.uptime)
                                } : null,
                                recent_actions: logs || []
                            }
                        });
                    }
                );
            } catch (error) {
                console.error('❌ Erreur stats:', error);
                res.status(500).json({
                    success: false,
                    error: 'Erreur récupération statistiques',
                    code: 'STATS_FETCH_ERROR'
                });
            }
        }
    );
});

app.post('/api/servers/:serverId/renew', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const userId = req.user.userId;

    db.get(
        'SELECT * FROM servers WHERE id = ? AND user_id = ?',
        [serverId, userId],
        async (err, server) => {
            if (err || !server) {
                return res.status(404).json({
                    success: false,
                    error: 'Serveur non trouvé',
                    code: 'SERVER_NOT_FOUND'
                });
            }

            if (server.server_type === 'free') {
                return res.status(400).json({
                    success: false,
                    error: 'Les serveurs gratuits ne sont pas renouvelables',
                    code: 'FREE_SERVER_NOT_RENEWABLE'
                });
            }

            if (server.is_ephemeral) {
                return res.status(400).json({
                    success: false,
                    error: 'Les serveurs créés avec des codes promo ne sont pas renouvelables',
                    code: 'EPHEMERAL_SERVER_NOT_RENEWABLE'
                });
            }

            if (!server.is_active) {
                return res.status(400).json({
                    success: false,
                    error: 'Ce serveur n\'est plus actif',
                    code: 'SERVER_NOT_ACTIVE'
                });
            }

            const planConfig = PLANS_CONFIG[server.server_type];
            if (!planConfig) {
                return res.status(400).json({
                    success: false,
                    error: 'Type de plan invalide',
                    code: 'INVALID_PLAN_TYPE'
                });
            }

            const coinsCost = PLAN_COINS_PRICES[server.server_type];
            if (coinsCost === undefined) {
                return res.status(400).json({
                    success: false,
                    error: 'Prix non défini',
                    code: 'COINS_PRICE_UNDEFINED'
                });
            }

            db.get('SELECT coins, username, email, role FROM users WHERE id = ?', [userId], (err, user) => {
                if (err || !user) {
                    return res.status(404).json({
                        success: false,
                        error: 'Utilisateur non trouvé',
                        code: 'USER_NOT_FOUND'
                    });
                }

                const isAdmin = user.role === 'admin' || user.role === 'superadmin';

                if (!isAdmin) {
                    if (user.coins < coinsCost) {
                        return res.status(400).json({
                            success: false,
                            error: `Coins insuffisants. Il vous faut ${coinsCost} coins.`,
                            code: 'INSUFFICIENT_COINS'
                        });
                    }
                }

                const paymentId = 'RENEW_' + crypto.randomBytes(8).toString('hex').toUpperCase();

                db.serialize(() => {
                    db.run('BEGIN TRANSACTION');

                    db.run(
                        'INSERT INTO transactions (user_id, plan_key, server_name, amount, status, payment_id, is_renewal, renewed_server_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                        [userId, server.server_type, server.server_name, coinsCost, 'completed', paymentId, true, serverId],
                        function(err) {
                            if (err) {
                                db.run('ROLLBACK');
                                return res.status(500).json({
                                    success: false,
                                    error: 'Erreur renouvellement',
                                    code: 'RENEWAL_ERROR'
                                });
                            }

                            if (!isAdmin) {
                                db.run('UPDATE users SET coins = coins - ? WHERE id = ? AND coins >= ?', [coinsCost, userId, coinsCost]);
                            }

                            let newExpiresAt;
                            if (server.expires_at) {
                                newExpiresAt = new Date(server.expires_at);
                                newExpiresAt.setDate(newExpiresAt.getDate() + planConfig.duration);
                            } else {
                                newExpiresAt = new Date();
                                newExpiresAt.setDate(newExpiresAt.getDate() + planConfig.duration);
                            }

                            db.run(
                                'UPDATE servers SET expires_at = ?, warning_sent = 0, last_activity = CURRENT_TIMESTAMP WHERE id = ?',
                                [newExpiresAt.toISOString(), serverId]
                            );

                            db.run(
                                'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
                                [serverId, 'renewed', `Renouvelé pour ${planConfig.duration} jours`]
                            );

                            db.run(
                                'INSERT INTO user_activities (user_id, activity_type, coins_earned, description) VALUES (?, ?, ?, ?)',
                                [userId, 'server_renewal', -coinsCost, `Renouvellement "${server.server_name}"`]
                            );

                            db.run('COMMIT', (err) => {
                                if (err) {
                                    db.run('ROLLBACK');
                                    return res.status(500).json({
                                        success: false,
                                        error: 'Erreur validation',
                                        code: 'COMMIT_ERROR'
                                    });
                                }

                                const emailHtml = `
                                    <div style="font-family: Arial; max-width: 600px; margin: 0 auto; padding: 20px; background: #0f172a; color: #fff; border-radius: 10px;">
                                        <h1 style="color: #10b981;">✅ Renouvellement Confirmé !</h1>
                                        <p>Bonjour ${user.username},</p>
                                        <p>Votre serveur <strong>"${server.server_name}"</strong> a été renouvelé.</p>
                                        <div style="background: #1e293b; padding: 20px; border-radius: 8px; margin: 20px 0;">
                                            <p><strong>Nouvelle expiration:</strong> ${newExpiresAt.toLocaleString('fr-FR')}</p>
                                            <p><strong>Coins déduits:</strong> ${coinsCost}</p>
                                        </div>
                                        <p style="color: #94a3b8; font-size: 12px; margin-top: 20px;">FLYHOST - Hébergement de serveurs</p>
                                    </div>
                                `;

                                sendEmail(user.email, `✅ Serveur "${server.server_name}" renouvelé`, emailHtml);

                                res.json({
                                    success: true,
                                    message: `Serveur renouvelé pour ${planConfig.duration} jours`,
                                    new_expires_at: newExpiresAt.toISOString(),
                                    coins_deducted: isAdmin ? 0 : coinsCost,
                                    remaining_coins: user.coins - (isAdmin ? 0 : coinsCost)
                                });
                            });
                        }
                    );
                });
            });
        }
    );
});

// =============================================
// ROUTES GESTIONNAIRE DE FICHIERS
// =============================================

// Lister les fichiers d'un répertoire
app.get('/api/servers/:serverId/files/list', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { directory = '/' } = req.query;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        const data = await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/files/list?directory=${encodeURIComponent(directory)}`
        );

        const files = (data.data || []).map(item => ({
            name: item.attributes.name,
            size: item.attributes.size,
            is_directory: item.attributes.is_file === false,
            modified_at: item.attributes.modified_at,
            mode: item.attributes.mode
        }));

        res.json({
            success: true,
            files,
            path: directory
        });

    } catch (error) {
        console.error('❌ Erreur liste fichiers:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur récupération des fichiers',
            code: 'FILE_LIST_ERROR',
            details: error.message
        });
    }
});

// Lire le contenu d'un fichier
app.get('/api/servers/:serverId/files/content', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { path } = req.query;
    const userId = req.user.userId;

    if (!path) {
        return res.status(400).json({
            success: false,
            error: 'Chemin du fichier requis',
            code: 'PATH_REQUIRED'
        });
    }

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        const content = await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/files/contents?file=${encodeURIComponent(path)}`
        );

        res.json({
            success: true,
            content: typeof content === 'string' ? content : JSON.stringify(content, null, 2)
        });

    } catch (error) {
        console.error('❌ Erreur lecture fichier:', error);
        
        if (error.message.includes('404')) {
            return res.status(404).json({
                success: false,
                error: 'Fichier non trouvé',
                code: 'FILE_NOT_FOUND'
            });
        }

        res.status(500).json({
            success: false,
            error: 'Erreur lecture fichier',
            code: 'FILE_READ_ERROR',
            details: error.message
        });
    }
});

// Écrire un fichier
app.post('/api/servers/:serverId/files/write', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { path, content } = req.body;
    const userId = req.user.userId;

    if (!path) {
        return res.status(400).json({
            success: false,
            error: 'Chemin du fichier requis',
            code: 'PATH_REQUIRED'
        });
    }

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/files/write?file=${encodeURIComponent(path)}`,
            'POST',
            content || ''
        );

        // Journaliser l'action
        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'file_write', `Fichier modifié: ${path}`]
        );

        res.json({
            success: true,
            message: 'Fichier enregistré avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur écriture fichier:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur écriture fichier',
            code: 'FILE_WRITE_ERROR',
            details: error.message
        });
    }
});

// Upload de fichiers
app.post('/api/servers/:serverId/files/upload', authenticateToken, requireEmailVerification, upload.single('file'), async (req, res) => {
    const { serverId } = req.params;
    const { path } = req.body;
    const userId = req.user.userId;

    if (!req.file) {
        return res.status(400).json({
            success: false,
            error: 'Fichier requis',
            code: 'FILE_REQUIRED'
        });
    }

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        // Upload vers Pterodactyl
        await uploadZipToPterodactyl(server.server_identifier, req.file.path);

        // Journaliser
        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'file_upload', `Fichier uploadé: ${req.file.originalname}`]
        );

        res.json({
            success: true,
            message: 'Fichier uploadé avec succès',
            filename: req.file.originalname
        });

    } catch (error) {
        console.error('❌ Erreur upload fichier:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur upload fichier',
            code: 'FILE_UPLOAD_ERROR',
            details: error.message
        });
    } finally {
        // Nettoyer le fichier temporaire
        if (req.file && req.file.path) {
            fs.unlink(req.file.path, (err) => {
                if (err) console.error('Erreur suppression fichier temporaire:', err);
            });
        }
    }
});

// Supprimer un fichier/dossier
app.post('/api/servers/:serverId/files/delete', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { path } = req.body;
    const userId = req.user.userId;

    if (!path) {
        return res.status(400).json({
            success: false,
            error: 'Chemin requis',
            code: 'PATH_REQUIRED'
        });
    }

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        const filename = path.split('/').pop();

        await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/files/delete`,
            'POST',
            {
                root: '/',
                files: [filename]
            }
        );

        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'file_delete', `Fichier supprimé: ${path}`]
        );

        res.json({
            success: true,
            message: 'Fichier supprimé avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur suppression fichier:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur suppression fichier',
            code: 'FILE_DELETE_ERROR',
            details: error.message
        });
    }
});

// Créer un dossier
app.post('/api/servers/:serverId/files/mkdir', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { path } = req.body;
    const userId = req.user.userId;

    if (!path) {
        return res.status(400).json({
            success: false,
            error: 'Chemin du dossier requis',
            code: 'PATH_REQUIRED'
        });
    }

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/files/create-folder`,
            'POST',
            {
                root: '/',
                name: path.split('/').pop()
            }
        );

        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'file_mkdir', `Dossier créé: ${path}`]
        );

        res.json({
            success: true,
            message: 'Dossier créé avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur création dossier:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur création dossier',
            code: 'FILE_MKDIR_ERROR',
            details: error.message
        });
    }
});

// Renommer un fichier/dossier
app.post('/api/servers/:serverId/files/rename', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { old_path, new_name } = req.body;
    const userId = req.user.userId;

    if (!old_path || !new_name) {
        return res.status(400).json({
            success: false,
            error: 'Ancien chemin et nouveau nom requis',
            code: 'RENAME_PARAMS_REQUIRED'
        });
    }

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/files/rename`,
            'PUT',
            {
                root: '/',
                files: [
                    {
                        from: old_path.split('/').pop(),
                        to: new_name
                    }
                ]
            }
        );

        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'file_rename', `Fichier renommé: ${old_path} -> ${new_name}`]
        );

        res.json({
            success: true,
            message: 'Élément renommé avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur renommage:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur renommage',
            code: 'FILE_RENAME_ERROR',
            details: error.message
        });
    }
});

// Copier un fichier/dossier
app.post('/api/servers/:serverId/files/copy', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { source, destination } = req.body;
    const userId = req.user.userId;

    if (!source || !destination) {
        return res.status(400).json({
            success: false,
            error: 'Source et destination requis',
            code: 'COPY_PARAMS_REQUIRED'
        });
    }

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/files/copy`,
            'POST',
            {
                location: source
            }
        );

        res.json({
            success: true,
            message: 'Fichier copié avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur copie fichier:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur copie fichier',
            code: 'FILE_COPY_ERROR',
            details: error.message
        });
    }
});

// Compresser des fichiers/dossiers
app.post('/api/servers/:serverId/files/compress', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { files, root = '/' } = req.body;
    const userId = req.user.userId;

    if (!files || !files.length) {
        return res.status(400).json({
            success: false,
            error: 'Liste de fichiers requise',
            code: 'FILES_REQUIRED'
        });
    }

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/files/compress`,
            'POST',
            {
                root,
                files
            }
        );

        res.json({
            success: true,
            message: 'Compression démarrée'
        });

    } catch (error) {
        console.error('❌ Erreur compression:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur compression',
            code: 'FILE_COMPRESS_ERROR',
            details: error.message
        });
    }
});

// Décompresser un fichier
app.post('/api/servers/:serverId/files/decompress', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { file, root = '/' } = req.body;
    const userId = req.user.userId;

    if (!file) {
        return res.status(400).json({
            success: false,
            error: 'Fichier à décompresser requis',
            code: 'FILE_REQUIRED'
        });
    }

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/files/decompress`,
            'POST',
            {
                root,
                file
            }
        );

        res.json({
            success: true,
            message: 'Décompression démarrée'
        });

    } catch (error) {
        console.error('❌ Erreur décompression:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur décompression',
            code: 'FILE_DECOMPRESS_ERROR',
            details: error.message
        });
    }
});

// Télécharger un fichier
app.get('/api/servers/:serverId/files/download', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { path } = req.query;
    const userId = req.user.userId;

    if (!path) {
        return res.status(400).json({
            success: false,
            error: 'Chemin du fichier requis',
            code: 'PATH_REQUIRED'
        });
    }

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        // Obtenir l'URL de téléchargement
        const downloadResponse = await axios.get(
            `${PTERODACTYL_CONFIG.url}/api/client/servers/${server.server_identifier}/files/download`,
            {
                headers: {
                    'Authorization': `Bearer ${PTERODACTYL_CONFIG.clientApiKey}`,
                    'Accept': 'application/json'
                },
                params: { file: path },
                httpsAgent: new https.Agent({ rejectUnauthorized: false })
            }
        );

        const downloadUrl = downloadResponse.data?.attributes?.url;

        if (!downloadUrl) {
            throw new Error('URL de téléchargement non trouvée');
        }

        // Rediriger vers l'URL signée
        res.redirect(downloadUrl);

    } catch (error) {
        console.error('❌ Erreur téléchargement:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur téléchargement',
            code: 'FILE_DOWNLOAD_ERROR',
            details: error.message
        });
    }
});

// =============================================
// ROUTES SAUVEGARDES
// =============================================

// Lister les sauvegardes
app.get('/api/servers/:serverId/backups', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        const data = await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/backups`
        );

        const backups = (data.data || []).map(backup => ({
            id: backup.attributes.uuid,
            name: backup.attributes.name,
            size: backup.attributes.bytes,
            size_formatted: formatFileSize(backup.attributes.bytes),
            status: backup.attributes.completed_at ? 'completed' : backup.attributes.failed_at ? 'failed' : 'running',
            created_at: backup.attributes.created_at,
            completed_at: backup.attributes.completed_at,
            failed_at: backup.attributes.failed_at,
            checksum: backup.attributes.checksum,
            is_locked: backup.attributes.is_locked
        }));

        res.json({
            success: true,
            backups
        });

    } catch (error) {
        console.error('❌ Erreur récupération sauvegardes:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur récupération sauvegardes',
            code: 'BACKUPS_FETCH_ERROR',
            details: error.message
        });
    }
});

// Créer une sauvegarde
app.post('/api/servers/:serverId/backups', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { name, ignored = '' } = req.body;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        // Vérifier le nombre de sauvegardes existantes
        const existing = await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/backups`
        );

        const featureLimits = await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}`
        );

        const maxBackups = featureLimits.attributes?.feature_limits?.backups || 5;

        if (existing.data?.length >= maxBackups) {
            return res.status(400).json({
                success: false,
                error: `Nombre maximum de sauvegardes atteint (${maxBackups})`,
                code: 'MAX_BACKUPS_REACHED'
            });
        }

        const result = await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/backups`,
            'POST',
            {
                name: name || `backup-${Date.now()}`,
                ignored: ignored.split(',').map(i => i.trim()).filter(i => i)
            }
        );

        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'backup_create', `Sauvegarde créée: ${name || result.attributes?.name}`]
        );

        res.json({
            success: true,
            message: 'Sauvegarde démarrée',
            backup: {
                id: result.attributes?.uuid,
                name: result.attributes?.name
            }
        });

    } catch (error) {
        console.error('❌ Erreur création sauvegarde:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur création sauvegarde',
            code: 'BACKUP_CREATE_ERROR',
            details: error.message
        });
    }
});

// Détails d'une sauvegarde
app.get('/api/servers/:serverId/backups/:backupId', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId, backupId } = req.params;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        const data = await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/backups/${backupId}`
        );

        const backup = data.attributes;

        res.json({
            success: true,
            backup: {
                id: backup.uuid,
                name: backup.name,
                size: backup.bytes,
                size_formatted: formatFileSize(backup.bytes),
                status: backup.completed_at ? 'completed' : backup.failed_at ? 'failed' : 'running',
                created_at: backup.created_at,
                completed_at: backup.completed_at,
                failed_at: backup.failed_at,
                checksum: backup.checksum,
                is_locked: backup.is_locked,
                download_url: backup.completed_at ? `/api/servers/${serverId}/backups/${backupId}/download` : null
            }
        });

    } catch (error) {
        console.error('❌ Erreur récupération sauvegarde:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur récupération sauvegarde',
            code: 'BACKUP_FETCH_ERROR',
            details: error.message
        });
    }
});

// Télécharger une sauvegarde
app.get('/api/servers/:serverId/backups/:backupId/download', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId, backupId } = req.params;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        const data = await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/backups/${backupId}/download`
        );

        const downloadUrl = data.attributes?.url;

        if (!downloadUrl) {
            throw new Error('URL de téléchargement non trouvée');
        }

        res.redirect(downloadUrl);

    } catch (error) {
        console.error('❌ Erreur téléchargement sauvegarde:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur téléchargement sauvegarde',
            code: 'BACKUP_DOWNLOAD_ERROR',
            details: error.message
        });
    }
});

// Restaurer une sauvegarde
app.post('/api/servers/:serverId/backups/:backupId/restore', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId, backupId } = req.params;
    const { truncate = false } = req.body;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/backups/${backupId}/restore`,
            'POST',
            { truncate }
        );

        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'backup_restore', `Sauvegarde restaurée: ${backupId}`]
        );

        res.json({
            success: true,
            message: 'Restauration démarrée'
        });

    } catch (error) {
        console.error('❌ Erreur restauration sauvegarde:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur restauration sauvegarde',
            code: 'BACKUP_RESTORE_ERROR',
            details: error.message
        });
    }
});

// Supprimer une sauvegarde
app.delete('/api/servers/:serverId/backups/:backupId', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId, backupId } = req.params;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/backups/${backupId}`,
            'DELETE'
        );

        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'backup_delete', `Sauvegarde supprimée: ${backupId}`]
        );

        res.json({
            success: true,
            message: 'Sauvegarde supprimée'
        });

    } catch (error) {
        console.error('❌ Erreur suppression sauvegarde:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur suppression sauvegarde',
            code: 'BACKUP_DELETE_ERROR',
            details: error.message
        });
    }
});

// Verrouiller/Déverrouiller une sauvegarde
app.post('/api/servers/:serverId/backups/:backupId/lock', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId, backupId } = req.params;
    const { lock } = req.body;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/backups/${backupId}`,
            'POST',
            { lock }
        );

        res.json({
            success: true,
            message: lock ? 'Sauvegarde verrouillée' : 'Sauvegarde déverrouillée'
        });

    } catch (error) {
        console.error('❌ Erreur verrouillage sauvegarde:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur verrouillage sauvegarde',
            code: 'BACKUP_LOCK_ERROR',
            details: error.message
        });
    }
});

// =============================================
// ROUTES BASES DE DONNÉES
// =============================================

// Lister les bases de données
app.get('/api/servers/:serverId/databases', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        const data = await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/databases`
        );

        const databases = (data.data || []).map(db => ({
            id: db.attributes.id,
            name: db.attributes.name,
            username: db.attributes.username,
            host: db.attributes.host?.address || 'localhost',
            port: db.attributes.host?.port || 3306,
            connections_from: db.attributes.connections_from,
            max_connections: db.attributes.max_connections,
            status: 'active'
        }));

        res.json({
            success: true,
            databases
        });

    } catch (error) {
        console.error('❌ Erreur récupération bases de données:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur récupération bases de données',
            code: 'DATABASES_FETCH_ERROR',
            details: error.message
        });
    }
});

// Créer une base de données
app.post('/api/servers/:serverId/databases', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { name, remote = '%', max_connections = 5 } = req.body;
    const userId = req.user.userId;

    if (!name) {
        return res.status(400).json({
            success: false,
            error: 'Nom de la base de données requis',
            code: 'DATABASE_NAME_REQUIRED'
        });
    }

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        // Vérifier le nombre de bases existantes
        const existing = await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/databases`
        );

        const featureLimits = await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}`
        );

        const maxDatabases = featureLimits.attributes?.feature_limits?.databases || 5;

        if (existing.data?.length >= maxDatabases) {
            return res.status(400).json({
                success: false,
                error: `Nombre maximum de bases de données atteint (${maxDatabases})`,
                code: 'MAX_DATABASES_REACHED'
            });
        }

        const result = await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/databases`,
            'POST',
            {
                database: name,
                remote,
                max_connections
            }
        );

        // Journaliser
        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'database_create', `Base de données créée: ${name}`]
        );

        res.json({
            success: true,
            message: 'Base de données créée avec succès',
            database: {
                id: result.attributes.id,
                name: result.attributes.name,
                username: result.attributes.username,
                password: result.attributes.password,
                host: result.attributes.host?.address,
                port: result.attributes.host?.port,
                connection_url: `mysql://${result.attributes.username}:${result.attributes.password}@${result.attributes.host?.address}:${result.attributes.host?.port}/${result.attributes.name}`
            }
        });

    } catch (error) {
        console.error('❌ Erreur création base de données:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur création base de données',
            code: 'DATABASE_CREATE_ERROR',
            details: error.message
        });
    }
});

// Détails d'une base de données
app.get('/api/servers/:serverId/databases/:databaseId', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId, databaseId } = req.params;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        const data = await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/databases/${databaseId}`
        );

        const db = data.attributes;

        res.json({
            success: true,
            database: {
                id: db.id,
                name: db.name,
                username: db.username,
                password: db.password,
                host: db.host?.address,
                port: db.host?.port,
                connections_from: db.connections_from,
                max_connections: db.max_connections,
                created_at: db.created_at,
                updated_at: db.updated_at
            }
        });

    } catch (error) {
        console.error('❌ Erreur récupération base de données:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur récupération base de données',
            code: 'DATABASE_FETCH_ERROR',
            details: error.message
        });
    }
});

// Supprimer une base de données
app.delete('/api/servers/:serverId/databases/:databaseId', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId, databaseId } = req.params;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/databases/${databaseId}`,
            'DELETE'
        );

        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'database_delete', `Base de données supprimée ID: ${databaseId}`]
        );

        res.json({
            success: true,
            message: 'Base de données supprimée avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur suppression base de données:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur suppression base de données',
            code: 'DATABASE_DELETE_ERROR',
            details: error.message
        });
    }
});

// Réinitialiser le mot de passe d'une base de données
app.post('/api/servers/:serverId/databases/:databaseId/reset-password', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId, databaseId } = req.params;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        const result = await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/databases/${databaseId}/reset-password`,
            'POST'
        );

        res.json({
            success: true,
            message: 'Mot de passe réinitialisé',
            new_password: result.attributes?.password
        });

    } catch (error) {
        console.error('❌ Erreur réinitialisation mot de passe:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur réinitialisation mot de passe',
            code: 'DATABASE_PASSWORD_RESET_ERROR',
            details: error.message
        });
    }
});

// =============================================
// ROUTES ALLOCATIONS RÉSEAU
// =============================================

// Lister les allocations
// Modifier le sous-domaine personnalisé d'un serveur
app.put('/api/servers/:serverId/subdomain', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const userId = req.user.userId;
    const { subdomain } = req.body;

    if (subdomain && !/^[a-z0-9-]{3,32}$/.test(subdomain)) {
        return res.status(400).json({ success: false, error: 'Sous-domaine invalide. Utilisez uniquement des lettres minuscules, chiffres et tirets (3-32 caractères).' });
    }

    const server = await getServerByIdAndUser(serverId, userId);
    if (!server) return res.status(404).json({ success: false, error: 'Serveur non trouvé' });

    // Vérifier que le sous-domaine n'est pas déjà pris
    if (subdomain) {
        const taken = await new Promise(resolve =>
            db.get(`SELECT id FROM servers WHERE custom_subdomain = ? AND id != ?`, [subdomain, server.id], (e, r) => resolve(r))
        );
        if (taken) return res.status(409).json({ success: false, error: 'Ce sous-domaine est déjà utilisé par un autre serveur.' });
    }

    await new Promise((resolve, reject) =>
        db.run(`UPDATE servers SET custom_subdomain = ? WHERE id = ?`, [subdomain || null, server.id], (e) => e ? reject(e) : resolve())
    );

    // Invalider le cache proxy
    subdomainCache.delete(server.server_identifier);
    if (server.custom_subdomain) subdomainCache.delete(server.custom_subdomain);

    res.json({ success: true, subdomain: subdomain ? `${subdomain}.flihost.site` : `${server.server_identifier}.flihost.site` });
});

app.put('/api/servers/:serverId/custom-domain', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const userId = req.user.userId;
    const { domain } = req.body;

    if (domain && !/^([a-z0-9-]+\.)+[a-z]{2,}$/.test(domain.toLowerCase())) {
        return res.status(400).json({ success: false, error: 'Domaine invalide. Exemple : monsite.com ou app.monsite.com' });
    }

    const server = await getServerByIdAndUser(serverId, userId);
    if (!server) return res.status(404).json({ success: false, error: 'Serveur non trouvé' });

    const cleanDomain = domain ? domain.toLowerCase().trim() : null;

    if (cleanDomain) {
        const taken = await new Promise(resolve =>
            db.get(`SELECT id FROM servers WHERE custom_domain = ? AND id != ?`, [cleanDomain, server.id], (e, r) => resolve(r))
        );
        if (taken) return res.status(409).json({ success: false, error: 'Ce domaine est déjà utilisé par un autre serveur.' });
    }

    await new Promise((resolve, reject) =>
        db.run(`UPDATE servers SET custom_domain = ? WHERE id = ?`, [cleanDomain, server.id], (e) => e ? reject(e) : resolve())
    );

    if (server.custom_domain) subdomainCache.delete('domain:' + server.custom_domain);
    if (cleanDomain) subdomainCache.delete('domain:' + cleanDomain);

    res.json({ success: true, custom_domain: cleanDomain || null });
});

app.get('/api/servers/:serverId/allocations', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        const data = await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/network/allocations`
        );

        const allocations = (data.data || []).map(alloc => ({
            id: alloc.attributes.id,
            ip: alloc.attributes.ip,
            port: alloc.attributes.port,
            ip_alias: alloc.attributes.ip_alias,
            notes: alloc.attributes.notes,
            is_default: alloc.attributes.is_default,
            assigned: alloc.attributes.assigned
        }));

        res.json({
            success: true,
            allocations
        });

    } catch (error) {
        console.error('❌ Erreur récupération allocations:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur récupération allocations',
            code: 'ALLOCATIONS_FETCH_ERROR',
            details: error.message
        });
    }
});

// Créer une allocation
app.post('/api/servers/:serverId/allocations', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { port } = req.body;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        const result = await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/network/allocations`,
            'POST',
            port ? { port } : {}
        );

        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'allocation_create', `Allocation créée: ${result.attributes?.ip}:${result.attributes?.port}`]
        );

        res.json({
            success: true,
            message: 'Allocation créée',
            allocation: {
                id: result.attributes?.id,
                ip: result.attributes?.ip,
                port: result.attributes?.port,
                is_default: result.attributes?.is_default
            }
        });

    } catch (error) {
        console.error('❌ Erreur création allocation:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur création allocation',
            code: 'ALLOCATION_CREATE_ERROR',
            details: error.message
        });
    }
});

// Définir une allocation comme default
app.post('/api/servers/:serverId/allocations/:allocationId/default', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId, allocationId } = req.params;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/network/allocations/${allocationId}`,
            'POST',
            { is_default: true }
        );

        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'allocation_set_default', `Allocation ${allocationId} définie par défaut`]
        );

        res.json({
            success: true,
            message: 'Allocation définie par défaut'
        });

    } catch (error) {
        console.error('❌ Erreur définition allocation par défaut:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur définition allocation par défaut',
            code: 'ALLOCATION_SET_DEFAULT_ERROR',
            details: error.message
        });
    }
});

// Supprimer une allocation
app.delete('/api/servers/:serverId/allocations/:allocationId', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId, allocationId } = req.params;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/network/allocations/${allocationId}`,
            'DELETE'
        );

        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'allocation_delete', `Allocation supprimée: ${allocationId}`]
        );

        res.json({
            success: true,
            message: 'Allocation supprimée'
        });

    } catch (error) {
        console.error('❌ Erreur suppression allocation:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur suppression allocation',
            code: 'ALLOCATION_DELETE_ERROR',
            details: error.message
        });
    }
});

// Mettre à jour les notes d'une allocation
app.put('/api/servers/:serverId/allocations/:allocationId/notes', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId, allocationId } = req.params;
    const { notes } = req.body;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/network/allocations/${allocationId}`,
            'POST',
            { notes }
        );

        res.json({
            success: true,
            message: 'Notes mises à jour'
        });

    } catch (error) {
        console.error('❌ Erreur mise à jour notes allocation:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur mise à jour notes',
            code: 'ALLOCATION_NOTES_ERROR',
            details: error.message
        });
    }
});

// Définir un alias IP
app.put('/api/servers/:serverId/allocations/:allocationId/alias', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId, allocationId } = req.params;
    const { ip_alias } = req.body;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/network/allocations/${allocationId}`,
            'POST',
            { ip_alias }
        );

        res.json({
            success: true,
            message: 'Alias IP défini'
        });

    } catch (error) {
        console.error('❌ Erreur définition alias IP:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur définition alias IP',
            code: 'ALLOCATION_ALIAS_ERROR',
            details: error.message
        });
    }
});

// =============================================
// ROUTES COMMANDES ET CONFIGURATION
// =============================================

// Envoyer une commande au serveur
app.post('/api/servers/:serverId/command', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { command } = req.body;
    const userId = req.user.userId;

    if (!command) {
        return res.status(400).json({
            success: false,
            error: 'Commande requise',
            code: 'COMMAND_REQUIRED'
        });
    }

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        // Vérifier que le serveur est en ligne
        const status = await getServerPowerStatus(server.server_identifier);
        if (status.status !== 'running') {
            return res.status(400).json({
                success: false,
                error: 'Le serveur doit être en ligne pour exécuter des commandes',
                code: 'SERVER_NOT_RUNNING'
            });
        }

        await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/command`,
            'POST',
            { command }
        );

        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'command', `Commande exécutée: ${command.substring(0, 50)}...`]
        );

        // Diffuser via WebSocket
        if (global.broadcastLog) {
            global.broadcastLog(serverId, {
                level: 'info',
                message: `> ${command}`
            });
        }

        res.json({
            success: true,
            message: 'Commande envoyée'
        });

    } catch (error) {
        console.error('❌ Erreur envoi commande:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur envoi commande',
            code: 'COMMAND_SEND_ERROR',
            details: error.message
        });
    }
});

// Renommer un serveur
app.post('/api/servers/:serverId/rename', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { name } = req.body;
    const userId = req.user.userId;

    if (!name) {
        return res.status(400).json({
            success: false,
            error: 'Nouveau nom requis',
            code: 'NAME_REQUIRED'
        });
    }

    if (name.length < 3 || name.length > 30) {
        return res.status(400).json({
            success: false,
            error: 'Le nom doit contenir entre 3 et 30 caractères',
            code: 'INVALID_NAME_LENGTH'
        });
    }

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        // Mettre à jour dans Pterodactyl
        await callPterodactylAPI(
            `/api/application/servers/${server.pterodactyl_id}/details`,
            'PATCH',
            { name }
        );

        // Mettre à jour dans la base de données
        await new Promise((resolve, reject) => {
            db.run(
                'UPDATE servers SET server_name = ? WHERE id = ?',
                [name, serverId],
                function(err) {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });

        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'rename', `Serveur renommé: "${server.server_name}" -> "${name}"`]
        );

        res.json({
            success: true,
            message: 'Serveur renommé avec succès',
            new_name: name
        });

    } catch (error) {
        console.error('❌ Erreur renommage serveur:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur renommage serveur',
            code: 'SERVER_RENAME_ERROR',
            details: error.message
        });
    }
});

// Mettre à jour les notes du serveur
app.post('/api/servers/:serverId/notes', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { notes } = req.body;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylAPI(
            `/api/application/servers/${server.pterodactyl_id}/details`,
            'PATCH',
            { description: notes || '' }
        );

        res.json({
            success: true,
            message: 'Notes mises à jour'
        });

    } catch (error) {
        console.error('❌ Erreur mise à jour notes:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur mise à jour notes',
            code: 'SERVER_NOTES_ERROR',
            details: error.message
        });
    }
});

// Mettre à jour la limite de mémoire
app.post('/api/servers/:serverId/limits/memory', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { memory } = req.body;
    const userId = req.user.userId;

    if (!memory || memory < 256) {
        return res.status(400).json({
            success: false,
            error: 'Limite mémoire invalide (minimum 256 MB)',
            code: 'INVALID_MEMORY_LIMIT'
        });
    }

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylAPI(
            `/api/application/servers/${server.pterodactyl_id}/build`,
            'PATCH',
            { memory: parseInt(memory) }
        );

        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'limit_memory', `Mémoire modifiée: ${memory} MB`]
        );

        res.json({
            success: true,
            message: 'Limite mémoire mise à jour'
        });

    } catch (error) {
        console.error('❌ Erreur mise à jour mémoire:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur mise à jour mémoire',
            code: 'SERVER_MEMORY_ERROR',
            details: error.message
        });
    }
});

// Mettre à jour la limite de disque
app.post('/api/servers/:serverId/limits/disk', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { disk } = req.body;
    const userId = req.user.userId;

    if (!disk || disk < 5120) {
        return res.status(400).json({
            success: false,
            error: 'Limite disque invalide (minimum 5120 MB)',
            code: 'INVALID_DISK_LIMIT'
        });
    }

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylAPI(
            `/api/application/servers/${server.pterodactyl_id}/build`,
            'PATCH',
            { disk: parseInt(disk) }
        );

        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'limit_disk', `Disque modifié: ${disk} MB`]
        );

        res.json({
            success: true,
            message: 'Limite disque mise à jour'
        });

    } catch (error) {
        console.error('❌ Erreur mise à jour disque:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur mise à jour disque',
            code: 'SERVER_DISK_ERROR',
            details: error.message
        });
    }
});

// Mettre à jour la limite CPU
app.post('/api/servers/:serverId/limits/cpu', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { cpu } = req.body;
    const userId = req.user.userId;

    if (!cpu || cpu < 50) {
        return res.status(400).json({
            success: false,
            error: 'Limite CPU invalide (minimum 50%)',
            code: 'INVALID_CPU_LIMIT'
        });
    }

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylAPI(
            `/api/application/servers/${server.pterodactyl_id}/build`,
            'PATCH',
            { cpu: parseInt(cpu) }
        );

        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'limit_cpu', `CPU modifié: ${cpu}%`]
        );

        res.json({
            success: true,
            message: 'Limite CPU mise à jour'
        });

    } catch (error) {
        console.error('❌ Erreur mise à jour CPU:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur mise à jour CPU',
            code: 'SERVER_CPU_ERROR',
            details: error.message
        });
    }
});

// Mettre à jour les feature limits
app.post('/api/servers/:serverId/limits/features', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { databases, backups, allocations } = req.body;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        const featureLimits = {};
        if (databases !== undefined) featureLimits.databases = parseInt(databases);
        if (backups !== undefined) featureLimits.backups = parseInt(backups);
        if (allocations !== undefined) featureLimits.allocations = parseInt(allocations);

        await callPterodactylAPI(
            `/api/application/servers/${server.pterodactyl_id}/build`,
            'PATCH',
            { feature_limits: featureLimits }
        );

        res.json({
            success: true,
            message: 'Limites mises à jour'
        });

    } catch (error) {
        console.error('❌ Erreur mise à jour feature limits:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur mise à jour feature limits',
            code: 'SERVER_FEATURE_LIMITS_ERROR',
            details: error.message
        });
    }
});

// Démarrer/Arrêter le redémarrage automatique
app.post('/api/servers/:serverId/auto-start', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { enabled } = req.body;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        // Cette fonctionnalité nécessite un champ dans la table servers
        // Ajouter la colonne auto_start si elle n'existe pas
        await new Promise((resolve, reject) => {
            db.run(
                `ALTER TABLE servers ADD COLUMN auto_start BOOLEAN DEFAULT FALSE`,
                (err) => {
                    // Ignorer si la colonne existe déjà
                    if (err && !err.message.includes('duplicate column name')) {
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });

        await new Promise((resolve, reject) => {
            db.run(
                'UPDATE servers SET auto_start = ? WHERE id = ?',
                [enabled ? 1 : 0, serverId],
                function(err) {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });

        res.json({
            success: true,
            message: enabled ? 'Démarrage automatique activé' : 'Démarrage automatique désactivé'
        });

    } catch (error) {
        console.error('❌ Erreur mise à jour auto-start:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur mise à jour auto-start',
            code: 'SERVER_AUTO_START_ERROR',
            details: error.message
        });
    }
});

// Récupérer la configuration du serveur
app.get('/api/servers/:serverId/config', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        const data = await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}`
        );

        const serverData = data.attributes;

        // Récupérer les paramètres auto_start de la base
        const autoStart = await new Promise(r => {
            db.get('SELECT auto_start FROM servers WHERE id = ?', [serverId], (err, row) => {
                r(row?.auto_start || false);
            });
        });

        res.json({
            success: true,
            config: {
                name: serverData.name,
                description: serverData.description,
                uuid: serverData.uuid,
                node: serverData.node,
                sftp_details: serverData.sftp_details,
                limits: serverData.limits,
                feature_limits: serverData.feature_limits,
                egg: serverData.egg,
                docker_image: serverData.container?.image,
                startup_command: serverData.container?.startup_command,
                environment: serverData.container?.environment,
                auto_start: autoStart,
                installed: serverData.is_installed,
                suspended: serverData.is_suspended
            }
        });

    } catch (error) {
        console.error('❌ Erreur récupération config:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur récupération configuration',
            code: 'SERVER_CONFIG_ERROR',
            details: error.message
        });
    }
});

// Mettre à jour la startup command
app.post('/api/servers/:serverId/startup', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { command } = req.body;
    const userId = req.user.userId;

    if (!command) {
        return res.status(400).json({
            success: false,
            error: 'Commande de démarrage requise',
            code: 'STARTUP_COMMAND_REQUIRED'
        });
    }

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/startup`,
            'PATCH',
            { command }
        );

        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'startup_update', 'Commande de démarrage mise à jour']
        );

        res.json({
            success: true,
            message: 'Commande de démarrage mise à jour'
        });

    } catch (error) {
        console.error('❌ Erreur mise à jour startup:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur mise à jour commande de démarrage',
            code: 'SERVER_STARTUP_ERROR',
            details: error.message
        });
    }
});

// Mettre à jour l'image Docker
app.post('/api/servers/:serverId/docker-image', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const { image } = req.body;
    const userId = req.user.userId;

    if (!image) {
        return res.status(400).json({
            success: false,
            error: 'Image Docker requise',
            code: 'DOCKER_IMAGE_REQUIRED'
        });
    }

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/settings/docker-image`,
            'POST',
            { docker_image: image }
        );

        db.run(
            'INSERT INTO server_logs (server_id, action, details) VALUES (?, ?, ?)',
            [serverId, 'docker_image', `Image Docker changée: ${image}`]
        );

        res.json({
            success: true,
            message: 'Image Docker mise à jour'
        });

    } catch (error) {
        console.error('❌ Erreur mise à jour image Docker:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur mise à jour image Docker',
            code: 'SERVER_DOCKER_IMAGE_ERROR',
            details: error.message
        });
    }
});

// =============================================
// SUPPRESSION DE SERVEUR (COMPLÈTE)
// =============================================

// Supprimer un serveur (version complète)
app.delete('/api/servers/:serverId', authenticateToken, requireEmailVerification, async (req, res) => {
    const { serverId } = req.params;
    const userId = req.user.userId;

    try {
        const server = await getServerByIdAndUser(serverId, userId);
        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        // Vérifier si le serveur est protégé
        if (server.is_admin_server && req.user.role !== 'superadmin') {
            return res.status(403).json({
                success: false,
                error: 'Ce serveur est protégé et ne peut pas être supprimé',
                code: 'SERVER_PROTECTED'
            });
        }

        // 1. Supprimer sur Pterodactyl
        const pteroDeleted = await deletePterodactylServer(server.pterodactyl_id);
        if (!pteroDeleted) {
            console.warn(`⚠️ Impossible de supprimer le serveur Pterodactyl ${server.pterodactyl_id}, suppression forcée de la BD`);
        }

        // 2. Supprimer les déploiements associés
        await new Promise((resolve) => {
            db.run('DELETE FROM deployments WHERE server_id = ?', [serverId], resolve);
        });

        // 3. Supprimer les snapshots
        await new Promise((resolve) => {
            db.all('SELECT snapshot_path FROM deployment_snapshots WHERE deployment_id IN (SELECT id FROM deployments WHERE server_id = ?)', [serverId], (err, snapshots) => {
                if (snapshots) {
                    snapshots.forEach(s => {
                        if (s.snapshot_path && fs.existsSync(s.snapshot_path)) {
                            fs.unlink(s.snapshot_path, () => {});
                        }
                    });
                }
                resolve();
            });
        });

        // 4. Supprimer les logs du serveur
        await new Promise((resolve) => {
            db.run('DELETE FROM server_logs WHERE server_id = ?', [serverId], resolve);
        });

        // 5. Supprimer les utilisations de codes promo
        await new Promise((resolve) => {
            db.run('DELETE FROM promo_code_uses WHERE server_id = ?', [serverId], resolve);
        });

        // 6. Supprimer le serveur lui-même
        await new Promise((resolve, reject) => {
            db.run('DELETE FROM servers WHERE id = ?', [serverId], function(err) {
                if (err) reject(err);
                else resolve();
            });
        });

        // 7. Journaliser
        db.run(
            'INSERT INTO user_activities (user_id, activity_type, description) VALUES (?, ?, ?)',
            [userId, 'server_deleted', `Serveur supprimé: "${server.server_name}"`]
        );

        res.json({
            success: true,
            message: 'Serveur supprimé avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur suppression serveur:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur suppression serveur',
            code: 'SERVER_DELETE_ERROR',
            details: error.message
        });
    }
});

// Forcer la suppression d'un serveur (superadmin uniquement)
app.delete('/api/admin/servers/:serverId/force', authenticateToken, requireSuperAdmin, async (req, res) => {
    const { serverId } = req.params;

    try {
        const server = await new Promise(r => {
            db.get('SELECT * FROM servers WHERE id = ?', [serverId], (err, row) => r(row));
        });

        if (!server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé',
                code: 'SERVER_NOT_FOUND'
            });
        }

        // Forcer la suppression Pterodactyl (même si échec, on continue)
        try {
            await deletePterodactylServer(server.pterodactyl_id);
        } catch (e) {
            console.warn('⚠️ Erreur suppression Pterodactyl ignorée:', e.message);
        }

        // Supprimer toutes les traces
        db.run('DELETE FROM deployments WHERE server_id = ?', [serverId]);
        db.run('DELETE FROM server_logs WHERE server_id = ?', [serverId]);
        db.run('DELETE FROM promo_code_uses WHERE server_id = ?', [serverId]);
        db.run('DELETE FROM servers WHERE id = ?', [serverId]);

        logAdminAction(
            req.user.userId,
            'force_delete_server',
            'server',
            serverId,
            `Suppression forcée du serveur "${server.server_name}"`
        );

        res.json({
            success: true,
            message: 'Serveur supprimé avec force'
        });

    } catch (error) {
        console.error('❌ Erreur suppression forcée:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur suppression forcée',
            code: 'FORCE_DELETE_ERROR',
            details: error.message
        });
    }
});

// =============================================
// ROUTES TEMPLATE ET GITHUB
// =============================================

app.get('/api/template/meta', async (req, res) => {
    const { repo } = req.query;
    if (!repo) {
        return res.status(400).json({ 
            success: false, 
            error: 'Paramètre repo requis' 
        });
    }

    const match = repo.match(/github\.com\/([^/]+)\/([^/]+)/);
    if (!match) {
        return res.status(400).json({ 
            success: false, 
            error: 'URL GitHub invalide' 
        });
    }
    
    const [, owner, repoName] = match;
    const cleanRepo = repoName.replace(/\.git$/, '');

    try {
        const response = await axios.get(
            `https://api.github.com/repos/${owner}/${cleanRepo}/contents/flyhost.json`,
            { 
                headers: { 
                    Accept: 'application/vnd.github.v3.raw', 
                    'User-Agent': 'FLYHOST' 
                } 
            }
        );

        let config;
        try {
            const raw = typeof response.data === 'string' ? response.data : Buffer.from(response.data.content, 'base64').toString('utf8');
            config = JSON.parse(raw);
        } catch(e) {
            return res.status(400).json({ 
                success: false, 
                error: 'flyhost.json invalide (JSON malformé)' 
            });
        }

        if (!config.name || !config.start) {
            return res.status(400).json({ 
                success: false, 
                error: 'flyhost.json incomplet (name et start requis)' 
            });
        }

        res.json({
            success: true,
            template: {
                name: config.name,
                description: config.description || '',
                author: config.author || owner,
                version: config.version || '1.0.0',
                runtime: config.runtime || 'node',
                start: config.start,
                build: config.build || 'npm install',
                repo_url: repo,
                env_schema: config.env_schema || [],
                recommended_plan: config.recommended_plan || '1gb'
            }
        });
    } catch(e) {
        if (e.response?.status === 404) {
            return res.status(404).json({ 
                success: false, 
                error: 'flyhost.json introuvable dans ce repo. Assurez-vous que le fichier existe à la racine.' 
            });
        }
        res.status(500).json({ 
            success: false, 
            error: 'Erreur lecture du repo GitHub' 
        });
    }
});

app.get('/api/github/auth', authenticateToken, (req, res) => {
    const state = crypto.randomBytes(16).toString('hex');
    const returnTo = req.query.return_to || '/profile';
    db.run(
        'INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)', 
        [`github_oauth_state_${req.user.userId}`, `${state}:${returnTo}`]
    );
    const dynamicRedirectUri = `${req.protocol}://${req.get('host')}/api/github/callback`;
    const authUrl = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CONFIG.client_id}&redirect_uri=${encodeURIComponent(dynamicRedirectUri)}&scope=${encodeURIComponent(GITHUB_CONFIG.scope)}&state=${state}`;
    res.json({ success: true, auth_url: authUrl });
});

app.get('/api/github/callback', async (req, res) => {
    const { code, state } = req.query;
    try {
        const setting = await new Promise(r => 
            db.get(
                'SELECT value, key FROM system_settings WHERE key LIKE "github_oauth_state_%" AND (value = ? OR value LIKE ?)', 
                [state, `${state}:%`], 
                (e, row) => r(row)
            )
        );
        if (!setting) return res.redirect('/profile?error=github_state_invalid');
        const userId = setting.key.replace('github_oauth_state_', '');
        const [, returnTo] = setting.value.split(':');
        const redirectPage = returnTo || '/profile';

        const tokenRes = await axios.post('https://github.com/login/oauth/access_token', {
            client_id: GITHUB_CONFIG.client_id,
            client_secret: GITHUB_CONFIG.client_secret,
            code
        }, { headers: { Accept: 'application/json' } });

        const accessToken = tokenRes.data.access_token;
        if (!accessToken) return res.redirect(`${redirectPage}?error=github_token_failed`);

        const ghUser = await axios.get('https://api.github.com/user', { 
            headers: { Authorization: `Bearer ${accessToken}` } 
        });
        const { id: githubId, login: githubUsername, email: githubEmail } = ghUser.data;

        db.run(
            'INSERT OR REPLACE INTO github_connections (user_id, github_id, github_username, github_email, access_token, updated_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)',
            [userId, githubId, githubUsername, githubEmail, accessToken]
        );
        db.run('DELETE FROM system_settings WHERE key = ?', [setting.key]);

        res.redirect(`${redirectPage}?github=connected&username=${encodeURIComponent(githubUsername)}`);
    } catch(e) {
        console.error('GitHub OAuth error:', e);
        res.redirect('/profile?error=github_oauth_failed');
    }
});

app.get('/api/github/status', authenticateToken, (req, res) => {
    db.get(
        'SELECT github_username, github_email, connected_at FROM github_connections WHERE user_id = ?', 
        [req.user.userId], 
        (err, conn) => {
            res.json({ success: true, connected: !!conn, github: conn || null });
        }
    );
});

app.delete('/api/github/disconnect', authenticateToken, (req, res) => {
    db.run('DELETE FROM github_connections WHERE user_id = ?', [req.user.userId], function(err) {
        if (err) return res.status(500).json({ success: false, error: 'Erreur' });
        res.json({ success: true, message: 'GitHub déconnecté' });
    });
});

app.get('/api/github/repos', authenticateToken, async (req, res) => {
    const conn = await new Promise(r => 
        db.get('SELECT access_token FROM github_connections WHERE user_id = ?', [req.user.userId], (e, row) => r(row))
    );
    if (!conn) {
        return res.status(401).json({ 
            success: false, 
            error: 'GitHub non connecté', 
            code: 'GITHUB_NOT_CONNECTED' 
        });
    }
    try {
        const response = await axios.get('https://api.github.com/user/repos', {
            headers: { Authorization: `Bearer ${conn.access_token}` },
            params: { sort: 'updated', per_page: 30, page: req.query.page || 1 }
        });
        res.json({ 
            success: true, 
            repos: response.data.map(r => ({
                id: r.id, 
                name: r.name, 
                full_name: r.full_name,
                description: r.description, 
                clone_url: r.clone_url,
                default_branch: r.default_branch, 
                private: r.private,
                language: r.language, 
                updated_at: r.updated_at
            }))
        });
    } catch(e) { 
        res.status(500).json({ success: false, error: 'Erreur récupération repos' }); 
    }
});

app.get('/api/github/repos/:owner/:repo/branches', authenticateToken, async (req, res) => {
    const conn = await new Promise(r => 
        db.get('SELECT access_token FROM github_connections WHERE user_id = ?', [req.user.userId], (e, row) => r(row))
    );
    if (!conn) {
        return res.status(401).json({ 
            success: false, 
            error: 'GitHub non connecté' 
        });
    }
    try {
        const resp = await axios.get(
            `https://api.github.com/repos/${req.params.owner}/${req.params.repo}/branches`, 
            { headers: { Authorization: `Bearer ${conn.access_token}` } }
        );
        res.json({ 
            success: true, 
            branches: resp.data.map(b => ({ name: b.name, sha: b.commit.sha })) 
        });
    } catch(e) { 
        res.status(500).json({ success: false, error: 'Erreur branches' }); 
    }
});

// =============================================
// ROUTES DÉPLOIEMENT
// =============================================

// Détecter la technologie depuis un repo GitHub ou une liste de fichiers
app.post('/api/deploy/detect-tech', authenticateToken, async (req, res) => {
    const { repo_url, branch = 'main', file_list } = req.body;
    const userId = req.user.userId;

    try {
        let fileList = [];

        if (file_list && Array.isArray(file_list)) {
            fileList = file_list;
        } else if (repo_url) {
            const match = repo_url.match(/github\.com\/([^/]+)\/([^/]+)/);
            if (!match) return res.status(400).json({ success: false, error: 'URL GitHub invalide' });
            const [, owner, repoName] = match;
            const conn = await new Promise(r =>
                db.get('SELECT access_token FROM github_connections WHERE user_id = ?', [userId], (e, row) => r(row))
            );
            const headers = { 'User-Agent': 'FLYHOST', Accept: 'application/vnd.github+json' };
            if (conn?.access_token) headers.Authorization = `Bearer ${conn.access_token}`;
            const treeRes = await axios.get(
                `https://api.github.com/repos/${owner}/${repoName.replace(/\.git$/, '')}/git/trees/${branch}?recursive=1`,
                { headers, timeout: 10000 }
            );
            fileList = (treeRes.data.tree || []).filter(e => e.type === 'blob').map(e => e.path);
        } else {
            return res.status(400).json({ success: false, error: 'repo_url ou file_list requis' });
        }

        const detection = detectTechnologyFromFiles(fileList);
        return res.json({
            success: true,
            ...detection,
            environments: Object.entries(TECH_ENVIRONMENTS).map(([key, cfg]) => ({
                key, name: cfg.name, icon: cfg.icon, color: cfg.color
            }))
        });
    } catch (e) {
        console.error('Detect tech error:', e.message);
        return res.json({
            success: true,
            tech: 'nodejs', framework: null, frameworkLabel: null, confidence: 'low',
            suggestedStart: 'npm start', suggestedBuild: 'npm install',
            environments: Object.entries(TECH_ENVIRONMENTS).map(([key, cfg]) => ({
                key, name: cfg.name, icon: cfg.icon, color: cfg.color
            }))
        });
    }
});

// Lister les environnements disponibles (public)
app.get('/api/deploy/environments', (req, res) => {
    const envs = Object.entries(TECH_ENVIRONMENTS).map(([key, cfg]) => ({
        key, name: cfg.name, icon: cfg.icon, color: cfg.color,
        default_start: cfg.default_start, default_build: cfg.default_build
    }));
    res.json({ success: true, environments: envs });
});

app.post('/api/deploy/github', authenticateToken, requireEmailVerification, async (req, res) => {
    const { server_id, repo_url, branch = 'main', env_vars = {}, auto_deploy = false, env_type, start_cmd, build_cmd } = req.body;
    const userId = req.user.userId;
    
    if (!server_id || !repo_url) {
        return res.status(400).json({ 
            success: false, 
            error: 'server_id et repo_url requis' 
        });
    }

    const server = await new Promise(r => 
        db.get('SELECT * FROM servers WHERE id = ? AND user_id = ?', [server_id, userId], (e, row) => r(row))
    );
    if (!server) {
        return res.status(404).json({ 
            success: false, 
            error: 'Serveur non trouvé' 
        });
    }

    const conn = await new Promise(r => 
        db.get('SELECT access_token FROM github_connections WHERE user_id = ?', [userId], (e, row) => r(row))
    );

    // Résoudre la technologie : depuis env_type (choix utilisateur) ou auto-détection
    let resolvedTech = TECH_ENVIRONMENTS[env_type] ? env_type : null;
    let detectedInfo = null;
    let flyhostConfig = { start: 'node index.js', build: '' };
    
    try {
        const match = repo_url.match(/github\.com\/([^/]+)\/([^/]+)/);
        if (match) {
            const [, owner, repoName] = match;
            const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'FLYHOST' };
            if (conn?.access_token) headers.Authorization = `Bearer ${conn.access_token}`;

            // Essayer flyhost.json d'abord
            try {
                const cfgRes = await axios.get(
                    `https://api.github.com/repos/${owner}/${repoName.replace(/\.git$/, '')}/contents/flyhost.json?ref=${branch}`, 
                    { headers: { ...headers, Accept: 'application/vnd.github.v3.raw' } }
                );
                const raw = typeof cfgRes.data === 'string' ? cfgRes.data : Buffer.from(cfgRes.data.content, 'base64').toString('utf8');
                const parsed = JSON.parse(raw);
                flyhostConfig = parsed;
                if (parsed.runtime && !resolvedTech) resolvedTech = parsed.runtime;
            } catch(_) {}

            // Auto-détection si pas de tech choisie
            if (!resolvedTech) {
                try {
                    const treeRes = await axios.get(
                        `https://api.github.com/repos/${owner}/${repoName.replace(/\.git$/, '')}/git/trees/${branch}?recursive=1`,
                        { headers, timeout: 10000 }
                    );
                    const fileList = (treeRes.data.tree || []).filter(e => e.type === 'blob').map(e => e.path);
                    detectedInfo = detectTechnologyFromFiles(fileList);
                    detectedInfo.fileList = fileList;
                    resolvedTech = detectedInfo.tech;
                    if (!flyhostConfig.start || flyhostConfig.start === 'node index.js') {
                        flyhostConfig.start = start_cmd || detectedInfo.suggestedStart;
                        flyhostConfig.build = build_cmd || detectedInfo.suggestedBuild;
                    }
                } catch(_) {}
            }

            // Lire package.json depuis GitHub pour récupérer scripts.start et main
            if (!start_cmd && (resolvedTech === 'nodejs' || !resolvedTech)) {
                try {
                    const pkgRes = await axios.get(
                        `https://api.github.com/repos/${owner}/${repoName.replace(/\.git$/, '')}/contents/package.json?ref=${branch}`,
                        { headers: { ...headers, Accept: 'application/vnd.github.v3.raw' }, timeout: 8000 }
                    );
                    const raw = typeof pkgRes.data === 'string' ? pkgRes.data : Buffer.from(pkgRes.data.content || '', 'base64').toString('utf8');
                    const pkg = JSON.parse(raw);
                    const needsStart = !flyhostConfig.start || flyhostConfig.start === 'node index.js';

                    if (pkg.scripts?.start && needsStart) {
                        flyhostConfig.start = pkg.scripts.start;
                    } else if (pkg.scripts?.dev && needsStart) {
                        flyhostConfig.start = pkg.scripts.dev;
                    } else if (needsStart) {
                        // Pas de script start → chercher l'entrée dans les sous-dossiers courants
                        const fileNames = (detectedInfo?.fileList || []).map(f => f.toLowerCase());
                        const serverEntries = [
                            'server/index.js','server/app.js','server/server.js','server/main.js',
                            'backend/index.js','backend/app.js','backend/server.js','backend/main.js',
                            'src/index.js','src/app.js','src/server.js','src/main.js',
                            'index.js','app.js','server.js','main.js'
                        ];
                        const found = serverEntries.find(e => fileNames.includes(e));
                        if (found) {
                            flyhostConfig.start = `node ${found}`;
                        } else if (pkg.main && pkg.main !== 'index.js') {
                            flyhostConfig.start = `node ${pkg.main}`;
                        }

                        // Si c'est un projet React sans backend → déploiement statique
                        const isReactApp = !!(pkg.dependencies?.react && (pkg.dependencies?.['react-scripts'] || pkg.devDependencies?.['react-scripts']));
                        const hasBuildScript = !!(pkg.scripts?.build);
                        const hasServer = serverEntries.slice(0,8).some(e => fileNames.includes(e));
                        if (isReactApp && !hasServer && !flyhostConfig.build) {
                            flyhostConfig.build = hasBuildScript ? 'npm run build' : 'npx react-scripts build';
                            flyhostConfig.static_dir = 'build';
                            resolvedTech = 'static';
                        }
                    }
                } catch(_) {}
            }
        }
    } catch(e) {}

    // Appliquer les commandes fournies par l'utilisateur en priorité
    if (start_cmd) flyhostConfig.start = start_cmd;
    if (build_cmd) flyhostConfig.build = build_cmd;
    if (!resolvedTech) resolvedTech = 'nodejs';
    flyhostConfig.env_type = resolvedTech;

    const deploymentId = await new Promise((resolve, reject) => {
        db.run(
            `INSERT INTO deployments 
             (server_id, user_id, deploy_type, deploy_source, status, env_vars, flyhost_config, git_branch, auto_deploy) 
             VALUES (?, ?, "github", ?, "building", ?, ?, ?, ?)`,
            [server_id, userId, repo_url, JSON.stringify(env_vars), JSON.stringify(flyhostConfig), branch, auto_deploy ? 1 : 0],
            function(err) { 
                if (err) reject(err); 
                else resolve(this.lastID); 
            }
        );
    });

    res.json({ 
        success: true, 
        message: 'Déploiement lancé !', 
        deployment_id: deploymentId, 
        ws_url: `wss://flihost.site/ws/logs?serverId=${server_id}`, 
        status: 'building' 
    });

    deployWithTimeout(() => 
        deployFromGitHub({ 
            deploymentId, 
            serverId: server_id, 
            serverIdentifier: server.server_identifier,
            pterodactylId: server.pterodactyl_id,
            repoUrl: repo_url, 
            branch, 
            envVars: env_vars, 
            flyhostConfig, 
            accessToken: conn?.access_token || null 
        })
    ).catch(error => {
        console.error('Timeout ou erreur déploiement:', error);
        db.run('UPDATE deployments SET status = "failed", build_log = build_log || ? WHERE id = ?', 
            [`❌ ${error.message}\n`, deploymentId]);
    });
});

app.post('/api/webhook/github/:serverId', async (req, res) => {
    const signature = req.headers['x-hub-signature-256'];
    
    const secret = GITHUB_CONFIG.webhook_secret;
    const hash = 'sha256=' + crypto
        .createHmac('sha256', secret)
        .update(JSON.stringify(req.body))
        .digest('hex');
    
    if (signature !== hash) {
        return res.status(401).json({ error: 'Non autorisé' });
    }
    
    const deployment = await new Promise(r => 
        db.get(
            'SELECT * FROM deployments WHERE server_id = ? ORDER BY created_at DESC LIMIT 1', 
            [req.params.serverId], 
            (e, row) => r(row)
        )
    );
    
    if (deployment?.auto_deploy) {
        const server = await new Promise(r => 
            db.get('SELECT * FROM servers WHERE id = ?', [deployment.server_id], (e, row) => r(row))
        );
        const conn = await new Promise(r => 
            db.get('SELECT access_token FROM github_connections WHERE user_id = ?', [deployment.user_id], (e, row) => r(row))
        );
        
        const newDeploymentId = await new Promise((resolve, reject) => {
            db.run(
                `INSERT INTO deployments 
                 (server_id, user_id, deploy_type, deploy_source, status, env_vars, flyhost_config, git_branch, auto_deploy) 
                 VALUES (?, ?, "github", ?, "building", ?, ?, ?, ?)`,
                [server.id, deployment.user_id, deployment.deploy_source, deployment.env_vars, deployment.flyhost_config, deployment.git_branch, deployment.auto_deploy],
                function(err) { 
                    if (err) reject(err); 
                    else resolve(this.lastID); 
                }
            );
        });
        
        deployFromGitHub({ 
            deploymentId: newDeploymentId, 
            serverId: server.id, 
            serverIdentifier: server.server_identifier, 
            repoUrl: deployment.deploy_source, 
            branch: deployment.git_branch || 'main', 
            envVars: JSON.parse(deployment.env_vars || '{}'), 
            flyhostConfig: JSON.parse(deployment.flyhost_config || '{}'), 
            accessToken: conn?.access_token || null 
        });
    }
    
    res.json({ success: true });
});

app.get('/api/servers/:serverId/files', authenticateToken, async (req, res) => {
    const { path } = req.query;
    const server = await getServerByIdAndUser(req.params.serverId, req.user.userId);
    if (!server) return res.status(404).json({ success: false, error: 'Serveur non trouvé' });
    
    try {
        const content = await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/files/contents?file=${encodeURIComponent(path)}`
        );
        res.json({ success: true, content });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Erreur lecture fichier' });
    }
});

app.put('/api/servers/:serverId/files', authenticateToken, async (req, res) => {
    const { path, content } = req.body;
    const server = await getServerByIdAndUser(req.params.serverId, req.user.userId);
    if (!server) return res.status(404).json({ success: false, error: 'Serveur non trouvé' });
    
    try {
        await callPterodactylClientAPI(
            `/api/client/servers/${server.server_identifier}/files/write?file=${encodeURIComponent(path)}`,
            'POST',
            content
        );
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Erreur écriture fichier' });
    }
});

app.post('/api/deploy/zip', authenticateToken, requireEmailVerification, upload.single('file'), async (req, res) => {
    const { server_id, env_vars = '{}', env_type, start_cmd, build_cmd } = req.body;
    const userId = req.user.userId;
    
    if (!server_id || !req.file) {
        return res.status(400).json({ 
            success: false, 
            error: 'server_id et fichier ZIP requis' 
        });
    }

    const server = await new Promise(r => 
        db.get('SELECT * FROM servers WHERE id = ? AND user_id = ?', [server_id, userId], (e, row) => r(row))
    );
    if (!server) {
        return res.status(404).json({ 
            success: false, 
            error: 'Serveur non trouvé' 
        });
    }

    let flyhostConfig = { start: '', build: '' };
    let resolvedTech = TECH_ENVIRONMENTS[env_type] ? env_type : null;
    
    try { 
        const zip = new AdmZip(req.file.path);
        const allEntries = zip.getEntries();
        const allEntryNames = allEntries.map(e => e.entryName);

        // Helper: trouver un fichier même dans un sous-dossier unique (ex: "hackeur MD/package.json")
        const findEntry = (filename) => {
            return allEntries.find(e => {
                const parts = e.entryName.split('/').filter(Boolean);
                return parts[parts.length - 1] === filename && parts.length <= 2;
            });
        };

        // Auto-detect tech depuis les fichiers du ZIP
        if (!resolvedTech) {
            const detection = detectTechnologyFromFiles(allEntryNames);
            resolvedTech = detection.tech;
            flyhostConfig.start = detection.suggestedStart;
            flyhostConfig.build = detection.suggestedBuild;
        }

        // 1. Lire flyhost.json si présent (racine ou sous-dossier direct)
        const flyhostEntry = findEntry('flyhost.json');
        if (flyhostEntry) {
            flyhostConfig = JSON.parse(flyhostEntry.getData().toString('utf8'));
        } else if (!resolvedTech || resolvedTech === 'nodejs') {
            // 2. Lire package.json -> scripts.start ou main (seulement si tech = Node.js)
            // Ne pas écraser un start Python/PHP/Java détecté avec un start npm !
            const pkgEntry = findEntry('package.json');
            if (pkgEntry) {
                const pkg = JSON.parse(pkgEntry.getData().toString('utf8'));
                if (pkg.scripts?.start) {
                    flyhostConfig.start = pkg.scripts.start;
                } else if (pkg.main) {
                    flyhostConfig.start = `node ${pkg.main}`;
                } else {
                    // 3. Chercher fichier d'entrée commun
                    const candidates = ['index.js','bot.js','app.js','server.js','main.js','start.js'];
                    const found = candidates.find(c => allEntryNames.some(n => n.endsWith('/' + c) || n === c));
                    if (found) flyhostConfig.start = `node ${found}`;
                }
            } else {
                // Pas de package.json — scanner les fichiers JS
                const candidates = ['index.js','bot.js','app.js','server.js','main.js','start.js'];
                const found = candidates.find(c => allEntryNames.some(n => n.endsWith('/' + c) || n === c));
                if (found) flyhostConfig.start = `node ${found}`;
            }
        }
    } catch(e) {}

    // Priorité aux commandes explicites de l'utilisateur
    if (start_cmd) flyhostConfig.start = start_cmd;
    if (build_cmd) flyhostConfig.build = build_cmd;
    if (!resolvedTech) resolvedTech = 'nodejs';
    flyhostConfig.env_type = resolvedTech;

    const parsedEnv = typeof env_vars === 'string' ? JSON.parse(env_vars) : env_vars;
    
    const deploymentId = await new Promise((resolve, reject) => {
        db.run(
            `INSERT INTO deployments 
             (server_id, user_id, deploy_type, deploy_source, status, env_vars, flyhost_config) 
             VALUES (?, ?, "zip", ?, "building", ?, ?)`,
            [server_id, userId, req.file.originalname, JSON.stringify(parsedEnv), JSON.stringify(flyhostConfig)],
            function(err) { 
                if (err) reject(err); 
                else resolve(this.lastID); 
            }
        );
    });

    res.json({ 
        success: true, 
        message: 'Déploiement ZIP lancé !', 
        deployment_id: deploymentId, 
        status: 'building' 
    });

    deployWithTimeout(() => 
        deployFromZip({ 
            deploymentId, 
            serverId: server_id, 
            serverIdentifier: server.server_identifier,
            pterodactylId: server.pterodactyl_id,
            zipPath: req.file.path, 
            envVars: parsedEnv, 
            flyhostConfig 
        })
    ).catch(error => {
        console.error('Timeout ou erreur déploiement ZIP:', error);
        db.run('UPDATE deployments SET status = "failed", build_log = build_log || ? WHERE id = ?', 
            [`❌ ${error.message}\n`, deploymentId]);
    });
});

const BUILTIN_TEMPLATE_URLS = {
    'nodejs-express':      'https://github.com/render-examples/express-hello-world',
    'nodejs-discord-bot':  'https://github.com/nickarocho/discord-bot-starter',
    'python-flask':        'https://github.com/render-examples/flask-hello-world',
    'static-html':         'https://github.com/nickarocho/hello-world-html',
    'nodejs-generic':      'https://github.com/render-examples/express-hello-world',
};

app.post('/api/deploy/template', authenticateToken, requireEmailVerification, async (req, res) => {
    const { server_id, template_url: rawTemplateUrl, template: templateName, env_vars = {} } = req.body;
    const userId = req.user.userId;

    // Résoudre l'URL du template (URL directe ou nom intégré)
    const template_url = rawTemplateUrl || BUILTIN_TEMPLATE_URLS[templateName] || null;

    if (!server_id || !template_url) {
        return res.status(400).json({ 
            success: false, 
            error: 'server_id et template_url (ou nom de template) requis' 
        });
    }

    const server = await new Promise(r => 
        db.get('SELECT * FROM servers WHERE id = ? AND user_id = ?', [server_id, userId], (e, row) => r(row))
    );
    if (!server) {
        return res.status(404).json({ 
            success: false, 
            error: 'Serveur non trouvé' 
        });
    }

    let flyhostConfig = { 
        runtime: 'node', 
        version: '24', 
        start: 'node index.js', 
        build: '' 
    };
    
    try {
        const match = template_url.match(/github\.com\/([^/]+)\/([^/]+)/);
        if (match) {
            const [, owner, repoName] = match;
            const cleanRepo = repoName.replace(/\.git$/, '');
            const headers = { 
                Accept: 'application/vnd.github.v3.raw', 
                'User-Agent': 'FLYHOST' 
            };
            const cfgRes = await axios.get(
                `https://api.github.com/repos/${owner}/${cleanRepo}/contents/flyhost.json`, 
                { headers }
            );
            const raw = typeof cfgRes.data === 'string' ? cfgRes.data : Buffer.from(cfgRes.data.content, 'base64').toString('utf8');
            flyhostConfig = JSON.parse(raw);
        }
    } catch(e) { 
    }

    const deploymentId = await new Promise((resolve, reject) => {
        db.run(
            `INSERT INTO deployments 
             (server_id, user_id, deploy_type, deploy_source, status, env_vars, flyhost_config, git_branch) 
             VALUES (?, ?, "template", ?, "building", ?, ?, "main")`,
            [server_id, userId, template_url, JSON.stringify(env_vars), JSON.stringify(flyhostConfig)],
            function(err) { 
                if (err) reject(err); 
                else resolve(this.lastID); 
            }
        );
    });

    res.json({ 
        success: true, 
        message: 'Déploiement Template lancé !', 
        deployment_id: deploymentId, 
        ws_url: `wss://flihost.site/ws/logs?serverId=${server_id}`, 
        status: 'building' 
    });

    deployWithTimeout(() => 
        deployFromTemplate({ 
            deploymentId, 
            serverId: server_id, 
            serverIdentifier: server.server_identifier,
            pterodactylId: server.pterodactyl_id,
            templateUrl: template_url, 
            envVars: env_vars, 
            flyhostConfig 
        })
    ).catch(error => {
        console.error('Timeout ou erreur déploiement template:', error);
        db.run('UPDATE deployments SET status = "failed", build_log = build_log || ? WHERE id = ?', 
            [`❌ ${error.message}\n`, deploymentId]);
    });
});

app.get('/api/deploy/:deploymentId/status', authenticateToken, (req, res) => {
    db.get(
        `SELECT d.*, s.env_type FROM deployments d 
         LEFT JOIN servers s ON s.id = d.server_id
         WHERE d.id = ? AND d.user_id = ?`, 
        [req.params.deploymentId, req.user.userId], 
        (err, dep) => {
            if (err || !dep) {
                return res.status(404).json({ 
                    success: false, 
                    error: 'Déploiement non trouvé' 
                });
            }
            let diagnosis = null;
            if (dep.status === 'failed' && dep.build_log) {
                diagnosis = analyzeDeployError(dep.build_log, dep.env_type || 'nodejs');
            }
            res.json({ 
                success: true, 
                deployment: { 
                    id: dep.id, 
                    type: dep.deploy_type, 
                    source: dep.deploy_source, 
                    status: dep.status, 
                    branch: dep.git_branch, 
                    commit: dep.git_commit, 
                    last_deployed: dep.last_deployed, 
                    created_at: dep.created_at,
                    build_log: dep.build_log || '',
                    diagnosis
                } 
            });
        }
    );
});

app.get('/api/servers/:serverId/deployments', authenticateToken, (req, res) => {
    db.all(
        `SELECT id, deploy_type, deploy_source, status, git_branch, git_commit, env_vars, last_deployed, created_at 
         FROM deployments 
         WHERE server_id = ? AND user_id = ? 
         ORDER BY created_at DESC 
         LIMIT 20`,
        [req.params.serverId, req.user.userId],
        (err, rows) => {
            if (err) {
                return res.status(500).json({ 
                    success: false, 
                    error: 'Erreur' 
                });
            }
            res.json({ 
                success: true, 
                deployments: rows || [] 
            });
        }
    );
});

// Logs runtime du serveur Pterodactyl (après déploiement)
app.get('/api/servers/:serverId/runtime-logs', authenticateToken, async (req, res) => {
    try {
        const server = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM servers WHERE id = ? AND user_id = ?', [req.params.serverId, req.user.userId], (e, row) => {
                if (e || !row) reject(new Error('Serveur introuvable'));
                else resolve(row);
            });
        });
        const identifier = server.pterodactyl_id;
        const logRes = await axios.get(`${PTERODACTYL_URL}/api/client/servers/${identifier}/logs`, {
            headers: { Authorization: `Bearer ${PTERODACTYL_CLIENT_KEY}`, Accept: 'application/json' }
        }).catch(() => null);
        let logs = '';
        if (logRes?.data) {
            logs = logRes.data;
        } else {
            // Fallback: récupérer depuis la DB le build_log du dernier déploiement
            const lastDep = await new Promise(r => db.get(
                'SELECT build_log FROM deployments WHERE server_id = ? ORDER BY created_at DESC LIMIT 1',
                [server.id], (e, row) => r(row)
            ));
            logs = lastDep?.build_log || 'Aucun log disponible';
        }
        // Analyser pour un diagnostic
        const diagnosis = analyzeDeployError(logs, server.env_type || 'nodejs');
        res.json({ success: true, logs, diagnosis });
    } catch(err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.put('/api/deploy/:deploymentId/env', authenticateToken, (req, res) => {
    const { env_vars } = req.body;
    db.run(
        'UPDATE deployments SET env_vars = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
        [JSON.stringify(env_vars), req.params.deploymentId, req.user.userId],
        function(err) {
            if (err) {
                return res.status(500).json({ 
                    success: false, 
                    error: 'Erreur' 
                });
            }
            if (this.changes === 0) {
                return res.status(404).json({ 
                    success: false, 
                    error: 'Non trouvé' 
                });
            }
            res.json({ 
                success: true, 
                message: 'Variables mises à jour' 
            });
        }
    );
});

app.post('/api/deploy/:deploymentId/redeploy', authenticateToken, requireEmailVerification, async (req, res) => {
    const dep = await new Promise(r => 
        db.get(
            'SELECT d.*, s.server_identifier FROM deployments d JOIN servers s ON d.server_id = s.id WHERE d.id = ? AND d.user_id = ?', 
            [req.params.deploymentId, req.user.userId], 
            (e, row) => r(row)
        )
    );
    
    if (!dep) {
        return res.status(404).json({ 
            success: false, 
            error: 'Non trouvé' 
        });
    }
    
    const conn = await new Promise(r => 
        db.get('SELECT access_token FROM github_connections WHERE user_id = ?', [req.user.userId], (e, row) => r(row))
    );
    
    db.run('UPDATE deployments SET status = "building", updated_at = CURRENT_TIMESTAMP WHERE id = ?', [dep.id]);
    
    res.json({ 
        success: true, 
        message: 'Re-déploiement lancé !' 
    });

    if (dep.deploy_type === 'github') {
        deployFromGitHub({ 
            deploymentId: dep.id, 
            serverId: dep.server_id, 
            serverIdentifier: dep.server_identifier, 
            repoUrl: dep.deploy_source, 
            branch: dep.git_branch || 'main', 
            envVars: JSON.parse(dep.env_vars || '{}'), 
            flyhostConfig: JSON.parse(dep.flyhost_config || '{}'), 
            accessToken: conn?.access_token || null 
        });
    } else if (dep.deploy_type === 'zip') {
        res.status(400).json({ 
            success: false, 
            error: 'Le re-déploiement ZIP nécessite de téléverser à nouveau le fichier' 
        });
    } else if (dep.deploy_type === 'template') {
        deployFromTemplate({ 
            deploymentId: dep.id, 
            serverId: dep.server_id, 
            serverIdentifier: dep.server_identifier, 
            templateUrl: dep.deploy_source, 
            envVars: JSON.parse(dep.env_vars || '{}'), 
            flyhostConfig: JSON.parse(dep.flyhost_config || '{}')
        });
    }
});

app.get('/api/deploy/:deploymentId/snapshots', authenticateToken, (req, res) => {
    db.all(
        'SELECT * FROM deployment_snapshots WHERE deployment_id = ? ORDER BY created_at DESC',
        [req.params.deploymentId],
        (err, snapshots) => {
            res.json({ success: true, snapshots });
        }
    );
});

app.post('/api/deploy/:deploymentId/rollback/:snapshotId', authenticateToken, async (req, res) => {
    const snapshot = await new Promise(r => 
        db.get(
            'SELECT ds.*, d.server_id, s.server_identifier FROM deployment_snapshots ds JOIN deployments d ON ds.deployment_id = d.id JOIN servers s ON d.server_id = s.id WHERE ds.id = ?',
            [req.params.snapshotId],
            (e, row) => r(row)
        )
    );
    
    if (!snapshot) {
        return res.status(404).json({ success: false, error: 'Snapshot non trouvé' });
    }
    
    try {
        await uploadZipToPterodactyl(snapshot.server_identifier, snapshot.snapshot_path);
        res.json({ success: true, message: 'Rollback effectué' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// =============================================
// ROUTES DE PAIEMENT MONEYFUSION
// =============================================

app.post('/api/payment/initiate', authenticateToken, async (req, res) => {
    const { amount, plan, panel_name, phone_number, env_type = 'nodejs' } = req.body;
    const userId = req.user.userId;

    if (!amount || amount < 1) {
        return res.status(400).json({ 
            success: false,
            error: 'Montant invalide',
            code: 'INVALID_AMOUNT'
        });
    }

    try {
        db.get('SELECT username, email FROM users WHERE id = ?', [userId], async (err, user) => {
            if (err || !user) {
                return res.status(404).json({ 
                    success: false,
                    error: 'Utilisateur non trouvé',
                    code: 'USER_NOT_FOUND'
                });
            }

            const paymentId = 'PAY_' + crypto.randomBytes(8).toString('hex').toUpperCase();
            const transactionId = 'TXN_' + crypto.randomBytes(6).toString('hex').toUpperCase();

            db.run(
                'INSERT INTO transactions (user_id, plan_key, panel_name, phone_number, amount, status, payment_id, transaction_id, env_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [userId, plan || 'coin_purchase', panel_name, phone_number, amount, 'pending', paymentId, transactionId, TECH_ENVIRONMENTS[env_type] ? env_type : 'nodejs'],
                async function(err) {
                    if (err) {
                        console.error('Erreur création transaction:', err);
                        return res.status(500).json({ 
                            success: false,
                            error: 'Erreur création transaction',
                            code: 'TRANSACTION_CREATION_ERROR'
                        });
                    }

                    try {
                        const baseUrl = process.env.BASE_URL || 'https://flihost.site';
                        const returnUrl = `${baseUrl}/payment/callback?payment_id=${paymentId}&status=success`;
                        const cancelUrl = `${baseUrl}/payment/callback?payment_id=${paymentId}&status=cancel`;
                        const webhookUrl = `${baseUrl}/api/payment/webhook`;

                        const paymentData = {
                            totalPrice: parseInt(amount),
                            article: [
                                {
                                    name: plan ? `Panel ${plan} - ${panel_name}` : 'Achat de coins FLYHOST',
                                    price: parseInt(amount)
                                }
                            ],
                            personal_Info: [
                                {
                                    userId: parseInt(userId),
                                    paymentId: paymentId,
                                    transactionId: transactionId,
                                    plan: plan,
                                    panel_name: panel_name,
                                    type: plan ? "plan_purchase" : "coin_purchase"
                                }
                            ],
                            numeroSend: phone_number || "",
                            nomclient: user.username,
                            return_url: returnUrl,
                            webhook_url: webhookUrl
                        };

                        console.log("📤 Données envoyées à MoneyFusion:", JSON.stringify(paymentData, null, 2));

                        const agent = new https.Agent({
                            rejectUnauthorized: false,
                            keepAlive: true
                        });

                        const controller = new AbortController();
                        const timeout = setTimeout(() => {
                            controller.abort();
                        }, 30000);

                        try {
                            const moneyFusionUrl = MONEYFUSION_CONFIG.api_url;
                            
                            const response = await fetch(moneyFusionUrl, {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                    'Accept': 'application/json',
                                    'User-Agent': 'FLYHOST/2.0'
                                },
                                body: JSON.stringify(paymentData),
                                agent: agent,
                                signal: controller.signal
                            });

                            clearTimeout(timeout);

                            const responseText = await response.text();
                            console.log('📥 Réponse MoneyFusion:', responseText);

                            let result;
                            try {
                                result = JSON.parse(responseText);
                            } catch (e) {
                                console.error('❌ Impossible de parser la réponse JSON:', e);
                                throw new Error(`Réponse invalide: ${responseText.substring(0, 200)}`);
                            }

                            if (result.statut === true && result.url) {
                                db.run(
                                    'UPDATE transactions SET payment_url = ?, moneyfusion_token = ? WHERE payment_id = ?',
                                    [result.url, result.token, paymentId]
                                );

                                res.json({
                                    success: true,
                                    paymentUrl: result.url,
                                    paymentId: paymentId,
                                    token: result.token,
                                    message: result.message || 'Paiement initié avec succès'
                                });
                            } else {
                                console.error('❌ Erreur MoneyFusion:', result);
                                throw new Error(`MoneyFusion: ${result.message || 'Erreur inconnue'}`);
                            }

                        } catch (fetchError) {
                            if (fetchError.name === 'AbortError') {
                                throw new Error('Timeout: La requête vers MoneyFusion a pris trop de temps');
                            }
                            throw fetchError;
                        }

                    } catch (error) {
                        console.error('❌ Erreur appel API MoneyFusion:', error);
                        
                        db.run(
                            'UPDATE transactions SET status = ? WHERE payment_id = ?',
                            ['failed', paymentId]
                        );
                        
                        res.status(500).json({ 
                            success: false,
                            error: 'Erreur lors du traitement du paiement: ' + error.message,
                            code: 'PAYMENT_PROCESSING_ERROR'
                        });
                    }
                }
            );
        });
    } catch (error) {
        console.error('❌ Erreur initiation paiement:', error);
        res.status(500).json({ 
            success: false,
            error: 'Erreur initiation paiement: ' + error.message,
            code: 'PAYMENT_INIT_ERROR'
        });
    }
});

app.post('/api/payment/webhook', express.json(), async (req, res) => {
    console.log('📥 Webhook MoneyFusion reçu:', JSON.stringify(req.body, null, 2));
    
    try {
        const { 
            event,
            tokenPay,
            numeroSend,
            nomclient,
            numeroTransaction,
            Montant,
            frais,
            personal_Info,
            return_url,
            webhook_url,
            createdAt
        } = req.body;
        
        if (!tokenPay || !event) {
            console.error('❌ Données manquantes dans le webhook');
            return res.status(400).json({ 
                success: false,
                error: 'Données manquantes',
                code: 'MISSING_WEBHOOK_DATA'
            });
        }

        console.log('🔍 Événement webhook:', event, 'Token:', tokenPay);

        db.get(
            'SELECT * FROM transactions WHERE moneyfusion_token = ? OR payment_id = ?',
            [tokenPay, tokenPay],
            async (err, transaction) => {
                if (err || !transaction) {
                    console.error('❌ Transaction non trouvée pour token:', tokenPay);
                    return res.status(404).json({ 
                        success: false,
                        error: 'Transaction non trouvée',
                        code: 'TRANSACTION_NOT_FOUND'
                    });
                }

                if (transaction.status === 'completed' && event === 'payin.session.completed') {
                    console.log('⚠️ Événement déjà traité:', tokenPay);
                    return res.json({ 
                        success: true, 
                        message: 'Événement déjà traité' 
                    });
                }

                switch (event) {
                    case 'payin.session.completed':
                        db.run(
                            'UPDATE transactions SET status = ?, transaction_id = ?, completed_at = CURRENT_TIMESTAMP WHERE moneyfusion_token = ?',
                            ['completed', numeroTransaction, tokenPay],
                            async function(err) {
                                if (err) {
                                    console.error('❌ Erreur mise à jour transaction:', err);
                                    return res.status(500).json({ 
                                        success: false,
                                        error: 'Erreur mise à jour transaction',
                                        code: 'TRANSACTION_UPDATE_ERROR'
                                    });
                                }

                                console.log(`✅ Transaction ${tokenPay} marquée comme payée`);

                                db.get('SELECT * FROM users WHERE id = ?', [transaction.user_id], async (err, user) => {
                                    if (!err && user) {
                                        await sendPaymentConfirmation({
                                            ...transaction,
                                            amount: Montant,
                                            completed_at: new Date().toISOString()
                                        }, user);
                                    }

                                    if (transaction.plan_key && transaction.plan_key !== 'coin_purchase') {
                                        await createPanelFromPayment(transaction.user_id, transaction.plan_key, transaction.panel_name, transaction.env_type || 'nodejs');
                                    } else {
                                        db.run(
                                            'UPDATE users SET coins = coins + ? WHERE id = ?',
                                            [Montant, transaction.user_id]
                                        );
                                        
                                        db.get('SELECT * FROM user_credits WHERE user_id = ?', [transaction.user_id], (err, credits) => {
                                            const newBalance = (credits?.balance || 0) + parseFloat(Montant);
                                            db.run(`INSERT INTO user_credits (user_id, balance, total_purchased, last_purchase)
                                                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                                                    ON CONFLICT(user_id) DO UPDATE SET
                                                    balance = balance + ?,
                                                    total_purchased = total_purchased + ?,
                                                    last_purchase = CURRENT_TIMESTAMP`,
                                                [transaction.user_id, Montant, Montant, Montant, Montant]
                                            );
                                            db.run(`INSERT INTO credit_transactions 
                                                    (user_id, type, amount, balance_after, description, payment_id)
                                                    VALUES (?, 'purchase', ?, ?, 'Achat de crédits', ?)`,
                                                [transaction.user_id, parseFloat(Montant), newBalance, tokenPay]
                                            );
                                        });
                                    }

                                    // NOUVEAU : Traiter la commission pour le revendeur
                                    await processResellerCommission(transaction.user_id, parseFloat(Montant), transaction.id);
                                });
                                
                                res.json({ 
                                    success: true, 
                                    message: 'Paiement traité avec succès' 
                                });
                            }
                        );
                        break;

                    case 'payin.session.cancelled':
                        db.run(
                            'UPDATE transactions SET status = ? WHERE moneyfusion_token = ?',
                            ['failed', tokenPay],
                            function(err) {
                                if (err) {
                                    console.error('❌ Erreur mise à jour transaction annulée:', err);
                                    return res.status(500).json({ 
                                        success: false,
                                        error: 'Erreur mise à jour transaction',
                                        code: 'TRANSACTION_UPDATE_ERROR'
                                    });
                                }
                                res.json({ 
                                    success: true, 
                                    message: 'Paiement annulé enregistré' 
                                });
                            }
                        );
                        break;

                    case 'payin.session.pending':
                        console.log(`⏳ Paiement en attente: ${tokenPay}`);
                        res.json({ 
                            success: true, 
                            message: 'Statut pending enregistré' 
                        });
                        break;

                    default:
                        console.log('⚠️ Événement non traité:', event);
                        res.json({ 
                            success: true, 
                            message: 'Événement non traité: ' + event 
                        });
                }
            }
        );
    } catch (error) {
        console.error('❌ Erreur webhook paiement:', error);
        res.status(500).json({ 
            success: false,
            error: 'Erreur traitement webhook',
            code: 'WEBHOOK_PROCESSING_ERROR'
        });
    }
});

app.get('/api/payment/status/:token', authenticateToken, async (req, res) => {
    const { token } = req.params;

    try {
        const response = await fetch(`${MONEYFUSION_CONFIG.status_url}${token}`);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const result = await response.json();

        if (result.statut && result.data) {
            res.json({
                success: true,
                status: result.data.statut,
                amount: result.data.Montant,
                fees: result.data.frais,
                method: result.data.moyen,
                transactionId: result.data.numeroTransaction,
                createdAt: result.data.createdAt
            });
        } else {
            res.status(404).json({ 
                success: false, 
                error: 'Statut de paiement non trouvé',
                code: 'PAYMENT_STATUS_NOT_FOUND'
            });
        }
    } catch (error) {
        console.error('❌ Erreur vérification statut:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erreur lors de la vérification du statut',
            code: 'PAYMENT_STATUS_CHECK_ERROR'
        });
    }
});

app.get('/api/payment/transaction-status/:paymentId', authenticateToken, async (req, res) => {
    const { paymentId } = req.params;
    const userId = req.user.userId;

    try {
        db.get(
            'SELECT * FROM transactions WHERE payment_id = ? AND user_id = ?',
            [paymentId, userId],
            async (err, transaction) => {
                if (err || !transaction) {
                    return res.status(404).json({ 
                        success: false,
                        error: 'Transaction non trouvé',
                        code: 'TRANSACTION_NOT_FOUND'
                    });
                }

                if (transaction.status === 'completed') {
                    return res.json({
                        success: true,
                        status: 'completed',
                        transaction: transaction
                    });
                }

                if (transaction.moneyfusion_token) {
                    try {
                        const response = await fetch(`${MONEYFUSION_CONFIG.status_url}${transaction.moneyfusion_token}`);
                        
                        if (response.ok) {
                            const result = await response.json();
                            
                            if (result.statut && result.data) {
                                if (result.data.statut === 'completed' && transaction.status !== 'completed') {
                                    db.run(
                                        'UPDATE transactions SET status = ?, transaction_id = ?, completed_at = CURRENT_TIMESTAMP WHERE payment_id = ?',
                                        ['completed', result.data.numeroTransaction, paymentId]
                                    );

                                    if (transaction.plan_key && transaction.plan_key !== 'coin_purchase') {
                                        await createPanelFromPayment(transaction.user_id, transaction.plan_key, transaction.panel_name, transaction.env_type || 'nodejs');
                                    } else {
                                        db.run(
                                            'UPDATE users SET coins = coins + ? WHERE id = ?',
                                            [transaction.amount, transaction.user_id]
                                        );
                                    }

                                    db.get('SELECT * FROM users WHERE id = ?', [userId], async (err, user) => {
                                        if (!err && user) {
                                            await sendPaymentConfirmation(transaction, user);
                                        }
                                    });

                                    // NOUVEAU : Traiter la commission
                                    await processResellerCommission(transaction.user_id, transaction.amount, transaction.id);
                                }
                            }
                        }
                    } catch (apiError) {
                        console.error('Erreur vérification statut MoneyFusion:', apiError);
                    }
                }

                db.get(
                    'SELECT * FROM transactions WHERE payment_id = ?',
                    [paymentId],
                    (err, updatedTransaction) => {
                        if (err) {
                            return res.status(500).json({ 
                                success: false,
                                error: 'Erreur base de données',
                                code: 'DATABASE_ERROR'
                            });
                        }

                        res.json({
                            success: true,
                            status: updatedTransaction.status,
                            transaction: updatedTransaction
                        });
                    }
                );
            }
        );
    } catch (error) {
        console.error('❌ Erreur vérification statut transaction:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erreur lors de la vérification du statut',
            code: 'TRANSACTION_STATUS_CHECK_ERROR'
        });
    }
});

app.get('/payment/callback', async (req, res) => {
    try {
        const { payment_id: paymentId, status } = req.query;
        
        if (!paymentId) {
            console.error('❌ Payment ID manquant dans le callback');
            return res.status(400).send('Payment ID manquant');
        }

        db.get('SELECT * FROM transactions WHERE payment_id = ?', [paymentId], async (err, tx) => {
            if (err) {
                console.error('❌ Erreur DB callback:', err);
                return res.status(500).send('Erreur serveur lors de la récupération de la transaction');
            }

            if (!tx) {
                console.warn('❌ Transaction introuvable pour payment_id:', paymentId);
                return res.redirect(`/payment-cancel.html?payment_id=${encodeURIComponent(paymentId)}&reason=not_found`);
            }

            if (tx.status === 'completed') {
                console.log(`✅ Transaction ${paymentId} déjà complétée, redirection vers success`);
                return res.redirect(`/payment-success.html?payment_id=${encodeURIComponent(paymentId)}&transaction_id=${encodeURIComponent(tx.transaction_id || '')}&amount=${encodeURIComponent(tx.amount || '')}&plan=${encodeURIComponent(tx.plan_key || '')}&user_id=${encodeURIComponent(tx.user_id)}`);
            }

            let mfStatus = null;
            try {
                const token = tx.moneyfusion_token || null;
                if (token) {
                    console.log(`🔍 Vérification statut MoneyFusion pour token: ${token}`);
                    const mfResp = await fetch(`${MONEYFUSION_CONFIG.status_url}${encodeURIComponent(token)}`, {
                        method: 'GET',
                        headers: { 
                            'Accept': 'application/json',
                            'User-Agent': 'FLYHOST/2.0'
                        },
                        timeout: 10000
                    });
                    
                    if (mfResp.ok) {
                        const mfJson = await mfResp.json();
                        console.log('📥 Réponse MoneyFusion callback:', mfJson);
                        
                        if (mfJson && mfJson.data && mfJson.data.statut) {
                            mfStatus = mfJson.data.statut;
                            
                            if (mfStatus === 'completed' && tx.status !== 'completed') {
                                db.run(
                                    'UPDATE transactions SET status = ?, transaction_id = ?, completed_at = CURRENT_TIMESTAMP WHERE payment_id = ?',
                                    ['completed', mfJson.data.numeroTransaction, paymentId]
                                );

                                if (tx.plan_key && tx.plan_key !== 'coin_purchase') {
                                    await createPanelFromPayment(tx.user_id, tx.plan_key, tx.panel_name, tx.env_type || 'nodejs');
                                } else {
                                    db.run(
                                        'UPDATE users SET coins = coins + ? WHERE id = ?',
                                        [tx.amount, tx.user_id]
                                    );
                                }

                                db.get('SELECT * FROM users WHERE id = ?', [tx.user_id], async (err, user) => {
                                    if (!err && user) {
                                        await sendPaymentConfirmation(tx, user);
                                    }
                                });

                                // NOUVEAU : Traiter la commission
                                await processResellerCommission(tx.user_id, tx.amount, tx.id);
                            }
                        }
                    } else {
                        console.warn('⚠️ Réponse non-OK de MoneyFusion:', mfResp.status);
                    }
                }
            } catch (e) {
                console.warn('⚠️ Impossible d\'interroger MoneyFusion:', e.message);
            }

            const finalStatus = (mfStatus) ? mfStatus.toString().toLowerCase() : (status ? status.toString().toLowerCase() : tx.status);

            console.log(`🔍 Statut final déterminé: ${finalStatus} pour payment_id: ${paymentId}`);

            if (finalStatus === 'completed' || finalStatus === 'success') {
                console.log(`✅ Redirection vers success pour ${paymentId}`);
                return res.redirect(`/payment-success.html?payment_id=${encodeURIComponent(paymentId)}&transaction_id=${encodeURIComponent(tx.transaction_id || '')}&amount=${encodeURIComponent(tx.amount || '')}&plan=${encodeURIComponent(tx.plan_key || '')}&user_id=${encodeURIComponent(tx.user_id)}`);
            } else if (finalStatus === 'pending') {
                console.log(`⏳ Redirection vers pending pour ${paymentId}`);
                return res.redirect(`/payment-pending.html?payment_id=${encodeURIComponent(paymentId)}&message=pending`);
            } else {
                console.log(`❌ Redirection vers cancel pour ${paymentId}, statut: ${finalStatus}`);
                return res.redirect(`/payment-cancel.html?payment_id=${encodeURIComponent(paymentId)}&status=${encodeURIComponent(finalStatus)}`);
            }
        });
    } catch (error) {
        console.error('❌ Erreur /payment/callback:', error);
        res.status(500).send('Erreur serveur lors du traitement du callback');
    }
});

async function createPanelFromPayment(userId, plan, panelName, envType = 'nodejs') {
    console.log(`🔄 Création automatique du serveur ${plan} "${panelName}" [${envType}] pour l'utilisateur ${userId}`);
    
    return new Promise((resolve, reject) => {
        db.get('SELECT username, api_key FROM users WHERE id = ?', [userId], async (err, user) => {
            if (err || !user) {
                console.error('Utilisateur non trouvé pour création panel');
                reject('Utilisateur non trouvé');
                return;
            }

            try {
                const pteroUser = await createPterodactylUser(user.username, userId.toString());
                const planConfig = PLANS_CONFIG[plan];
                const serverName = `${panelName}-${plan}-${Date.now().toString().slice(-4)}`;
                
                const server = await createPterodactylServer({
                    name: serverName,
                    userId: pteroUser.id,
                    memory: planConfig.memory,
                    disk: planConfig.disk,
                    cpu: planConfig.cpu,
                    env_type: TECH_ENVIRONMENTS[envType] ? envType : 'nodejs'
                });

                const allocations = await getServerAllocations(server.id);

                let expiresAt = new Date();
                if (plan === 'free') {
                    expiresAt.setHours(expiresAt.getHours() + 24);
                } else {
                    expiresAt.setDate(expiresAt.getDate() + planConfig.duration);
                }

                db.run(
                    `INSERT INTO panels (user_id, panel_type, panel_name, pterodactyl_id, server_identifier, username, password, email, allocations, expires_at) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        userId,
                        plan,
                        panelName,
                        server.id,
                        server.identifier,
                        pteroUser.username,
                        pteroUser.password,
                        pteroUser.email,
                        JSON.stringify(allocations || []),
                        expiresAt.toISOString()
                    ],
                    function(err) {
                        if (err) {
                            reject('Erreur enregistrement serveur: ' + err.message);
                            return;
                        }

                        if (plan === 'free') {
                            db.run('UPDATE users SET free_panel_created = TRUE WHERE id = ?', [userId]);
                        }

                        console.log(`✅ serveur ${plan} créé automatiquement pour l'utilisateur ${userId}`);
                        resolve({
                            success: true,
                            panel: {
                                id: server.id,
                                identifier: server.identifier,
                                username: pteroUser.username,
                                password: pteroUser.password,
                                allocations: allocations
                            }
                        });
                    }
                );

            } catch (error) {
                console.error('❌ Erreur création serveur automatique:', error);
                reject(error);
            }
        });
    });
}

// =============================================
// ROUTES DU CHAT GLOBAL
// =============================================

// MODIFIER UN MESSAGE
app.put('/api/chat/message/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { content } = req.body;
    const userId = req.user.userId;

    if (!content || !content.trim()) {
        return res.status(400).json({
            success: false,
            error: 'Contenu du message requis'
        });
    }

    // Vérifier que l'utilisateur est propriétaire du message
    db.get(
        'SELECT user_id FROM chat_messages WHERE id = ?',
        [id],
        (err, message) => {
            if (err || !message) {
                return res.status(404).json({
                    success: false,
                    error: 'Message non trouvé'
                });
            }

            if (message.user_id !== userId && req.user.role !== 'superadmin') {
                return res.status(403).json({
                    success: false,
                    error: 'Non autorisé à modifier ce message'
                });
            }

            db.run(
                'UPDATE chat_messages SET content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                [content.trim(), id],
                function(err) {
                    if (err) {
                        console.error('Erreur modification message:', err);
                        return res.status(500).json({
                            success: false,
                            error: 'Erreur modification message'
                        });
                    }

                    // Récupérer le message modifié pour broadcast
                    db.get(
                        `SELECT cm.*, u.username, u.role 
                         FROM chat_messages cm
                         JOIN users u ON cm.user_id = u.id
                         WHERE cm.id = ?`,
                        [id],
                        (err, updatedMessage) => {
                            if (!err && updatedMessage) {
                                broadcastChatMessage(updatedMessage, 'message_updated');
                            }
                        }
                    );

                    res.json({
                        success: true,
                        message: 'Message modifié avec succès'
                    });
                }
            );
        }
    );
});

// SUPPRIMER UN MESSAGE
app.delete('/api/chat/message/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.userId;

    db.get(
        'SELECT user_id, media_url FROM chat_messages WHERE id = ?',
        [id],
        (err, message) => {
            if (err || !message) {
                return res.status(404).json({
                    success: false,
                    error: 'Message non trouvé'
                });
            }

            // Autoriser le propriétaire ou superadmin
            if (message.user_id !== userId && req.user.role !== 'superadmin') {
                return res.status(403).json({
                    success: false,
                    error: 'Non autorisé à supprimer ce message'
                });
            }

            // Supprimer le fichier média si présent
            if (message.media_url) {
                const filePath = path.join(__dirname, message.media_url);
                fs.unlink(filePath, (err) => {
                    if (err) console.error('Erreur suppression fichier:', err);
                });
            }

            db.run('DELETE FROM chat_messages WHERE id = ?', [id], function(err) {
                if (err) {
                    console.error('Erreur suppression message:', err);
                    return res.status(500).json({
                        success: false,
                        error: 'Erreur suppression message'
                    });
                }

                // Broadcast de la suppression
                broadcastChatUpdate('message_deleted', { message_id: id });

                // Journalisation si superadmin
                if (req.user.role === 'superadmin' && message.user_id !== userId) {
                    logAdminAction(
                        userId,
                        'chat_delete_message',
                        'message',
                        id,
                        `Suppression du message d'un autre utilisateur`
                    );
                }

                res.json({
                    success: true,
                    message: 'Message supprimé avec succès'
                });
            });
        }
    );
});

// RECHERCHER DES MESSAGES
app.get('/api/chat/search', authenticateToken, (req, res) => {
    const { q, limit = 20 } = req.query;

    if (!q || q.length < 2) {
        return res.status(400).json({
            success: false,
            error: 'Requête de recherche trop courte'
        });
    }

    db.all(
        `SELECT cm.*, u.username, u.role 
         FROM chat_messages cm
         JOIN users u ON cm.user_id = u.id
         WHERE cm.content LIKE ? 
         ORDER BY cm.created_at DESC
         LIMIT ?`,
        [`%${q}%`, parseInt(limit)],
        (err, messages) => {
            if (err) {
                console.error('Erreur recherche messages:', err);
                return res.status(500).json({
                    success: false,
                    error: 'Erreur recherche'
                });
            }

            res.json({
                success: true,
                messages: messages || []
            });
        }
    );
});

// STATISTIQUES DÉTAILLÉES
app.get('/api/chat/stats/detailed', authenticateToken, (req, res) => {
    const userId = req.user.userId;

    Promise.all([
        new Promise(r => db.get('SELECT COUNT(*) as total FROM chat_messages', [], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as today FROM chat_messages WHERE date(created_at) = date("now")', [], (e, row) => r(row?.today || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as this_week FROM chat_messages WHERE created_at > datetime("now", "-7 days")', [], (e, row) => r(row?.this_week || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as media FROM chat_messages WHERE media_type IS NOT NULL', [], (e, row) => r(row?.media || 0))),
        new Promise(r => db.get('SELECT user_id, COUNT(*) as count FROM chat_messages GROUP BY user_id ORDER BY count DESC LIMIT 1', [], (e, row) => r(row))),
        new Promise(r => db.get('SELECT COUNT(DISTINCT user_id) as active_users FROM chat_messages WHERE created_at > datetime("now", "-7 days")', [], (e, row) => r(row?.active_users || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as messages_sent FROM chat_messages WHERE user_id = ?', [userId], (e, row) => r(row?.messages_sent || 0)))
    ]).then(([total, today, week, media, topUser, activeUsers, userMessages]) => {
        res.json({
            success: true,
            stats: {
                total_messages: total,
                messages_today: today,
                messages_this_week: week,
                total_media: media,
                most_active_user: topUser,
                active_users_week: activeUsers,
                user_messages: userMessages
            }
        });
    }).catch(error => {
        console.error('Erreur stats détaillées:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur récupération statistiques'
        });
    });
});

// Récupérer l'historique des messages
app.get('/api/chat/messages', authenticateToken, (req, res) => {
    const { limit = CHAT_CONFIG.message_history_limit, before } = req.query;

    let query = `
        SELECT cm.*, u.username, u.role 
        FROM chat_messages cm
        JOIN users u ON cm.user_id = u.id
        WHERE 1=1
    `;
    const params = [];

    if (before) {
        query += ' AND cm.id < ?';
        params.push(before);
    }

    query += ' ORDER BY cm.created_at DESC LIMIT ?';
    params.push(parseInt(limit));

    db.all(query, params, (err, messages) => {
        if (err) {
            console.error('❌ Erreur récupération messages chat:', err);
            return res.status(500).json({ 
                success: false, 
                error: 'Erreur récupération messages' 
            });
        }

        res.json({ 
            success: true, 
            messages: messages.reverse() // Pour avoir du plus vieux au plus récent
        });
    });
});

// VOIR LE PROFIL D'UN UTILISATEUR
app.get('/api/chat/user/:userId/profile', authenticateToken, (req, res) => {
    const { userId } = req.params;

    db.get(
        `SELECT u.id, u.username, u.role, u.created_at,
                (SELECT COUNT(*) FROM chat_messages WHERE user_id = u.id) as total_messages,
                (SELECT COUNT(*) FROM chat_messages WHERE user_id = u.id AND media_type IS NOT NULL) as media_sent,
                (SELECT created_at FROM chat_messages WHERE user_id = u.id ORDER BY created_at DESC LIMIT 1) as last_message,
                u.last_login > datetime('now', '-5 minutes') as online
         FROM users u
         WHERE u.id = ?`,
        [userId],
        (err, user) => {
            if (err || !user) {
                return res.status(404).json({
                    success: false,
                    error: 'Utilisateur non trouvé'
                });
            }

            res.json({
                success: true,
                profile: user
            });
        }
    );
});

// ÉPINGLER UN MESSAGE (superadmin uniquement)
app.post('/api/chat/pin', authenticateToken, requireSuperAdmin, (req, res) => {
    const { message_id } = req.body;

    db.run(
        'INSERT INTO chat_pinned_messages (message_id, pinned_by) VALUES (?, ?)',
        [message_id, req.user.userId],
        function(err) {
            if (err) {
                console.error('Erreur épinglage:', err);
                return res.status(500).json({
                    success: false,
                    error: 'Erreur épinglage'
                });
            }

            broadcastChatUpdate('message_pinned', { message_id });
            res.json({ success: true });
        }
    );
});

// DÉSÉPINGLER UN MESSAGE
app.delete('/api/chat/pin/:messageId', authenticateToken, requireSuperAdmin, (req, res) => {
    db.run(
        'DELETE FROM chat_pinned_messages WHERE message_id = ?',
        [req.params.messageId],
        function(err) {
            if (err) {
                console.error('Erreur désépinglage:', err);
                return res.status(500).json({
                    success: false,
                    error: 'Erreur désépinglage'
                });
            }

            broadcastChatUpdate('message_unpinned', { message_id: req.params.messageId });
            res.json({ success: true });
        }
    );
});

// AJOUTER/SUPPRIMER UNE RÉACTION
app.post('/api/chat/reaction', authenticateToken, async (req, res) => {
    const { message_id, emoji } = req.body;
    const userId = req.user.userId;

    if (!message_id || !emoji) {
        return res.status(400).json({
            success: false,
            error: 'Message ID et emoji requis'
        });
    }

    // Vérifier si la réaction existe déjà
    db.get(
        'SELECT id FROM chat_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?',
        [message_id, userId, emoji],
        (err, existing) => {
            if (err) {
                console.error('Erreur vérification réaction:', err);
                return res.status(500).json({
                    success: false,
                    error: 'Erreur serveur'
                });
            }

            if (existing) {
                // Supprimer la réaction
                db.run(
                    'DELETE FROM chat_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?',
                    [message_id, userId, emoji],
                    function(err) {
                        if (err) {
                            console.error('Erreur suppression réaction:', err);
                            return res.status(500).json({
                                success: false,
                                error: 'Erreur suppression réaction'
                            });
                        }

                        broadcastReactionUpdate(message_id);
                        res.json({
                            success: true,
                            action: 'removed',
                            message: 'Réaction retirée'
                        });
                    }
                );
            } else {
                // Ajouter la réaction
                db.run(
                    'INSERT INTO chat_reactions (message_id, user_id, emoji) VALUES (?, ?, ?)',
                    [message_id, userId, emoji],
                    function(err) {
                        if (err) {
                            console.error('Erreur ajout réaction:', err);
                            return res.status(500).json({
                                success: false,
                                error: 'Erreur ajout réaction'
                            });
                        }

                        broadcastReactionUpdate(message_id);
                        res.json({
                            success: true,
                            action: 'added',
                            message: 'Réaction ajoutée'
                        });
                    }
                );
            }
        }
    );
});

// RÉCUPÉRER LES RÉACTIONS D'UN MESSAGE
app.get('/api/chat/message/:id/reactions', authenticateToken, (req, res) => {
    const { id } = req.params;

    db.all(
        `SELECT cr.emoji, cr.user_id, u.username,
                COUNT(*) as count,
                SUM(CASE WHEN cr.user_id = ? THEN 1 ELSE 0 END) as user_reacted
         FROM chat_reactions cr
         JOIN users u ON cr.user_id = u.id
         WHERE cr.message_id = ?
         GROUP BY cr.emoji`,
        [req.user.userId, id],
        (err, reactions) => {
            if (err) {
                console.error('Erreur récupération réactions:', err);
                return res.status(500).json({
                    success: false,
                    error: 'Erreur récupération réactions'
                });
            }

            res.json({
                success: true,
                reactions: reactions || []
            });
        }
    );
});

// Fonction de broadcast des réactions
function broadcastReactionUpdate(messageId) {
    db.all(
        `SELECT cr.emoji, cr.user_id, u.username,
                COUNT(*) as count,
                SUM(CASE WHEN cr.user_id = ? THEN 1 ELSE 0 END) as user_reacted
         FROM chat_reactions cr
         JOIN users u ON cr.user_id = u.id
         WHERE cr.message_id = ?
         GROUP BY cr.emoji`,
        [req?.user?.userId || 0, messageId],
        (err, reactions) => {
            if (!err) {
                broadcastChatUpdate('reactions_update', {
                    message_id: messageId,
                    reactions: reactions || []
                });
            }
        }
    );
}

// RÉCUPÉRER LES MESSAGES ÉPINGLÉS
app.get('/api/chat/pinned', authenticateToken, (req, res) => {
    db.all(
        `SELECT cm.*, u.username, u.role, cpm.pinned_at, pu.username as pinned_by_username
         FROM chat_pinned_messages cpm
         JOIN chat_messages cm ON cpm.message_id = cm.id
         JOIN users u ON cm.user_id = u.id
         JOIN users pu ON cpm.pinned_by = pu.id
         ORDER BY cpm.pinned_at DESC`,
        [],
        (err, messages) => {
            if (err) {
                console.error('Erreur récupération messages épinglés:', err);
                return res.status(500).json({
                    success: false,
                    error: 'Erreur récupération'
                });
            }

            res.json({
                success: true,
                pinned_messages: messages || []
            });
        }
    );
});

// =============================================
// ENVOYER UN MESSAGE (TEXTE OU MÉDIA) AVEC SUPPORT DES RÉPONSES
// =============================================
app.post('/api/chat/send', authenticateToken, chatUpload.single('media'), async (req, res) => {
    const userId = req.user.userId;
    const { content, reply_to } = req.body;
    const file = req.file;

    if (!content && !file) {
        return res.status(400).json({ 
            success: false, 
            error: 'Message ou média requis' 
        });
    }

    // Vérifier les restrictions
    const settings = await new Promise(r => 
        db.get('SELECT restriction_enabled, media_disabled FROM chat_settings WHERE id = 1', [], (e, row) => r(row))
    );

    const user = await new Promise(r => 
        db.get('SELECT role FROM users WHERE id = ?', [userId], (e, row) => r(row))
    );

    // Vérifier si l'utilisateur est muté
    const isMuted = await new Promise(r => 
        db.get(
            'SELECT * FROM chat_mutes WHERE user_id = ? AND (muted_until IS NULL OR muted_until > datetime("now"))',
            [userId], (e, row) => r(!!row)
        )
    );

    if (isMuted && user.role !== 'superadmin') {
        return res.status(403).json({ 
            success: false, 
            error: 'Vous avez été restreint par un administrateur' 
        });
    }

    if (settings.restriction_enabled && user.role !== 'superadmin') {
        return res.status(403).json({ 
            success: false, 
            error: 'Mode silencieux activé. Seuls les superadmins peuvent envoyer des messages.' 
        });
    }

    if (file && settings.media_disabled && user.role !== 'superadmin') {
        return res.status(403).json({ 
            success: false, 
            error: 'L\'envoi de médias est temporairement désactivé' 
        });
    }

    // Vérifier que le message reply_to existe si fourni
    if (reply_to) {
        const replyExists = await new Promise(r => 
            db.get('SELECT id FROM chat_messages WHERE id = ?', [reply_to], (e, row) => r(!!row))
        );
        if (!replyExists) {
            return res.status(400).json({
                success: false,
                error: 'Le message auquel vous répondez n\'existe plus'
            });
        }
    }

    let mediaUrl = null;
    let mediaType = null;
    let mediaSize = null;

    if (file) {
        // Déterminer le type de média
        if (CHAT_CONFIG.allowed_image_types.includes(file.mimetype)) {
            mediaType = 'image';
        } else if (CHAT_CONFIG.allowed_video_types.includes(file.mimetype)) {
            mediaType = 'video';
        } else if (CHAT_CONFIG.allowed_audio_types.includes(file.mimetype)) {
            mediaType = 'audio';
        } else {
            return res.status(400).json({
                success: false,
                error: 'Type de fichier non supporté'
            });
        }

        // Générer un nom de fichier unique
        const ext = path.extname(file.originalname);
        const filename = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${ext}`;
        const filepath = path.join(CHAT_CONFIG.upload_dir, filename);
        
        // Déplacer le fichier
        fs.renameSync(file.path, filepath);
        
        mediaUrl = `/uploads/chat/${filename}`;
        mediaSize = file.size;
    }

    db.run(
        `INSERT INTO chat_messages (user_id, content, media_type, media_url, media_size, reply_to)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [userId, content || null, mediaType, mediaUrl, mediaSize, reply_to || null],
        function(err) {
            if (err) {
                console.error('❌ Erreur envoi message chat:', err);
                return res.status(500).json({ 
                    success: false, 
                    error: 'Erreur envoi message' 
                });
            }

            // Récupérer le message complet avec les infos de l'utilisateur
            db.get(
                `SELECT cm.*, u.username, u.role 
                 FROM chat_messages cm
                 JOIN users u ON cm.user_id = u.id
                 WHERE cm.id = ?`,
                [this.lastID],
                (err, message) => {
                    if (!err && message) {
                        // Si c'est une réponse, ajouter les infos du message original
                        if (message.reply_to) {
                            db.get(
                                `SELECT cm.id, cm.content, cm.media_type, u.username
                                 FROM chat_messages cm
                                 JOIN users u ON cm.user_id = u.id
                                 WHERE cm.id = ?`,
                                [message.reply_to],
                                (err, replyMsg) => {
                                    if (!err && replyMsg) {
                                        message.reply_to_data = replyMsg;
                                    }
                                    // Broadcast via WebSocket
                                    broadcastChatMessage(message);
                                }
                            );
                        } else {
                            // Broadcast via WebSocket
                            broadcastChatMessage(message);
                        }
                    }
                }
            );

            // Journaliser l'activité
            db.run(
                `INSERT INTO user_activities (user_id, activity_type, description)
                 VALUES (?, 'chat_message', ?)`,
                [userId, `Message envoyé dans le chat global`]
            );

            res.json({ 
                success: true, 
                message: 'Message envoyé',
                id: this.lastID
            });
        }
    );
});

// Récupérer la liste des membres
app.get('/api/chat/members', authenticateToken, (req, res) => {
    db.all(
        `SELECT u.id, u.username, u.role,
                (SELECT COUNT(*) FROM chat_messages WHERE user_id = u.id) as message_count,
                u.last_login > datetime('now', '-5 minutes') as online
         FROM users u
         WHERE u.email_verified = 1
         ORDER BY online DESC, u.role, u.username`,
        [],
        (err, members) => {
            if (err) {
                console.error('❌ Erreur récupération membres:', err);
                return res.status(500).json({ 
                    success: false, 
                    error: 'Erreur récupération membres' 
                });
            }

            res.json({ success: true, members });
        }
    );
});

// Récupérer les paramètres du chat
app.get('/api/chat/settings', authenticateToken, (req, res) => {
    db.get('SELECT * FROM chat_settings WHERE id = 1', [], (err, settings) => {
        if (err) {
            return res.status(500).json({ success: false, error: 'Erreur récupération paramètres' });
        }

        db.all('SELECT user_id FROM chat_mutes WHERE muted_until IS NULL OR muted_until > datetime("now")', [], (err, mutes) => {
            const mutedUsers = (mutes || []).map(m => m.user_id);

            res.json({
                success: true,
                settings: {
                    restriction_enabled: settings?.restriction_enabled || false,
                    media_disabled: settings?.media_disabled || false,
                    muted_users: mutedUsers
                }
            });
        });
    });
});

// =============================================
// ROUTES ADMIN DU CHAT (superadmin uniquement)
// =============================================

// Activer/désactiver le mode silencieux
app.post('/api/chat/restriction', authenticateToken, requireSuperAdmin, (req, res) => {
    const { enabled } = req.body;

    db.run(
        'UPDATE chat_settings SET restriction_enabled = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1',
        [enabled ? 1 : 0, req.user.userId],
        function(err) {
            if (err) {
                return res.status(500).json({ success: false, error: 'Erreur mise à jour' });
            }

            // Broadcast du changement
            broadcastChatUpdate('restriction_update', { enabled });

            logAdminAction(
                req.user.userId,
                'chat_restriction',
                'system',
                null,
                `Mode silencieux ${enabled ? 'activé' : 'désactivé'}`
            );

            res.json({ success: true });
        }
    );
});

// Activer/désactiver les médias
app.post('/api/chat/media', authenticateToken, requireSuperAdmin, (req, res) => {
    const { disabled } = req.body;

    db.run(
        'UPDATE chat_settings SET media_disabled = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1',
        [disabled ? 1 : 0, req.user.userId],
        function(err) {
            if (err) {
                return res.status(500).json({ success: false, error: 'Erreur mise à jour' });
            }

            // Broadcast du changement
            broadcastChatUpdate('media_update', { disabled });

            logAdminAction(
                req.user.userId,
                'chat_media',
                'system',
                null,
                `Médias ${disabled ? 'désactivés' : 'activés'}`
            );

            res.json({ success: true });
        }
    );
});

// Effacer tous les messages
app.post('/api/chat/clear', authenticateToken, requireSuperAdmin, (req, res) => {
    db.serialize(() => {
        db.run('DELETE FROM chat_messages');
        db.run('DELETE FROM sqlite_sequence WHERE name="chat_messages"');

        // Broadcast
        broadcastChatUpdate('clear_chat', {});

        logAdminAction(
            req.user.userId,
            'chat_clear',
            'system',
            null,
            'Tous les messages du chat ont été effacés'
        );

        res.json({ success: true, message: 'Chat effacé' });
    });
});

// Restreindre un membre (mute)
app.post('/api/chat/mute', authenticateToken, requireSuperAdmin, (req, res) => {
    const { user_id, muted, duration_hours, reason } = req.body;

    if (muted) {
        let mutedUntil = null;
        if (duration_hours) {
            mutedUntil = new Date();
            mutedUntil.setHours(mutedUntil.getHours() + duration_hours);
        }

        db.run(
            `INSERT OR REPLACE INTO chat_mutes (user_id, muted_by, reason, muted_until)
             VALUES (?, ?, ?, ?)`,
            [user_id, req.user.userId, reason || null, mutedUntil?.toISOString()],
            function(err) {
                if (err) {
                    return res.status(500).json({ success: false, error: 'Erreur restriction' });
                }

                broadcastChatUpdate('mute_update', { user_id, muted: true });

                logAdminAction(
                    req.user.userId,
                    'chat_mute',
                    'user',
                    user_id,
                    `Membre restreint${duration_hours ? ` pour ${duration_hours}h` : ''}${reason ? `: ${reason}` : ''}`
                );

                res.json({ success: true });
            }
        );
    } else {
        db.run('DELETE FROM chat_mutes WHERE user_id = ?', [user_id], function(err) {
            if (err) {
                return res.status(500).json({ success: false, error: 'Erreur levée restriction' });
            }

            broadcastChatUpdate('mute_update', { user_id, muted: false });

            logAdminAction(
                req.user.userId,
                'chat_unmute',
                'user',
                user_id,
                'Restriction levée'
            );

            res.json({ success: true });
        });
    }
});

// Demander la parole (quand mode silencieux activé)
app.post('/api/chat/request-speak', authenticateToken, (req, res) => {
    const userId = req.user.userId;

    // Vérifier si une demande est déjà en attente
    db.get(
        'SELECT * FROM chat_speak_requests WHERE user_id = ? AND status = "pending"',
        [userId],
        (err, existing) => {
            if (existing) {
                return res.status(400).json({ 
                    success: false, 
                    error: 'Vous avez déjà une demande en attente' 
                });
            }

            db.run(
                'INSERT INTO chat_speak_requests (user_id) VALUES (?)',
                [userId],
                function(err) {
                    if (err) {
                        return res.status(500).json({ success: false, error: 'Erreur demande' });
                    }

                    // Notifier les superadmins
                    db.all('SELECT id FROM users WHERE role = "superadmin"', [], (err, admins) => {
                        admins?.forEach(admin => {
                            if (global.sendNotification) {
                                global.sendNotification(admin.id, {
                                    title: '🗣️ Demande de parole',
                                    message: `${req.user.username} souhaite parler dans le chat`,
                                    type: 'info',
                                    metadata: { user_id: userId, request_id: this.lastID }
                                });
                            }
                        });
                    });

                    res.json({ 
                        success: true, 
                        message: 'Demande envoyée aux administrateurs' 
                    });
                }
            );
        }
    );
});

// Liste des demandes de parole (superadmin)
app.get('/api/chat/speak-requests', authenticateToken, requireSuperAdmin, (req, res) => {
    db.all(
        `SELECT sr.*, u.username 
         FROM chat_speak_requests sr
         JOIN users u ON sr.user_id = u.id
         WHERE sr.status = "pending"
         ORDER BY sr.created_at ASC`,
        [],
        (err, requests) => {
            res.json({ success: true, requests: requests || [] });
        }
    );
});

// Répondre à une demande de parole
app.post('/api/chat/speak-requests/:id/respond', authenticateToken, requireSuperAdmin, (req, res) => {
    const { id } = req.params;
    const { approve } = req.body;

    db.get('SELECT user_id FROM chat_speak_requests WHERE id = ?', [id], (err, request) => {
        if (!request) {
            return res.status(404).json({ success: false, error: 'Demande non trouvée' });
        }

        db.run(
            `UPDATE chat_speak_requests 
             SET status = ?, resolved_by = ?, resolved_at = CURRENT_TIMESTAMP 
             WHERE id = ?`,
            [approve ? 'approved' : 'rejected', req.user.userId, id],
            function(err) {
                if (err) {
                    return res.status(500).json({ success: false, error: 'Erreur' });
                }

                if (approve) {
                    // Retirer temporairement la restriction pour cet utilisateur
                    // (à faire via un système de permissions temporaires)
                }

                if (global.sendNotification) {
                    global.sendNotification(request.user_id, {
                        title: approve ? '✅ Demande approuvée' : '❌ Demande refusée',
                        message: approve 
                            ? 'Vous pouvez maintenant envoyer des messages'
                            : 'Votre demande de parole a été refusée',
                        type: approve ? 'success' : 'error'
                    });
                }

                res.json({ success: true });
            }
        );
    });
});

// Statistiques du chat
app.get('/api/chat/stats', authenticateToken, (req, res) => {
    Promise.all([
        new Promise(r => db.get('SELECT COUNT(*) as total FROM chat_messages', [], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM chat_messages WHERE media_type IS NOT NULL', [], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM users WHERE email_verified = 1', [], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM users WHERE last_login > datetime("now", "-5 minutes")', [], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM chat_mutes WHERE muted_until IS NULL OR muted_until > datetime("now")', [], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM chat_speak_requests WHERE status = "pending"', [], (e, row) => r(row?.total || 0)))
    ]).then(([totalMessages, totalMedia, totalUsers, onlineUsers, mutedUsers, pendingRequests]) => {
        res.json({
            success: true,
            stats: {
                total_messages: totalMessages,
                total_media: totalMedia,
                total_users: totalUsers,
                online_users: onlineUsers,
                muted_users: mutedUsers,
                pending_requests: pendingRequests
            }
        });
    });
});

// Route pour servir les fichiers uploadés
app.use('/uploads/chat', express.static(CHAT_CONFIG.upload_dir));

// =============================================
// ROUTES GRADE ADMIN (REVENDEUR)
// =============================================

app.post('/api/grade/admin/purchase', authenticateToken, async (req, res) => {
    const { payment_method } = req.body;
    const userId = req.user.userId;
    
    db.get('SELECT coins, role FROM users WHERE id = ?', [userId], async (err, user) => {
        if (err || !user) {
            return res.status(404).json({ success: false, error: 'Utilisateur non trouvé' });
        }
        
        if (payment_method === 'coins') {
            if (user.coins < ADMIN_GRADE_CONFIG.price_coins) {
                return res.status(400).json({ 
                    success: false, 
                    error: `Coins insuffisants. Il vous faut ${ADMIN_GRADE_CONFIG.price_coins} coins` 
                });
            }
            
            const expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + ADMIN_GRADE_CONFIG.duration_days);
            
            db.run(`UPDATE users SET 
                role = 'admin',
                admin_expires_at = ?,
                admin_access_active = 1,
                coins = coins - ?
                WHERE id = ?`,
                [expiresAt.toISOString(), ADMIN_GRADE_CONFIG.price_coins, userId],
                function(err) {
                    if (err) {
                        return res.status(500).json({ success: false, error: 'Erreur activation' });
                    }
                    
                    db.run('INSERT INTO user_activities (user_id, activity_type, coins_earned, description) VALUES (?, ?, ?, ?)',
                        [userId, 'admin_purchase', -ADMIN_GRADE_CONFIG.price_coins, 'Achat du grade Admin']);
                    
                    res.json({ 
                        success: true, 
                        message: 'Grade Admin activé !',
                        expires_at: expiresAt
                    });
                }
            );
            
        } else if (payment_method === 'money') {
            const paymentId = 'ADMIN_' + crypto.randomBytes(8).toString('hex').toUpperCase();
            
            const paymentData = {
                totalPrice: ADMIN_GRADE_CONFIG.price_money,
                article: [{ name: 'Grade Admin FLYHOST (30 jours)', price: ADMIN_GRADE_CONFIG.price_money }],
                personal_Info: [{ userId, paymentId, type: 'admin_grade' }],
                numeroSend: req.body.phone_number || '',
                nomclient: user.username,
                return_url: `${WEB_CONFIG.SITE_URL}/grade/callback?payment_id=${paymentId}`,
                webhook_url: `${WEB_CONFIG.SITE_URL}/api/grade/webhook`
            };
            
            try {
                const response = await fetch(MONEYFUSION_CONFIG.api_url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(paymentData)
                });
                const result = await response.json();
                
                if (result.statut && result.url) {
                    res.json({ success: true, paymentUrl: result.url, paymentId });
                } else {
                    throw new Error('Erreur MoneyFusion');
                }
            } catch (error) {
                res.status(500).json({ success: false, error: 'Erreur paiement' });
            }
        }
    });
});

app.post('/api/grade/webhook', express.json(), async (req, res) => {
    const { event, tokenPay, personal_Info } = req.body;
    if (event !== 'payin.session.completed') return res.json({ success: true });
    
    const userId = personal_Info[0].userId;
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + ADMIN_GRADE_CONFIG.duration_days);
    
    db.run(`UPDATE users SET 
        role = 'admin',
        admin_expires_at = ?,
        admin_access_active = 1
        WHERE id = ?`,
        [expiresAt.toISOString(), userId]
    );
    
    res.json({ success: true });
});

// =============================================
// ROUTES REVENDEUR (/api/reseller)
// =============================================

// 4.1 — Accepter le contrat revendeur
app.post('/api/reseller/contract/accept', authenticateToken, requireAdmin, async (req, res) => {
    const { business_name, support_email } = req.body;
    const userId = req.user.userId;

    try {
        const affiliateCode = generateAffiliateCode();

        db.run(
            `INSERT INTO reseller_profiles 
             (user_id, business_name, support_email, affiliate_code, contract_accepted, contract_accepted_at, contract_ip, commission_rate)
             VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP, ?, ?)`,
            [userId, business_name, support_email, affiliateCode, req.ip, RESELLER_CONFIG.default_commission_rate],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        return res.status(400).json({ 
                            success: false, 
                            error: 'Vous avez déjà un profil revendeur' 
                        });
                    }
                    console.error('Erreur création profil revendeur:', err);
                    return res.status(500).json({ 
                        success: false, 
                        error: 'Erreur création profil' 
                    });
                }

                const affiliateUrl = `${WEB_CONFIG.SITE_URL}/register?aff=${affiliateCode}`;

                logSystem('reseller', 'Nouveau revendeur', { 
                    user_id: userId, 
                    business_name,
                    affiliate_code: affiliateCode 
                });

                res.json({
                    success: true,
                    message: 'Contrat revendeur accepté !',
                    affiliate_code: affiliateCode,
                    affiliate_url: affiliateUrl,
                    commission_rate: RESELLER_CONFIG.default_commission_rate
                });
            }
        );
    } catch (error) {
        console.error('Erreur acceptation contrat:', error);
        res.status(500).json({ success: false, error: 'Erreur serveur' });
    }
});

// 4.2 — Dashboard revendeur
app.get('/api/reseller/dashboard', authenticateToken, requireAdmin, async (req, res) => {
    const userId = req.user.userId;

    try {
        const profile = await new Promise(r => 
            db.get('SELECT * FROM reseller_profiles WHERE user_id = ?', [userId], (e, row) => r(row))
        );

        if (!profile) {
            return res.status(404).json({ 
                success: false, 
                error: 'Profil revendeur non trouvé' 
            });
        }

        // Clients count
        const clients = await new Promise(r => 
            db.get('SELECT COUNT(*) as total FROM reseller_clients WHERE reseller_id = ?', [userId], (e, row) => r(row?.total || 0))
        );

        // Active clients (with at least one active server)
        const activeClients = await new Promise(r => 
            db.get(
                `SELECT COUNT(DISTINCT rc.client_id) as total
                 FROM reseller_clients rc
                 JOIN servers s ON rc.client_id = s.user_id
                 WHERE rc.reseller_id = ? AND s.is_active = 1`,
                [userId], (e, row) => r(row?.total || 0)
            )
        );

        // Servers under management
        const serversManaged = await new Promise(r => 
            db.get(
                `SELECT COUNT(*) as total
                 FROM servers s
                 JOIN reseller_clients rc ON s.user_id = rc.client_id
                 WHERE rc.reseller_id = ? AND s.is_active = 1`,
                [userId], (e, row) => r(row?.total || 0)
            )
        );

        // Pending withdrawals
        const pendingWithdrawals = await new Promise(r => 
            db.get(
                'SELECT COUNT(*) as total, SUM(amount) as total_amount FROM withdrawal_requests WHERE reseller_id = ? AND status = "pending"',
                [userId], (e, row) => r({ count: row?.total || 0, amount: row?.total_amount || 0 })
            )
        );

        // Recent commissions (5 dernières)
        const recentCommissions = await new Promise(r => 
            db.all(
                `SELECT cl.*, u.username as client_username
                 FROM commission_logs cl
                 JOIN users u ON cl.client_id = u.id
                 WHERE cl.reseller_id = ?
                 ORDER BY cl.created_at DESC
                 LIMIT 5`,
                [userId], (e, rows) => r(rows || [])
            )
        );

        // Top clients (3 meilleurs par dépenses)
        const topClients = await new Promise(r => 
            db.all(
                `SELECT u.id, u.username, u.coins, u.created_at,
                        COUNT(s.id) as server_count,
                        SUM(CASE WHEN s.is_active = 1 THEN 1 ELSE 0 END) as active_servers
                 FROM reseller_clients rc
                 JOIN users u ON rc.client_id = u.id
                 LEFT JOIN servers s ON u.id = s.user_id
                 WHERE rc.reseller_id = ?
                 GROUP BY u.id
                 ORDER BY u.coins DESC
                 LIMIT 3`,
                [userId], (e, rows) => r(rows || [])
            )
        );

        // Monthly revenue
        const firstDayOfMonth = new Date();
        firstDayOfMonth.setDate(1);
        firstDayOfMonth.setHours(0, 0, 0, 0);

        const monthlyRevenue = await new Promise(r => 
            db.get(
                `SELECT SUM(amount) as total
                 FROM commission_logs
                 WHERE reseller_id = ? AND created_at >= ?`,
                [userId, firstDayOfMonth.toISOString()], (e, row) => r(row?.total || 0)
            )
        );

        res.json({
            success: true,
            dashboard: {
                business_name: profile.business_name,
                commission_rate: profile.commission_rate,
                commission_balance: profile.commission_balance,
                total_earned: profile.total_earned,
                total_withdrawn: profile.total_withdrawn,
                clients_count: clients,
                active_clients: activeClients,
                servers_under_management: serversManaged,
                pending_withdrawals: pendingWithdrawals,
                recent_commissions: recentCommissions,
                top_clients: topClients,
                monthly_revenue: monthlyRevenue,
                active: profile.active,
                affiliate_code: profile.affiliate_code,
                max_clients: profile.max_clients,
                bulk_discount_rate: profile.bulk_discount_rate,
                plan_name: profile.business_name || 'Revendeur'
            }
        });

    } catch (error) {
        console.error('Erreur dashboard revendeur:', error);
        res.status(500).json({ success: false, error: 'Erreur serveur' });
    }
});

// 4.3 — Liste des clients du revendeur
app.get('/api/reseller/clients', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.user.userId;
    const { limit = 20, offset = 0, search = '' } = req.query;

    let query = `
        SELECT u.id, u.username, u.email, u.coins, u.created_at,
               COUNT(s.id) as server_count,
               SUM(CASE WHEN s.is_active = 1 THEN 1 ELSE 0 END) as active_servers,
               rc.acquisition_source, rc.created_at as acquired_at,
               (SELECT SUM(base_amount) FROM commission_logs WHERE client_id = u.id) as total_spent
        FROM reseller_clients rc
        JOIN users u ON rc.client_id = u.id
        LEFT JOIN servers s ON u.id = s.user_id
        WHERE rc.reseller_id = ?
    `;
    const params = [userId];

    if (search) {
        query += ' AND (u.username LIKE ? OR u.email LIKE ?)';
        params.push(`%${search}%`, `%${search}%`);
    }

    query += ' GROUP BY u.id ORDER BY rc.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    db.all(query, params, (err, clients) => {
        if (err) {
            console.error('Erreur récupération clients:', err);
            return res.status(500).json({ success: false, error: 'Erreur récupération clients' });
        }

        db.get(
            'SELECT COUNT(*) as total FROM reseller_clients WHERE reseller_id = ?',
            [userId],
            (err, count) => {
                res.json({
                    success: true,
                    clients: clients || [],
                    total: count?.total || 0,
                    limit: parseInt(limit),
                    offset: parseInt(offset)
                });
            }
        );
    });
});

// 4.4 — Détails d'un client spécifique
app.get('/api/reseller/clients/:clientId', authenticateToken, requireAdmin, async (req, res) => {
    const { clientId } = req.params;
    const resellerId = req.user.userId;

    try {
        // Vérifier que le client appartient au revendeur
        const ownership = await new Promise(r => 
            db.get(
                'SELECT * FROM reseller_clients WHERE reseller_id = ? AND client_id = ?',
                [resellerId, clientId], (e, row) => r(row)
            )
        );

        if (!ownership) {
            return res.status(403).json({ 
                success: false, 
                error: 'Ce client ne vous appartient pas' 
            });
        }

        const user = await new Promise(r => 
            db.get(
                'SELECT id, username, email, coins, created_at, last_login FROM users WHERE id = ?',
                [clientId], (e, row) => r(row)
            )
        );

        const servers = await new Promise(r => 
            db.all(
                'SELECT id, server_name, server_type, server_status, expires_at, is_active FROM servers WHERE user_id = ? ORDER BY created_at DESC',
                [clientId], (e, rows) => r(rows || [])
            )
        );

        const transactions = await new Promise(r => 
            db.all(
                'SELECT id, plan_key, amount, status, created_at FROM transactions WHERE user_id = ? AND status = "completed" ORDER BY created_at DESC LIMIT 10',
                [clientId], (e, rows) => r(rows || [])
            )
        );

        const commissions = await new Promise(r => 
            db.all(
                'SELECT * FROM commission_logs WHERE client_id = ? ORDER BY created_at DESC',
                [clientId], (e, rows) => r(rows || [])
            )
        );

        const totalCommission = commissions.reduce((sum, c) => sum + c.amount, 0);

        res.json({
            success: true,
            client: {
                user,
                servers,
                transactions,
                commissions_generated: {
                    total: totalCommission,
                    logs: commissions
                },
                acquisition_source: ownership.acquisition_source,
                acquired_at: ownership.created_at
            }
        });

    } catch (error) {
        console.error('Erreur détails client:', error);
        res.status(500).json({ success: false, error: 'Erreur serveur' });
    }
});

// 4.5b — Liste des achats en gros
app.get('/api/reseller/bulk-purchases', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.user.userId;
    db.all(
        `SELECT bp.*, u.username as reseller_username 
         FROM bulk_purchases bp
         LEFT JOIN users u ON bp.reseller_id = u.id
         WHERE bp.reseller_id = ?
         ORDER BY bp.created_at DESC LIMIT 50`,
        [userId],
        (err, rows) => {
            if (err) return res.status(500).json({ success: false, error: 'Erreur serveur' });
            res.json({ success: true, purchases: rows || [] });
        }
    );
});

// 4.5 — Achat en gros (Bulk Purchase)
app.post('/api/reseller/bulk-purchase', authenticateToken, requireAdmin, async (req, res) => {
    const { plan_key, quantity } = req.body;
    const userId = req.user.userId;

    if (!plan_key || !quantity || quantity < 1) {
        return res.status(400).json({ 
            success: false, 
            error: 'Plan et quantité requis' 
        });
    }

    if (!PLAN_COINS_PRICES[plan_key]) {
        return res.status(400).json({ 
            success: false, 
            error: 'Plan invalide' 
        });
    }

    try {
        const profile = await new Promise(r => 
            db.get('SELECT * FROM reseller_profiles WHERE user_id = ?', [userId], (e, row) => r(row))
        );

        if (!profile) {
            return res.status(403).json({ 
                success: false, 
                error: 'Profil revendeur requis' 
            });
        }

        const user = await new Promise(r => 
            db.get('SELECT coins FROM users WHERE id = ?', [userId], (e, row) => r(row))
        );

        const planPrice = PLAN_COINS_PRICES[plan_key];

        // Calcul de la remise selon les paliers
        let discountRate = 0;
        for (const tier of RESELLER_CONFIG.bulk_discount_tiers) {
            if (quantity >= tier.min_quantity) discountRate = tier.discount;
        }

        const unitPrice = Math.floor(planPrice * (1 - discountRate / 100));
        const totalPrice = unitPrice * quantity;
        const coinsToCredit = planPrice * quantity; // Valeur de revente

        if (user.coins < totalPrice) {
            return res.status(400).json({ 
                success: false, 
                error: `Coins insuffisants. Il vous faut ${totalPrice} coins` 
            });
        }

        db.serialize(() => {
            db.run('BEGIN TRANSACTION');

            db.run('UPDATE users SET coins = coins - ? WHERE id = ?', [totalPrice, userId]);

            db.run(
                `INSERT INTO bulk_purchases 
                 (reseller_id, plan_key, quantity, unit_price, total_price, discount_applied, coins_credited) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [userId, plan_key, quantity, unitPrice, totalPrice, discountRate, coinsToCredit],
                function(err) {
                    if (err) {
                        db.run('ROLLBACK');
                        console.error('Erreur bulk purchase:', err);
                        return res.status(500).json({ success: false, error: 'Erreur enregistrement' });
                    }

                    db.run('COMMIT', (err) => {
                        if (err) {
                            db.run('ROLLBACK');
                            return res.status(500).json({ success: false, error: 'Erreur validation' });
                        }

                        logSystem('financial', 'Bulk purchase', {
                            reseller_id: userId,
                            plan_key,
                            quantity,
                            total_price: totalPrice,
                            discount: discountRate
                        });

                        res.json({
                            success: true,
                            message: 'Achat en gros effectué !',
                            quantity,
                            unit_price: unitPrice,
                            discount_rate: discountRate,
                            total_price: totalPrice,
                            coins_credited: coinsToCredit,
                            new_balance: user.coins - totalPrice
                        });
                    });
                }
            );
        });

    } catch (error) {
        console.error('Erreur bulk purchase:', error);
        res.status(500).json({ success: false, error: 'Erreur serveur' });
    }
});

// 4.6 — Créer un code promo revendeur
app.post('/api/reseller/promo-codes/create', authenticateToken, requireAdmin, async (req, res) => {
    const { server_type, duration_hours, max_uses, expires_at } = req.body;
    const userId = req.user.userId;

    if (!server_type || !duration_hours || !max_uses) {
        return res.status(400).json({ 
            success: false, 
            error: 'Type de serveur, durée et nombre d\'utilisations requis' 
        });
    }

    try {
        const profile = await new Promise(r => 
            db.get('SELECT * FROM reseller_profiles WHERE user_id = ?', [userId], (e, row) => r(row))
        );

        if (!profile) {
            return res.status(403).json({ 
                success: false, 
                error: 'Profil revendeur requis' 
            });
        }

        // Vérifier le nombre de codes promo actifs
        const promoCount = await new Promise(r => 
            db.get(
                'SELECT COUNT(*) as total FROM reseller_promo_codes WHERE reseller_id = ? AND is_active = 1',
                [userId], (e, row) => r(row?.total || 0)
            )
        );

        if (promoCount >= RESELLER_CONFIG.max_promo_codes_per_reseller) {
            return res.status(400).json({ 
                success: false, 
                error: `Nombre maximum de codes promo atteint (${RESELLER_CONFIG.max_promo_codes_per_reseller})` 
            });
        }

        // Calculer le coût en coins pour ce code
        const planPrice = PLAN_COINS_PRICES[server_type];
        const coinsCost = planPrice * max_uses;

        const user = await new Promise(r => 
            db.get('SELECT coins FROM users WHERE id = ?', [userId], (e, row) => r(row))
        );

        if (user.coins < coinsCost) {
            return res.status(400).json({ 
                success: false, 
                error: `Coins insuffisants. Il vous faut ${coinsCost} coins` 
            });
        }

        const code = 'RES_' + generatePromoCode(server_type.toUpperCase());

        db.serialize(() => {
            db.run('BEGIN TRANSACTION');

            db.run('UPDATE users SET coins = coins - ? WHERE id = ?', [coinsCost, userId]);

            db.run(
                `INSERT INTO reseller_promo_codes 
                 (reseller_id, code, server_type, duration_hours, max_uses, coins_cost, expires_at) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [userId, code, server_type, duration_hours, max_uses, coinsCost, expires_at || null],
                function(err) {
                    if (err) {
                        db.run('ROLLBACK');
                        console.error('Erreur création code promo:', err);
                        return res.status(500).json({ success: false, error: 'Erreur création code' });
                    }

                    db.run('COMMIT', (err) => {
                        if (err) {
                            db.run('ROLLBACK');
                            return res.status(500).json({ success: false, error: 'Erreur validation' });
                        }

                        res.json({
                            success: true,
                            message: 'Code promo créé !',
                            code,
                            coins_reserved: coinsCost,
                            details: {
                                server_type,
                                duration_hours,
                                max_uses,
                                expires_at
                            }
                        });
                    });
                }
            );
        });

    } catch (error) {
        console.error('Erreur création code promo:', error);
        res.status(500).json({ success: false, error: 'Erreur serveur' });
    }
});

// 4.7 — Liste des codes promo du revendeur
app.get('/api/reseller/promo-codes', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.user.userId;

    db.all(
        `SELECT rpc.*, 
                (SELECT COUNT(*) FROM promo_code_uses pcu JOIN promo_codes pc ON pcu.promo_code_id = pc.id WHERE pc.code = rpc.code) as uses
         FROM reseller_promo_codes rpc
         WHERE rpc.reseller_id = ?
         ORDER BY rpc.created_at DESC`,
        [userId],
        (err, codes) => {
            if (err) {
                console.error('Erreur récupération codes promo:', err);
                return res.status(500).json({ success: false, error: 'Erreur récupération' });
            }
            res.json({ success: true, promo_codes: codes || [] });
        }
    );
});

// 4.8 — Historique des commissions
app.get('/api/reseller/commissions', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.user.userId;
    const { limit = 20, offset = 0 } = req.query;

    db.all(
        `SELECT cl.*, u.username as client_username
         FROM commission_logs cl
         JOIN users u ON cl.client_id = u.id
         WHERE cl.reseller_id = ?
         ORDER BY cl.created_at DESC
         LIMIT ? OFFSET ?`,
        [userId, parseInt(limit), parseInt(offset)],
        (err, commissions) => {
            if (err) {
                console.error('Erreur récupération commissions:', err);
                return res.status(500).json({ success: false, error: 'Erreur récupération' });
            }

            db.get(
                'SELECT SUM(amount) as total FROM commission_logs WHERE reseller_id = ?',
                [userId],
                (err, total) => {
                    res.json({
                        success: true,
                        commissions: commissions || [],
                        total: total?.total || 0,
                        limit: parseInt(limit),
                        offset: parseInt(offset)
                    });
                }
            );
        }
    );
});

// 4.9 — Demande de retrait
app.post('/api/reseller/withdraw', authenticateToken, requireAdmin, async (req, res) => {
    const { amount, payment_method, payment_details } = req.body;
    const userId = req.user.userId;

    if (!amount || amount < RESELLER_CONFIG.min_withdrawal_amount) {
        return res.status(400).json({ 
            success: false, 
            error: `Montant minimum de retrait: ${RESELLER_CONFIG.min_withdrawal_amount} XOF` 
        });
    }

    if (!payment_method || !payment_details) {
        return res.status(400).json({ 
            success: false, 
            error: 'Méthode et détails de paiement requis' 
        });
    }

    try {
        const profile = await new Promise(r => 
            db.get('SELECT commission_balance FROM reseller_profiles WHERE user_id = ?', [userId], (e, row) => r(row))
        );

        if (!profile || profile.commission_balance < amount) {
            return res.status(400).json({ 
                success: false, 
                error: 'Solde de commission insuffisant' 
            });
        }

        db.serialize(() => {
            db.run('BEGIN TRANSACTION');

            // Geler le montant (soustraire du solde)
            db.run(
                'UPDATE reseller_profiles SET commission_balance = commission_balance - ? WHERE user_id = ?',
                [amount, userId]
            );

            db.run(
                `INSERT INTO withdrawal_requests 
                 (reseller_id, amount, payment_method, payment_details, status) 
                 VALUES (?, ?, ?, ?, 'pending')`,
                [userId, amount, payment_method, JSON.stringify(payment_details)],
                function(err) {
                    if (err) {
                        db.run('ROLLBACK');
                        console.error('Erreur création demande retrait:', err);
                        return res.status(500).json({ success: false, error: 'Erreur création demande' });
                    }

                    db.run('COMMIT', (err) => {
                        if (err) {
                            db.run('ROLLBACK');
                            return res.status(500).json({ success: false, error: 'Erreur validation' });
                        }

                        logSystem('financial', 'Withdrawal requested', {
                            reseller_id: userId,
                            amount,
                            payment_method
                        });

                        // Notifier les superadmins via WebSocket
                        if (global.sendNotification) {
                            // À implémenter : notification aux superadmins
                        }

                        res.json({
                            success: true,
                            message: 'Demande de retrait enregistrée',
                            withdrawal_id: this.lastID,
                            amount,
                            status: 'pending',
                            estimated_processing: `${RESELLER_CONFIG.withdrawal_processing_days} jours`
                        });
                    });
                }
            );
        });

    } catch (error) {
        console.error('Erreur demande retrait:', error);
        res.status(500).json({ success: false, error: 'Erreur serveur' });
    }
});

// 4.10 — Historique des retraits
app.get('/api/reseller/withdrawals', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.user.userId;

    db.all(
        `SELECT * FROM withdrawal_requests 
         WHERE reseller_id = ? 
         ORDER BY created_at DESC`,
        [userId],
        (err, withdrawals) => {
            if (err) {
                console.error('Erreur récupération retraits:', err);
                return res.status(500).json({ success: false, error: 'Erreur récupération' });
            }
            res.json({ success: true, withdrawals: withdrawals || [] });
        }
    );
});

// 4.11 — Envoyer une notification à un client
app.post('/api/reseller/clients/:clientId/notify', authenticateToken, requireAdmin, async (req, res) => {
    const { clientId } = req.params;
    const { title, message, type = 'info' } = req.body;
    const resellerId = req.user.userId;

    if (!title || !message) {
        return res.status(400).json({ 
            success: false, 
            error: 'Titre et message requis' 
        });
    }

    try {
        // Vérifier que le client appartient au revendeur
        const ownership = await new Promise(r => 
            db.get(
                'SELECT * FROM reseller_clients WHERE reseller_id = ? AND client_id = ?',
                [resellerId, clientId], (e, row) => r(row)
            )
        );

        if (!ownership) {
            return res.status(403).json({ 
                success: false, 
                error: 'Ce client ne vous appartient pas' 
            });
        }

        // Enregistrer la notification
        db.run(
            `INSERT INTO reseller_notifications 
             (reseller_id, type, title, message, metadata) 
             VALUES (?, ?, ?, ?, ?)`,
            [resellerId, type, title, message, JSON.stringify({ client_id: clientId })],
            function(err) {
                if (err) {
                    console.error('Erreur enregistrement notification:', err);
                    return res.status(500).json({ success: false, error: 'Erreur enregistrement' });
                }

                // Envoyer via WebSocket si le client est connecté
                if (global.sendNotification) {
                    global.sendNotification(clientId, {
                        title,
                        message,
                        type,
                        from_reseller: true
                    });
                }

                res.json({
                    success: true,
                    message: 'Notification envoyée au client'
                });
            }
        );

    } catch (error) {
        console.error('Erreur envoi notification:', error);
        res.status(500).json({ success: false, error: 'Erreur serveur' });
    }
});

// 4.12 — Serveurs des clients du revendeur
app.get('/api/reseller/clients/:clientId/servers', authenticateToken, requireAdmin, async (req, res) => {
    const { clientId } = req.params;
    const resellerId = req.user.userId;

    try {
        // Vérifier que le client appartient au revendeur
        const ownership = await new Promise(r => 
            db.get(
                'SELECT * FROM reseller_clients WHERE reseller_id = ? AND client_id = ?',
                [resellerId, clientId], (e, row) => r(row)
            )
        );

        if (!ownership) {
            return res.status(403).json({ 
                success: false, 
                error: 'Ce client ne vous appartient pas' 
            });
        }

        const servers = await new Promise(r => 
            db.all(
                'SELECT * FROM servers WHERE user_id = ? ORDER BY created_at DESC',
                [clientId], (e, rows) => r(rows || [])
            )
        );

        res.json({
            success: true,
            servers
        });

    } catch (error) {
        console.error('Erreur récupération serveurs client:', error);
        res.status(500).json({ success: false, error: 'Erreur serveur' });
    }
});

// 4.13 — Statistiques mensuelles
app.get('/api/reseller/stats/monthly', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.user.userId;
    const { year, month } = req.query;

    const startDate = new Date(year || new Date().getFullYear(), (month || new Date().getMonth()) - 1, 1);
    const endDate = new Date(startDate);
    endDate.setMonth(endDate.getMonth() + 1);

    Promise.all([
        new Promise(r => db.get(
            `SELECT SUM(amount) as revenue FROM commission_logs 
             WHERE reseller_id = ? AND created_at >= ? AND created_at < ?`,
            [userId, startDate.toISOString(), endDate.toISOString()], (e, row) => r(row?.revenue || 0)
        )),
        new Promise(r => db.get(
            `SELECT COUNT(*) as sales FROM commission_logs 
             WHERE reseller_id = ? AND created_at >= ? AND created_at < ?`,
            [userId, startDate.toISOString(), endDate.toISOString()], (e, row) => r(row?.sales || 0)
        )),
        new Promise(r => db.get(
            `SELECT COUNT(*) as new_clients FROM reseller_clients 
             WHERE reseller_id = ? AND created_at >= ? AND created_at < ?`,
            [userId, startDate.toISOString(), endDate.toISOString()], (e, row) => r(row?.new_clients || 0)
        ))
    ]).then(([revenue, sales_count, new_clients]) => {
        res.json({
            success: true,
            stats: {
                revenue,
                sales_count,
                new_clients
            }
        });
    }).catch(error => {
        console.error('Erreur stats mensuelles:', error);
        res.status(500).json({ success: false, error: 'Erreur serveur' });
    });
});

// 4.14 — Lien d'affiliation et QR Code
app.get('/api/reseller/affiliate-info', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.user.userId;

    db.get(
        'SELECT affiliate_code FROM reseller_profiles WHERE user_id = ?',
        [userId],
        (err, profile) => {
            if (err || !profile) {
                return res.status(404).json({ 
                    success: false, 
                    error: 'Profil revendeur non trouvé' 
                });
            }

            db.get(
                `SELECT COUNT(*) as conversions, 
                        SUM(CASE WHEN rc.acquisition_source = 'affiliate' THEN 1 ELSE 0 END) as affiliate_conversions,
                        (SELECT SUM(base_amount) FROM commission_logs WHERE reseller_id = ?) as earnings
                 FROM reseller_clients rc
                 WHERE rc.reseller_id = ?`,
                [userId, userId],
                (err, stats) => {
                    const affiliateUrl = `${WEB_CONFIG.SITE_URL}/register?aff=${profile.affiliate_code}`;
                    const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${encodeURIComponent(affiliateUrl)}`;

                    res.json({
                        success: true,
                        affiliate_code: profile.affiliate_code,
                        affiliate_url: affiliateUrl,
                        qr_code_url: qrCodeUrl,
                        total_conversions: stats?.conversions || 0,
                        affiliate_conversions: stats?.affiliate_conversions || 0,
                        earnings_from_affiliate: stats?.earnings || 0
                    });
                }
            );
        }
    );
});

// =============================================
// ROUTES SUPERADMIN (/api/superadmin)
// =============================================

// 5.0 — Stats globales dashboard superadmin
app.get('/api/superadmin/stats', authenticateToken, requireSuperAdmin, (req, res) => {
    const stats = {};
    Promise.all([
        new Promise(r => db.get('SELECT COUNT(*) as c FROM users', [], (e, row) => { stats.totalUsers = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM users WHERE is_verified = 1', [], (e, row) => { stats.verifiedUsers = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM users WHERE is_banned = 1', [], (e, row) => { stats.bannedUsers = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM servers', [], (e, row) => { stats.totalServers = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM servers WHERE is_active = 1', [], (e, row) => { stats.activeServers = row?.c || 0; r(); })),
        new Promise(r => db.all('SELECT server_type, COUNT(*) as count FROM servers GROUP BY server_type', [], (e, rows) => { stats.serversByType = rows || []; r(); })),
        new Promise(r => db.get('SELECT SUM(amount) as c FROM transactions WHERE status = "completed"', [], (e, row) => { stats.totalRevenue = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM promo_codes WHERE is_active = 1', [], (e, row) => { stats.activePromoCodes = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM deployments', [], (e, row) => { stats.totalDeployments = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM deployments WHERE status = "running"', [], (e, row) => { stats.runningDeployments = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM deployments WHERE status = "failed"', [], (e, row) => { stats.failedDeployments = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM deployments WHERE method = "github"', [], (e, row) => { stats.githubDeployments = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM deployments WHERE method = "zip"', [], (e, row) => { stats.zipDeployments = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM deployments WHERE method = "template"', [], (e, row) => { stats.templateDeployments = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM github_connections', [], (e, row) => { stats.githubConnections = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM reseller_profiles WHERE active = 1', [], (e, row) => { stats.activeResellers = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM withdrawal_requests WHERE status = "pending"', [], (e, row) => { stats.pendingWithdrawals = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT SUM(amount) as c FROM withdrawal_requests WHERE status = "pending"', [], (e, row) => { stats.pendingWithdrawalAmount = row?.c || 0; r(); }))
    ]).then(() => res.json({ success: true, stats }))
      .catch(e => res.status(500).json({ success: false, error: e.message }));
});

// 5.1 — Liste des revendeurs
app.get('/api/superadmin/resellers', authenticateToken, requireSuperAdmin, (req, res) => {
    const { limit = 20, offset = 0 } = req.query;

    db.all(
        `SELECT u.id, u.username, u.email, u.created_at,
                rp.business_name, rp.commission_rate, rp.commission_balance, rp.total_earned, rp.total_withdrawn,
                rp.contract_accepted, rp.active,
                (SELECT COUNT(*) FROM reseller_clients WHERE reseller_id = u.id) as clients_count,
                (SELECT COUNT(*) FROM withdrawal_requests WHERE reseller_id = u.id AND status = 'pending') as pending_withdrawals,
                (SELECT SUM(amount) FROM withdrawal_requests WHERE reseller_id = u.id AND status = 'approved') as total_withdrawn
         FROM users u
         JOIN reseller_profiles rp ON u.id = rp.user_id
         WHERE u.role = 'admin'
         ORDER BY rp.created_at DESC
         LIMIT ? OFFSET ?`,
        [parseInt(limit), parseInt(offset)],
        (err, resellers) => {
            if (err) {
                console.error('Erreur récupération revendeurs:', err);
                return res.status(500).json({ success: false, error: 'Erreur récupération' });
            }

            db.get(
                'SELECT COUNT(*) as total FROM users WHERE role = "admin"',
                [],
                (err, count) => {
                    res.json({
                        success: true,
                        resellers: resellers || [],
                        total: count?.total || 0,
                        limit: parseInt(limit),
                        offset: parseInt(offset)
                    });
                }
            );
        }
    );
});

// 5.2 — Approuver ou rejeter un retrait
app.post('/api/superadmin/withdrawals/:withdrawalId/process', authenticateToken, requireSuperAdmin, async (req, res) => {
    const { withdrawalId } = req.params;
    const { action, reference, admin_note } = req.body;
    const adminId = req.user.userId;

    if (!action || !['approved', 'rejected'].includes(action)) {
        return res.status(400).json({ 
            success: false, 
            error: 'Action invalide (approved ou rejected requis)' 
        });
    }

    try {
        const withdrawal = await new Promise(r => 
            db.get('SELECT * FROM withdrawal_requests WHERE id = ?', [withdrawalId], (e, row) => r(row))
        );

        if (!withdrawal) {
            return res.status(404).json({ 
                success: false, 
                error: 'Demande de retrait non trouvée' 
            });
        }

        if (withdrawal.status !== 'pending') {
            return res.status(400).json({ 
                success: false, 
                error: `Cette demande a déjà été traitée (statut: ${withdrawal.status})` 
            });
        }

        db.serialize(() => {
            db.run('BEGIN TRANSACTION');

            if (action === 'approved') {
                // Approuver le retrait
                db.run(
                    `UPDATE withdrawal_requests 
                     SET status = 'approved', processed_by = ?, processed_at = CURRENT_TIMESTAMP, 
                         reference = ?, admin_note = ?
                     WHERE id = ?`,
                    [adminId, reference, admin_note, withdrawalId]
                );

                // Mettre à jour le total_withdrawn du revendeur
                db.run(
                    'UPDATE reseller_profiles SET total_withdrawn = total_withdrawn + ? WHERE user_id = ?',
                    [withdrawal.amount, withdrawal.reseller_id]
                );

            } else {
                // Rejeter le retrait : remettre le montant dans commission_balance
                db.run(
                    `UPDATE withdrawal_requests 
                     SET status = 'rejected', processed_by = ?, processed_at = CURRENT_TIMESTAMP, 
                         admin_note = ?
                     WHERE id = ?`,
                    [adminId, admin_note, withdrawalId]
                );

                db.run(
                    'UPDATE reseller_profiles SET commission_balance = commission_balance + ? WHERE user_id = ?',
                    [withdrawal.amount, withdrawal.reseller_id]
                );
            }

            db.run('COMMIT', (err) => {
                if (err) {
                    db.run('ROLLBACK');
                    console.error('Erreur validation traitement retrait:', err);
                    return res.status(500).json({ success: false, error: 'Erreur validation' });
                }

                logSystem('financial', `Withdrawal ${action}`, {
                    withdrawal_id: withdrawalId,
                    reseller_id: withdrawal.reseller_id,
                    amount: withdrawal.amount,
                    processed_by: adminId
                });

                // Notifier le revendeur
                if (global.sendNotification) {
                    global.sendNotification(withdrawal.reseller_id, {
                        title: action === 'approved' ? '✅ Retrait approuvé' : '❌ Retrait rejeté',
                        message: action === 'approved' 
                            ? `Votre retrait de ${withdrawal.amount} XOF a été approuvé. Réf: ${reference}`
                            : `Votre retrait de ${withdrawal.amount} XOF a été rejeté. Motif: ${admin_note || 'Non spécifié'}`,
                        type: action === 'approved' ? 'success' : 'error'
                    });
                }

                res.json({
                    success: true,
                    action,
                    reference,
                    message: action === 'approved' ? 'Retrait approuvé' : 'Retrait rejeté'
                });
            });
        });

    } catch (error) {
        console.error('Erreur traitement retrait:', error);
        res.status(500).json({ success: false, error: 'Erreur serveur' });
    }
});

// 5.3 — Liste des retraits en attente
app.get('/api/superadmin/withdrawals', authenticateToken, requireSuperAdmin, (req, res) => {
    const { status = 'pending', limit = 50, offset = 0 } = req.query;

    db.all(
        `SELECT wr.*, u.username as reseller_username, rp.business_name
         FROM withdrawal_requests wr
         JOIN users u ON wr.reseller_id = u.id
         JOIN reseller_profiles rp ON u.id = rp.user_id
         WHERE wr.status = ?
         ORDER BY wr.created_at ASC
         LIMIT ? OFFSET ?`,
        [status, parseInt(limit), parseInt(offset)],
        (err, withdrawals) => {
            if (err) {
                console.error('Erreur récupération retraits:', err);
                return res.status(500).json({ success: false, error: 'Erreur récupération' });
            }

            db.get(
                'SELECT COUNT(*) as total, SUM(amount) as total_amount FROM withdrawal_requests WHERE status = ?',
                [status],
                (err, totals) => {
                    res.json({
                        success: true,
                        withdrawals: withdrawals || [],
                        total: totals?.total || 0,
                        total_amount: totals?.total_amount || 0,
                        limit: parseInt(limit),
                        offset: parseInt(offset)
                    });
                }
            );
        }
    );
});

// 5.4 — Modifier le taux de commission d'un revendeur
app.post('/api/superadmin/resellers/:resellerId/commission-rate', authenticateToken, requireSuperAdmin, (req, res) => {
    const { resellerId } = req.params;
    const { rate } = req.body;
    const adminId = req.user.userId;

    if (!rate || rate < 0 || rate > 100) {
        return res.status(400).json({ 
            success: false, 
            error: 'Taux de commission invalide (0-100)' 
        });
    }

    db.run(
        'UPDATE reseller_profiles SET commission_rate = ? WHERE user_id = ?',
        [rate, resellerId],
        function(err) {
            if (err) {
                console.error('Erreur modification taux commission:', err);
                return res.status(500).json({ success: false, error: 'Erreur modification' });
            }

            logAdminAction(adminId, 'modify_commission_rate', 'reseller', resellerId, `Taux modifié à ${rate}%`);

            res.json({
                success: true,
                message: `Taux de commission modifié à ${rate}%`
            });
        }
    );
});

// 5.5 — Rapport financier global
app.get('/api/superadmin/financial-report', authenticateToken, requireSuperAdmin, (req, res) => {
    const { period = 'monthly' } = req.query;

    const now = new Date();
    let startDate;

    if (period === 'monthly') {
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
    } else if (period === 'yearly') {
        startDate = new Date(now.getFullYear(), 0, 1);
    } else if (period === 'all') {
        startDate = new Date(0);
    } else {
        return res.status(400).json({ success: false, error: 'Période invalide' });
    }

    Promise.all([
        new Promise(r => db.get(
            `SELECT SUM(amount) as total_commissions FROM commission_logs WHERE created_at >= ?`,
            [startDate.toISOString()], (e, row) => r(row?.total_commissions || 0)
        )),
        new Promise(r => db.get(
            `SELECT SUM(amount) as total_withdrawn FROM withdrawal_requests WHERE status = 'approved' AND created_at >= ?`,
            [startDate.toISOString()], (e, row) => r(row?.total_withdrawn || 0)
        )),
        new Promise(r => db.get(
            `SELECT SUM(amount) as pending_withdrawals FROM withdrawal_requests WHERE status = 'pending'`,
            [], (e, row) => r(row?.pending_withdrawals || 0)
        )),
        new Promise(r => db.get(
            `SELECT SUM(coins_credited) as total_bulk_purchases FROM bulk_purchases WHERE created_at >= ?`,
            [startDate.toISOString()], (e, row) => r(row?.total_bulk_purchases || 0)
        )),
        new Promise(r => db.get(
            `SELECT SUM(amount) as platform_revenue FROM transactions WHERE status = 'completed' AND created_at >= ?`,
            [startDate.toISOString()], (e, row) => r(row?.platform_revenue || 0)
        ))
    ]).then(([total_commissions, total_withdrawn, pending_withdrawals, total_bulk_purchases, platform_revenue]) => {
        const net_platform_revenue = platform_revenue - total_commissions;

        res.json({
            success: true,
            report: {
                period,
                start_date: startDate.toISOString(),
                end_date: now.toISOString(),
                total_commissions,
                total_withdrawn,
                pending_withdrawals,
                total_bulk_purchases,
                platform_revenue,
                net_platform_revenue
            }
        });
    }).catch(error => {
        console.error('Erreur rapport financier:', error);
        res.status(500).json({ success: false, error: 'Erreur serveur' });
    });
});

// 5.6 — Désactiver un revendeur
app.post('/api/superadmin/resellers/:resellerId/deactivate', authenticateToken, requireSuperAdmin, (req, res) => {
    const { resellerId } = req.params;
    const adminId = req.user.userId;

    db.serialize(() => {
        db.run('UPDATE users SET role = "user" WHERE id = ?', [resellerId]);
        db.run('UPDATE reseller_profiles SET active = 0 WHERE user_id = ?', [resellerId]);

        logAdminAction(adminId, 'deactivate_reseller', 'reseller', resellerId, 'Désactivation revendeur');

        res.json({
            success: true,
            message: 'Revendeur désactivé'
        });
    });
});

// 5.7 — Rapport par revendeur
app.get('/api/superadmin/resellers/:resellerId/report', authenticateToken, requireSuperAdmin, (req, res) => {
    const { resellerId } = req.params;

    Promise.all([
        new Promise(r => db.get('SELECT * FROM reseller_profiles WHERE user_id = ?', [resellerId], (e, row) => r(row))),
        new Promise(r => db.get('SELECT COUNT(*) as clients FROM reseller_clients WHERE reseller_id = ?', [resellerId], (e, row) => r(row?.clients || 0))),
        new Promise(r => db.get('SELECT SUM(amount) as total_commissions FROM commission_logs WHERE reseller_id = ?', [resellerId], (e, row) => r(row?.total_commissions || 0))),
        new Promise(r => db.get('SELECT SUM(amount) as total_withdrawn FROM withdrawal_requests WHERE reseller_id = ? AND status = "approved"', [resellerId], (e, row) => r(row?.total_withdrawn || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as promo_codes, SUM(coins_cost) as promo_codes_cost FROM reseller_promo_codes WHERE reseller_id = ?', [resellerId], (e, row) => r(row))),
        new Promise(r => db.get('SELECT COUNT(*) as bulk_purchases, SUM(total_price) as bulk_total FROM bulk_purchases WHERE reseller_id = ?', [resellerId], (e, row) => r(row))),
        new Promise(r => db.all('SELECT * FROM withdrawal_requests WHERE reseller_id = ? ORDER BY created_at DESC', [resellerId], (e, rows) => r(rows || []))),
        new Promise(r => db.all('SELECT * FROM commission_logs WHERE reseller_id = ? ORDER BY created_at DESC LIMIT 20', [resellerId], (e, rows) => r(rows || [])))
    ]).then(([profile, clients, total_commissions, total_withdrawn, promoStats, bulkStats, withdrawals, commissions]) => {
        res.json({
            success: true,
            report: {
                profile,
                clients_count: clients,
                total_commissions,
                total_withdrawn,
                promo_codes: {
                    count: promoStats?.promo_codes || 0,
                    total_cost: promoStats?.promo_codes_cost || 0
                },
                bulk_purchases: {
                    count: bulkStats?.bulk_purchases || 0,
                    total_spent: bulkStats?.bulk_total || 0
                },
                recent_withdrawals: withdrawals,
                recent_commissions: commissions
            }
        });
    }).catch(error => {
        console.error('Erreur rapport revendeur:', error);
        res.status(500).json({ success: false, error: 'Erreur serveur' });
    });
});

// =============================================
// ROUTES DE GESTION DES API KEYS
// =============================================

// Liste toutes ses API Keys
app.get('/api/api-keys', authenticateToken, (req, res) => {
    db.all(
        `SELECT id, name, key, api_key_type, webhook_url, telegram_chat_id, whatsapp_number, description,
                requests_per_day, requests_today, last_used, is_active, expires_at, created_at
         FROM api_keys
         WHERE user_id = ?
         ORDER BY created_at DESC`,
        [req.user.userId],
        (err, keys) => {
            if (err) {
                console.error('Erreur récupération clés API:', err);
                return res.status(500).json({ success: false, error: 'Erreur récupération' });
            }
            res.json({ success: true, api_keys: keys || [] });
        }
    );
});

// Créer une nouvelle API Key typée
app.post('/api/api-keys/create', authenticateToken, (req, res) => {
    const { name, description, expires_in_days, allowed_ips, telegram_chat_id, whatsapp_number, webhook_url } = req.body;
    const userId = req.user.userId;

    db.get('SELECT username, role FROM users WHERE id = ?', [userId], (err, user) => {
        if (err || !user) {
            return res.status(404).json({ success: false, error: 'Utilisateur non trouvé' });
        }

        // Déterminer le type de clé selon le rôle
        let keyType;
        if (user.role === 'superadmin') keyType = 'superadmin';
        else if (user.role === 'admin') keyType = 'reseller';
        else keyType = 'user';

        const apiKey = generateTypedApiKey(keyType, user.username);

        let expiresAt = null;
        if (expires_in_days) {
            expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + expires_in_days);
        }

        db.run(
            `INSERT INTO api_keys 
             (user_id, key, name, api_key_type, telegram_chat_id, whatsapp_number, webhook_url, description, allowed_ips, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                userId, apiKey, name, keyType, telegram_chat_id, whatsapp_number, webhook_url, description,
                JSON.stringify(allowed_ips || []), expiresAt?.toISOString()
            ],
            function(err) {
                if (err) {
                    console.error('Erreur création clé API:', err);
                    return res.status(500).json({ success: false, error: 'Erreur création clé' });
                }

                logSystem('api', 'API Key créée', { user_id: userId, key_type: keyType });

                res.json({
                    success: true,
                    message: 'Clé API créée',
                    api_key: {
                        id: this.lastID,
                        key: apiKey,
                        type: keyType,
                        name
                    }
                });
            }
        );
    });
});

// Révoquer une clé (soft delete)
app.delete('/api/api-keys/:keyId', authenticateToken, (req, res) => {
    const { keyId } = req.params;

    db.run(
        'UPDATE api_keys SET is_active = 0 WHERE id = ? AND user_id = ?',
        [keyId, req.user.userId],
        function(err) {
            if (err) {
                console.error('Erreur révocation clé:', err);
                return res.status(500).json({ success: false, error: 'Erreur révocation' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ success: false, error: 'Clé non trouvée' });
            }
            res.json({ success: true, message: 'Clé API révoquée' });
        }
    );
});

// Stats d'utilisation d'une clé
app.get('/api/api-keys/:keyId/usage', authenticateToken, (req, res) => {
    const { keyId } = req.params;

    db.get(
        `SELECT ak.*,
                (SELECT COUNT(*) FROM api_usage_logs WHERE api_key_id = ak.id) as total_requests,
                (SELECT COUNT(*) FROM api_usage_logs WHERE api_key_id = ak.id AND created_at > datetime('now', '-24 hours')) as requests_24h,
                (SELECT MAX(created_at) FROM api_usage_logs WHERE api_key_id = ak.id) as last_request
         FROM api_keys ak
         WHERE ak.id = ? AND ak.user_id = ?`,
        [keyId, req.user.userId],
        (err, key) => {
            if (err || !key) {
                return res.status(404).json({ success: false, error: 'Clé non trouvée' });
            }

            res.json({
                success: true,
                usage: {
                    total_requests: key.total_requests || 0,
                    requests_24h: key.requests_24h || 0,
                    requests_today: key.requests_today,
                    requests_per_day: key.requests_per_day,
                    last_used: key.last_used,
                    last_ip: key.last_ip,
                    last_request: key.last_request
                }
            });
        }
    );
});

// Modifier une clé
app.put('/api/api-keys/:keyId', authenticateToken, (req, res) => {
    const { keyId } = req.params;
    const { name, allowed_ips, telegram_chat_id, whatsapp_number, webhook_url, description } = req.body;

    db.run(
        `UPDATE api_keys 
         SET name = COALESCE(?, name),
             allowed_ips = COALESCE(?, allowed_ips),
             telegram_chat_id = COALESCE(?, telegram_chat_id),
             whatsapp_number = COALESCE(?, whatsapp_number),
             webhook_url = COALESCE(?, webhook_url),
             description = COALESCE(?, description)
         WHERE id = ? AND user_id = ?`,
        [name, allowed_ips ? JSON.stringify(allowed_ips) : null, telegram_chat_id, whatsapp_number, webhook_url, description, keyId, req.user.userId],
        function(err) {
            if (err) {
                console.error('Erreur modification clé:', err);
                return res.status(500).json({ success: false, error: 'Erreur modification' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ success: false, error: 'Clé non trouvée' });
            }
            res.json({ success: true, message: 'Clé API mise à jour' });
        }
    );
});

// =============================================
// ROUTES API EXTERNES POUR BOTS (/v1)
// =============================================

const externalApi = express.Router();

// Routes USER
externalApi.get('/me', authenticateApiKey, requirePermission('can_view_own_stats'), (req, res) => {
    db.get(
        `SELECT u.id, u.username, u.email, u.coins, u.role, u.level, u.current_plan,
                uc.balance as credits
         FROM users u
         LEFT JOIN user_credits uc ON u.id = uc.user_id
         WHERE u.id = ?`,
        [req.user.userId],
        (err, user) => {
            if (err || !user) {
                return res.status(404).json({ success: false, error: 'Utilisateur non trouvé' });
            }
            res.json({ success: true, user });
        }
    );
});

externalApi.get('/servers', authenticateApiKey, requirePermission('can_view_own_servers'), (req, res) => {
    db.all(
        `SELECT id, server_name, server_type, server_status, expires_at
         FROM servers WHERE user_id = ? AND is_active = 1`,
        [req.user.userId],
        (err, servers) => {
            if (err) {
                return res.status(500).json({ success: false, error: 'Erreur récupération' });
            }
            res.json({ success: true, servers });
        }
    );
});

externalApi.post('/servers/:id/power', authenticateApiKey, requirePermission('can_power_own_servers'), async (req, res) => {
    const { action } = req.body;
    
    const server = await getServerByIdAndUser(req.params.id, req.user.userId);
    if (!server) return res.status(404).json({ success: false, error: 'Serveur non trouvé' });
    
    await sendPowerAction(server.server_identifier, action);
    res.json({ success: true, message: `Action ${action} envoyée` });
});

externalApi.get('/servers/:id/stats', authenticateApiKey, requirePermission('can_view_own_stats'), async (req, res) => {
    const server = await getServerByIdAndUser(req.params.id, req.user.userId);
    if (!server) return res.status(404).json({ success: false, error: 'Serveur non trouvé' });

    const status = await getServerPowerStatus(server.server_identifier);
    res.json({ success: true, stats: status });
});

externalApi.get('/transactions', authenticateApiKey, requirePermission('can_view_own_transactions'), (req, res) => {
    db.all(
        `SELECT id, plan_key, amount, status, created_at
         FROM transactions
         WHERE user_id = ?
         ORDER BY created_at DESC
         LIMIT 50`,
        [req.user.userId],
        (err, transactions) => {
            res.json({ success: true, transactions });
        }
    );
});

externalApi.get('/daily-reward/status', authenticateApiKey, requirePermission('can_claim_daily_reward'), (req, res) => {
    db.get(
        'SELECT last_daily_login, daily_login_streak FROM users WHERE id = ?',
        [req.user.userId],
        (err, user) => {
            const today = getCurrentDate();
            const canClaim = user?.last_daily_login !== today;
            res.json({ success: true, can_claim: canClaim, current_streak: user?.daily_login_streak || 0 });
        }
    );
});

externalApi.post('/daily-reward/claim', authenticateApiKey, requirePermission('can_claim_daily_reward'), (req, res) => {
    const userId = req.user.userId;
    const today = getCurrentDate();

    db.get('SELECT last_daily_login, daily_login_streak FROM users WHERE id = ?', [userId], (err, user) => {
        if (user.last_daily_login === today) {
            return res.status(400).json({ success: false, error: 'Déjà réclamé aujourd\'hui' });
        }

        let coinsReward = 5;
        let streak = 1;

        const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
        if (user.last_daily_login === yesterday) {
            streak = (user.daily_login_streak || 0) + 1;
            coinsReward = 7;
        }

        db.run(
            'UPDATE users SET daily_login_streak = ?, last_daily_login = ?, coins = coins + ? WHERE id = ?',
            [streak, today, coinsReward, userId],
            function(err) {
                res.json({ success: true, coins: coinsReward, streak });
            }
        );
    });
});

externalApi.get('/notifications', authenticateApiKey, requirePermission('can_view_own_stats'), (req, res) => {
    db.all(
        `SELECT * FROM reseller_notifications WHERE reseller_id = ? AND read = 0 ORDER BY created_at DESC`,
        [req.user.userId],
        (err, notifications) => {
            res.json({ success: true, notifications });
        }
    );
});

externalApi.get('/coins', authenticateApiKey, requirePermission('can_view_own_stats'), (req, res) => {
    db.get('SELECT coins FROM users WHERE id = ?', [req.user.userId], (err, user) => {
        res.json({ success: true, coins: user?.coins || 0 });
    });
});

// Routes RESELLER
externalApi.get('/reseller/dashboard', authenticateApiKey, requirePermission('can_view_commission'), async (req, res) => {
    const userId = req.user.userId;

    const profile = await new Promise(r => 
        db.get('SELECT * FROM reseller_profiles WHERE user_id = ?', [userId], (e, row) => r(row))
    );

    if (!profile) {
        return res.status(403).json({ success: false, error: 'Profil revendeur requis' });
    }

    const clients = await new Promise(r => 
        db.get('SELECT COUNT(*) as total FROM reseller_clients WHERE reseller_id = ?', [userId], (e, row) => r(row?.total || 0))
    );

    const recentCommissions = await new Promise(r => 
        db.all(
            `SELECT cl.*, u.username as client_username
             FROM commission_logs cl
             JOIN users u ON cl.client_id = u.id
             WHERE cl.reseller_id = ?
             ORDER BY cl.created_at DESC
             LIMIT 5`,
            [userId], (e, rows) => r(rows || [])
        )
    );

    res.json({
        success: true,
        dashboard: {
            commission_balance: profile.commission_balance,
            total_earned: profile.total_earned,
            clients_count: clients,
            recent_commissions: recentCommissions
        }
    });
});

externalApi.get('/reseller/clients', authenticateApiKey, requirePermission('can_view_clients'), (req, res) => {
    db.all(
        `SELECT u.id, u.username, u.email, u.coins,
                COUNT(s.id) as server_count,
                SUM(CASE WHEN s.is_active = 1 THEN 1 ELSE 0 END) as active_servers
         FROM reseller_clients rc
         JOIN users u ON rc.client_id = u.id
         LEFT JOIN servers s ON u.id = s.user_id
         WHERE rc.reseller_id = ?
         GROUP BY u.id
         ORDER BY rc.created_at DESC`,
        [req.user.userId],
        (err, clients) => {
            res.json({ success: true, clients: clients || [] });
        }
    );
});

externalApi.get('/reseller/clients/:id', authenticateApiKey, requirePermission('can_view_clients'), (req, res) => {
    const clientId = req.params.id;

    db.get(
        'SELECT u.*, rc.acquisition_source FROM users u JOIN reseller_clients rc ON u.id = rc.client_id WHERE rc.reseller_id = ? AND rc.client_id = ?',
        [req.user.userId, clientId],
        (err, client) => {
            if (!client) return res.status(404).json({ success: false, error: 'Client non trouvé' });

            db.all('SELECT * FROM servers WHERE user_id = ?', [clientId], (err, servers) => {
                res.json({ success: true, client: { ...client, servers } });
            });
        }
    );
});

externalApi.get('/reseller/clients/:id/servers', authenticateApiKey, requirePermission('can_view_client_servers'), (req, res) => {
    const clientId = req.params.id;

    db.get(
        'SELECT * FROM reseller_clients WHERE reseller_id = ? AND client_id = ?',
        [req.user.userId, clientId],
        (err, rel) => {
            if (!rel) return res.status(403).json({ success: false, error: 'Accès non autorisé' });

            db.all('SELECT * FROM servers WHERE user_id = ?', [clientId], (err, servers) => {
                res.json({ success: true, servers });
            });
        }
    );
});

externalApi.post('/reseller/clients/:id/notify', authenticateApiKey, requirePermission('can_send_client_notification'), (req, res) => {
    const clientId = req.params.id;
    const { title, message, type } = req.body;

    db.get(
        'SELECT * FROM reseller_clients WHERE reseller_id = ? AND client_id = ?',
        [req.user.userId, clientId],
        (err, rel) => {
            if (!rel) return res.status(403).json({ success: false, error: 'Client non autorisé' });

            db.run(
                `INSERT INTO reseller_notifications (reseller_id, type, title, message, metadata) VALUES (?, ?, ?, ?, ?)`,
                [req.user.userId, type || 'info', title, message, JSON.stringify({ client_id: clientId })]
            );

            if (global.sendNotification) {
                global.sendNotification(clientId, { title, message, type, from_reseller: true });
            }

            res.json({ success: true, message: 'Notification envoyée' });
        }
    );
});

externalApi.get('/reseller/commissions', authenticateApiKey, requirePermission('can_view_commission'), (req, res) => {
    db.all(
        `SELECT cl.*, u.username as client_username
         FROM commission_logs cl
         JOIN users u ON cl.client_id = u.id
         WHERE cl.reseller_id = ?
         ORDER BY cl.created_at DESC
         LIMIT 50`,
        [req.user.userId],
        (err, commissions) => {
            res.json({ success: true, commissions });
        }
    );
});

externalApi.get('/reseller/commission-balance', authenticateApiKey, requirePermission('can_view_commission'), (req, res) => {
    db.get(
        'SELECT commission_balance FROM reseller_profiles WHERE user_id = ?',
        [req.user.userId],
        (err, profile) => {
            res.json({ success: true, balance: profile?.commission_balance || 0 });
        }
    );
});

externalApi.post('/reseller/withdraw', authenticateApiKey, requirePermission('can_request_withdrawal'), async (req, res) => {
    const { amount, payment_method, payment_details } = req.body;

    if (amount < RESELLER_CONFIG.min_withdrawal_amount) {
        return res.status(400).json({ success: false, error: `Minimum: ${RESELLER_CONFIG.min_withdrawal_amount} XOF` });
    }

    const profile = await new Promise(r => 
        db.get('SELECT commission_balance FROM reseller_profiles WHERE user_id = ?', [req.user.userId], (e, row) => r(row))
    );

    if (!profile || profile.commission_balance < amount) {
        return res.status(400).json({ success: false, error: 'Solde insuffisant' });
    }

    db.serialize(() => {
        db.run('BEGIN TRANSACTION');
        db.run('UPDATE reseller_profiles SET commission_balance = commission_balance - ? WHERE user_id = ?', [amount, req.user.userId]);
        db.run(
            `INSERT INTO withdrawal_requests (reseller_id, amount, payment_method, payment_details) VALUES (?, ?, ?, ?)`,
            [req.user.userId, amount, payment_method, JSON.stringify(payment_details)]
        );
        db.run('COMMIT');

        res.json({ success: true, message: 'Demande de retrait enregistrée' });
    });
});

externalApi.get('/reseller/withdrawals', authenticateApiKey, requirePermission('can_view_commission'), (req, res) => {
    db.all(
        'SELECT * FROM withdrawal_requests WHERE reseller_id = ? ORDER BY created_at DESC',
        [req.user.userId],
        (err, withdrawals) => {
            res.json({ success: true, withdrawals });
        }
    );
});

externalApi.post('/reseller/bulk-purchase', authenticateApiKey, requirePermission('can_bulk_purchase'), async (req, res) => {
    const { plan_key, quantity } = req.body;

    const user = await new Promise(r => db.get('SELECT coins FROM users WHERE id = ?', [req.user.userId], (e, row) => r(row)));

    const planPrice = PLAN_COINS_PRICES[plan_key];
    let discountRate = 0;
    for (const tier of RESELLER_CONFIG.bulk_discount_tiers) {
        if (quantity >= tier.min_quantity) discountRate = tier.discount;
    }

    const unitPrice = Math.floor(planPrice * (1 - discountRate / 100));
    const totalPrice = unitPrice * quantity;

    if (user.coins < totalPrice) {
        return res.status(400).json({ success: false, error: 'Coins insuffisants' });
    }

    db.serialize(() => {
        db.run('UPDATE users SET coins = coins - ? WHERE id = ?', [totalPrice, req.user.userId]);
        db.run(
            `INSERT INTO bulk_purchases (reseller_id, plan_key, quantity, unit_price, total_price, discount_applied, coins_credited)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [req.user.userId, plan_key, quantity, unitPrice, totalPrice, discountRate, planPrice * quantity]
        );
        db.run('COMMIT');

        res.json({ success: true, message: 'Achat en gros effectué' });
    });
});

externalApi.get('/reseller/promo-codes', authenticateApiKey, requirePermission('can_create_promo_codes'), (req, res) => {
    db.all(
        'SELECT * FROM reseller_promo_codes WHERE reseller_id = ? ORDER BY created_at DESC',
        [req.user.userId],
        (err, codes) => {
            res.json({ success: true, promo_codes: codes });
        }
    );
});

externalApi.post('/reseller/promo-codes', authenticateApiKey, requirePermission('can_create_promo_codes'), async (req, res) => {
    const { server_type, duration_hours, max_uses, expires_at } = req.body;

    const planPrice = PLAN_COINS_PRICES[server_type];
    const coinsCost = planPrice * max_uses;

    const user = await new Promise(r => db.get('SELECT coins FROM users WHERE id = ?', [req.user.userId], (e, row) => r(row)));

    if (user.coins < coinsCost) {
        return res.status(400).json({ success: false, error: 'Coins insuffisants' });
    }

    const code = 'RES_' + generatePromoCode(server_type.toUpperCase());

    db.serialize(() => {
        db.run('UPDATE users SET coins = coins - ? WHERE id = ?', [coinsCost, req.user.userId]);
        db.run(
            `INSERT INTO reseller_promo_codes (reseller_id, code, server_type, duration_hours, max_uses, coins_cost, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [req.user.userId, code, server_type, duration_hours, max_uses, coinsCost, expires_at]
        );
        db.run('COMMIT');

        res.json({ success: true, code });
    });
});

externalApi.get('/reseller/affiliate-info', authenticateApiKey, requirePermission('can_view_commission'), (req, res) => {
    db.get(
        'SELECT affiliate_code FROM reseller_profiles WHERE user_id = ?',
        [req.user.userId],
        (err, profile) => {
            if (!profile) return res.status(404).json({ success: false, error: 'Profil non trouvé' });

            const affiliateUrl = `${WEB_CONFIG.SITE_URL}/register?aff=${profile.affiliate_code}`;

            db.get(
                'SELECT COUNT(*) as conversions FROM reseller_clients WHERE reseller_id = ? AND acquisition_source = "affiliate"',
                [req.user.userId],
                (err, stats) => {
                    res.json({
                        success: true,
                        affiliate_code: profile.affiliate_code,
                        affiliate_url: affiliateUrl,
                        conversions: stats?.conversions || 0
                    });
                }
            );
        }
    );
});

externalApi.get('/reseller/stats/monthly', authenticateApiKey, requirePermission('can_view_commission'), (req, res) => {
    const startDate = new Date();
    startDate.setDate(1);
    startDate.setHours(0, 0, 0, 0);

    db.get(
        'SELECT SUM(amount) as revenue FROM commission_logs WHERE reseller_id = ? AND created_at >= ?',
        [req.user.userId, startDate.toISOString()],
        (err, result) => {
            res.json({ success: true, monthly_revenue: result?.revenue || 0 });
        }
    );
});

// Routes SUPERADMIN
externalApi.get('/admin/users', authenticateApiKey, requirePermission('can_view_all_users'), (req, res) => {
    db.all('SELECT id, username, email, coins, role, created_at FROM users ORDER BY created_at DESC LIMIT 100', [], (err, users) => {
        res.json({ success: true, users });
    });
});

externalApi.get('/admin/users/:id', authenticateApiKey, requirePermission('can_view_all_users'), (req, res) => {
    db.get('SELECT * FROM users WHERE id = ?', [req.params.id], (err, user) => {
        res.json({ success: true, user });
    });
});

externalApi.post('/admin/users/:id/ban', authenticateApiKey, requirePermission('can_ban_users'), (req, res) => {
    const { reason, duration_hours } = req.body;
    let banExpires = null;
    if (duration_hours) {
        banExpires = new Date();
        banExpires.setHours(banExpires.getHours() + duration_hours);
    }

    db.run(
        'UPDATE users SET banned = 1, ban_reason = ?, ban_expires = ? WHERE id = ?',
        [reason, banExpires?.toISOString(), req.params.id],
        function(err) {
            res.json({ success: true, message: 'Utilisateur banni' });
        }
    );
});

externalApi.post('/admin/users/:id/unban', authenticateApiKey, requirePermission('can_ban_users'), (req, res) => {
    db.run('UPDATE users SET banned = 0, ban_reason = NULL, ban_expires = NULL WHERE id = ?', [req.params.id], function(err) {
        res.json({ success: true, message: 'Utilisateur débanni' });
    });
});

externalApi.post('/admin/users/:id/coins', authenticateApiKey, requirePermission('can_add_coins_to_any_user'), (req, res) => {
    const { amount, reason } = req.body;

    db.run('UPDATE users SET coins = coins + ? WHERE id = ?', [amount, req.params.id], function(err) {
        if (err) return res.status(500).json({ success: false, error: 'Erreur' });

        db.run(
            'INSERT INTO user_activities (user_id, activity_type, coins_earned, description) VALUES (?, ?, ?, ?)',
            [req.params.id, 'admin_coins', amount, reason || 'Ajustement par admin']
        );

        res.json({ success: true, message: `Coins ${amount > 0 ? 'ajoutés' : 'retirés'}` });
    });
});

externalApi.get('/admin/servers', authenticateApiKey, requirePermission('can_view_all_servers'), (req, res) => {
    db.all(
        `SELECT s.*, u.username, u.email 
         FROM servers s
         JOIN users u ON s.user_id = u.id
         ORDER BY s.created_at DESC
         LIMIT 100`,
        [],
        (err, servers) => {
            res.json({ success: true, servers });
        }
    );
});

externalApi.delete('/admin/servers/:id', authenticateApiKey, requirePermission('can_delete_any_server'), async (req, res) => {
    const server = await new Promise(r => db.get('SELECT * FROM servers WHERE id = ?', [req.params.id], (e, row) => r(row)));

    if (!server) return res.status(404).json({ success: false, error: 'Serveur non trouvé' });

    await deletePterodactylServer(server.pterodactyl_id);
    db.run('DELETE FROM servers WHERE id = ?', [req.params.id]);

    res.json({ success: true, message: 'Serveur supprimé' });
});

externalApi.get('/admin/resellers', authenticateApiKey, requirePermission('can_manage_resellers'), (req, res) => {
    db.all(
        `SELECT u.id, u.username, u.email, rp.*,
                (SELECT COUNT(*) FROM reseller_clients WHERE reseller_id = u.id) as clients_count
         FROM users u
         JOIN reseller_profiles rp ON u.id = rp.user_id
         WHERE u.role = 'admin'`,
        [],
        (err, resellers) => {
            res.json({ success: true, resellers });
        }
    );
});

externalApi.get('/admin/withdrawals', authenticateApiKey, requirePermission('can_approve_withdrawals'), (req, res) => {
    const { status = 'pending' } = req.query;

    db.all(
        `SELECT wr.*, u.username as reseller_username
         FROM withdrawal_requests wr
         JOIN users u ON wr.reseller_id = u.id
         WHERE wr.status = ?`,
        [status],
        (err, withdrawals) => {
            res.json({ success: true, withdrawals });
        }
    );
});

externalApi.post('/admin/withdrawals/:id/process', authenticateApiKey, requirePermission('can_approve_withdrawals'), async (req, res) => {
    const { action, reference, admin_note } = req.body;

    const withdrawal = await new Promise(r => db.get('SELECT * FROM withdrawal_requests WHERE id = ?', [req.params.id], (e, row) => r(row)));

    if (!withdrawal) return res.status(404).json({ success: false, error: 'Demande non trouvée' });

    db.serialize(() => {
        if (action === 'approved') {
            db.run(
                `UPDATE withdrawal_requests SET status = 'approved', processed_by = ?, processed_at = CURRENT_TIMESTAMP, reference = ?, admin_note = ? WHERE id = ?`,
                [req.user.userId, reference, admin_note, req.params.id]
            );
            db.run('UPDATE reseller_profiles SET total_withdrawn = total_withdrawn + ? WHERE user_id = ?', [withdrawal.amount, withdrawal.reseller_id]);
        } else {
            db.run(
                `UPDATE withdrawal_requests SET status = 'rejected', processed_by = ?, processed_at = CURRENT_TIMESTAMP, admin_note = ? WHERE id = ?`,
                [req.user.userId, admin_note, req.params.id]
            );
            db.run('UPDATE reseller_profiles SET commission_balance = commission_balance + ? WHERE user_id = ?', [withdrawal.amount, withdrawal.reseller_id]);
        }

        res.json({ success: true, action });
    });
});

externalApi.get('/admin/financial-report', authenticateApiKey, requirePermission('can_view_financial_reports'), (req, res) => {
    Promise.all([
        new Promise(r => db.get('SELECT SUM(amount) as total_commissions FROM commission_logs', [], (e, row) => r(row?.total_commissions || 0))),
        new Promise(r => db.get('SELECT SUM(amount) as total_withdrawn FROM withdrawal_requests WHERE status = "approved"', [], (e, row) => r(row?.total_withdrawn || 0))),
        new Promise(r => db.get('SELECT SUM(amount) as pending_withdrawals FROM withdrawal_requests WHERE status = "pending"', [], (e, row) => r(row?.pending_withdrawals || 0))),
        new Promise(r => db.get('SELECT SUM(total_price) as bulk_revenue FROM bulk_purchases', [], (e, row) => r(row?.bulk_revenue || 0))),
        new Promise(r => db.get('SELECT SUM(amount) as platform_revenue FROM transactions WHERE status = "completed"', [], (e, row) => r(row?.platform_revenue || 0)))
    ]).then(([total_commissions, total_withdrawn, pending_withdrawals, bulk_revenue, platform_revenue]) => {
        res.json({
            success: true,
            report: {
                total_commissions,
                total_withdrawn,
                pending_withdrawals,
                bulk_revenue,
                platform_revenue,
                net_platform_revenue: platform_revenue - total_commissions
            }
        });
    });
});

externalApi.get('/admin/stats', authenticateApiKey, requirePermission('can_view_system_logs'), (req, res) => {
    Promise.all([
        new Promise(r => db.get('SELECT COUNT(*) as users FROM users', [], (e, row) => r(row?.users || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as servers FROM servers', [], (e, row) => r(row?.servers || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as admins FROM users WHERE role = "admin"', [], (e, row) => r(row?.admins || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as resellers FROM reseller_profiles', [], (e, row) => r(row?.resellers || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as active_servers FROM servers WHERE is_active = 1', [], (e, row) => r(row?.active_servers || 0))),
        new Promise(r => db.get('SELECT SUM(amount) as revenue FROM transactions WHERE status = "completed"', [], (e, row) => r(row?.revenue || 0)))
    ]).then(([users, servers, admins, resellers, active_servers, revenue]) => {
        res.json({ success: true, stats: { users, servers, admins, resellers, active_servers, revenue } });
    });
});

externalApi.get('/admin/logs', authenticateApiKey, requirePermission('can_view_system_logs'), (req, res) => {
    db.all(
        'SELECT * FROM system_logs ORDER BY created_at DESC LIMIT 100',
        [],
        (err, logs) => {
            res.json({ success: true, logs });
        }
    );
});

externalApi.post('/admin/promo-codes', authenticateApiKey, requirePermission('can_create_promo_codes'), (req, res) => {
    const { server_type, duration_hours, max_uses, expires_at, description } = req.body;
    const code = generatePromoCode(server_type.toUpperCase());

    db.run(
        `INSERT INTO promo_codes (code, server_type, duration_hours, max_uses, created_by, expires_at, description)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [code, server_type, duration_hours, max_uses, req.user.userId, expires_at, description],
        function(err) {
            res.json({ success: true, code, id: this.lastID });
        }
    );
});

externalApi.get('/admin/transactions', authenticateApiKey, requirePermission('can_view_all_transactions'), (req, res) => {
    db.all(
        `SELECT t.*, u.username 
         FROM transactions t
         JOIN users u ON t.user_id = u.id
         WHERE t.status = "completed"
         ORDER BY t.created_at DESC
         LIMIT 100`,
        [],
        (err, transactions) => {
            res.json({ success: true, transactions });
        }
    );
});

externalApi.post('/admin/settings', authenticateApiKey, requirePermission('can_manage_platform_settings'), (req, res) => {
    const { key, value } = req.body;

    db.run(
        'INSERT OR REPLACE INTO system_settings (key, value, updated_at, updated_by) VALUES (?, ?, CURRENT_TIMESTAMP, ?)',
        [key, value, req.user.userId],
        function(err) {
            res.json({ success: true, message: 'Paramètre mis à jour' });
        }
    );
});

externalApi.post('/admin/resellers/:id/commission-rate', authenticateApiKey, requirePermission('can_adjust_commission_rates'), (req, res) => {
    const { rate } = req.body;

    db.run(
        'UPDATE reseller_profiles SET commission_rate = ? WHERE user_id = ?',
        [rate, req.params.id],
        function(err) {
            res.json({ success: true, message: `Taux modifié à ${rate}%` });
        }
    );
});

app.use('/v1', externalApi);

// =============================================
// ROUTES ADMIN INTERNE (/admin)
// =============================================

app.use('/admin', requireInternalAccess);

app.get('/admin/dashboard', (req, res) => {
    const stats = {};

    Promise.all([
        new Promise(r => db.get('SELECT COUNT(*) as total FROM users', [], (e, row) => { stats.totalUsers = row?.total || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM users WHERE is_verified = 1', [], (e, row) => { stats.verifiedUsers = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM users WHERE is_banned = 1', [], (e, row) => { stats.bannedUsers = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as active FROM users WHERE last_login > datetime("now", "-7 days")', [], (e, row) => { stats.activeUsers = row?.active || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM servers', [], (e, row) => { stats.totalServers = row?.total || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as active FROM servers WHERE is_active = 1', [], (e, row) => { stats.activeServers = row?.active || 0; r(); })),
        new Promise(r => db.all('SELECT server_type, COUNT(*) as count FROM servers GROUP BY server_type', [], (e, rows) => { stats.serversByType = rows || []; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM transactions WHERE status = "completed"', [], (e, row) => { stats.totalTransactions = row?.total || 0; r(); })),
        new Promise(r => db.get('SELECT SUM(amount) as total FROM transactions WHERE status = "completed"', [], (e, row) => { stats.totalRevenue = row?.total || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM promo_codes WHERE is_active = 1', [], (e, row) => { stats.activePromoCodes = row?.total || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM promo_code_uses WHERE used_at > datetime("now", "-7 days")', [], (e, row) => { stats.promoUsesWeek = row?.total || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM deployments', [], (e, row) => { stats.totalDeployments = row?.total || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM deployments WHERE status = "running"', [], (e, row) => { stats.runningDeployments = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM deployments WHERE status = "failed"', [], (e, row) => { stats.failedDeployments = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM deployments WHERE method = "github"', [], (e, row) => { stats.githubDeployments = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM deployments WHERE method = "zip"', [], (e, row) => { stats.zipDeployments = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as c FROM deployments WHERE method = "template"', [], (e, row) => { stats.templateDeployments = row?.c || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM github_connections', [], (e, row) => { stats.githubConnections = row?.total || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM panels', [], (e, row) => { stats.totalPanels = row?.total || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM reseller_profiles WHERE active = 1', [], (e, row) => { stats.activeResellers = row?.total || 0; r(); })),
        new Promise(r => db.get('SELECT SUM(commission_balance) as total FROM reseller_profiles', [], (e, row) => { stats.totalCommissionBalance = row?.total || 0; r(); })),
        new Promise(r => db.get('SELECT COUNT(*) as pending FROM withdrawal_requests WHERE status = "pending"', [], (e, row) => { stats.pendingWithdrawals = row?.pending || 0; r(); })),
        new Promise(r => db.get('SELECT SUM(amount) as total FROM withdrawal_requests WHERE status = "pending"', [], (e, row) => { stats.pendingWithdrawalAmount = row?.total || 0; r(); }))
    ]).then(() => {
        res.json({
            success: true,
            message: '🚀 Interface d\'administration interne FLYHOST',
            stats,
            timestamp: new Date().toISOString()
        });
    }).catch(e => res.json({ success: false, error: e.message }));
});

app.get('/admin/promo-codes', (req, res) => {
    db.all(
        `SELECT pc.*, u.username as created_by_username,
                (SELECT COUNT(*) FROM promo_code_uses WHERE promo_code_id = pc.id) as uses
         FROM promo_codes pc
         LEFT JOIN users u ON pc.created_by = u.id
         ORDER BY pc.created_at DESC`,
        [],
        (err, codes) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    error: 'Erreur récupération codes promo',
                    details: err.message
                });
            }
            res.json({ success: true, codes });
        }
    );
});

app.post('/admin/promo-codes/create', (req, res) => {
    const { 
        server_type, 
        duration_hours, 
        max_uses, 
        expires_at, 
        description,
        custom_code,
        admin_id 
    } = req.body;

    if (!server_type || !PLANS_CONFIG[server_type]) {
        return res.status(400).json({
            success: false,
            error: 'Type de serveur invalide'
        });
    }

    if (!duration_hours || duration_hours < 1 || duration_hours > 8760) {
        return res.status(400).json({
            success: false,
            error: 'Durée invalide (1-8760 heures)'
        });
    }

    if (!max_uses || max_uses < 1) {
        return res.status(400).json({
            success: false,
            error: 'Nombre d\'utilisations invalide'
        });
    }

    if (!admin_id) {
        return res.status(400).json({
            success: false,
            error: 'ID admin requis'
        });
    }

    db.get('SELECT id FROM users WHERE id = ? AND role IN ("admin", "superadmin")', [admin_id], (err, admin) => {
        if (err || !admin) {
            return res.status(403).json({
                success: false,
                error: 'Admin non trouvé ou non autorisé'
            });
        }

        const code = custom_code || generatePromoCode(server_type.toUpperCase());

        db.run(
            `INSERT INTO promo_codes (
                code, server_type, duration_hours, max_uses, current_uses, 
                created_by, expires_at, description, is_active
            ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, 1)`,
            [code, server_type, duration_hours, max_uses, admin_id, expires_at || null, description || null],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        return res.status(400).json({
                            success: false,
                            error: 'Ce code promo existe déjà'
                        });
                    }
                    return res.status(500).json({
                        success: false,
                        error: 'Erreur création code promo',
                        details: err.message
                    });
                }

                logAdminAction(
                    admin_id,
                    'create_promo_code',
                    'promo_code',
                    this.lastID,
                    `Création code promo ${code} pour ${server_type} (${max_uses} utilisations, ${duration_hours}h)`
                );

                res.json({
                    success: true,
                    message: 'Code promo créé avec succès',
                    code: {
                        id: this.lastID,
                        code,
                        server_type,
                        duration_hours,
                        max_uses,
                        expires_at
                    }
                });
            }
        );
    });
});

app.put('/admin/promo-codes/:codeId', (req, res) => {
    const { codeId } = req.params;
    const { max_uses, is_active, expires_at, description, admin_id } = req.body;

    if (!admin_id) {
        return res.status(400).json({
            success: false,
            error: 'ID admin requis'
        });
    }

    db.run(
        `UPDATE promo_codes SET 
            max_uses = COALESCE(?, max_uses),
            is_active = COALESCE(?, is_active),
            expires_at = COALESCE(?, expires_at),
            description = COALESCE(?, description)
         WHERE id = ?`,
        [max_uses, is_active, expires_at, description, codeId],
        function(err) {
            if (err) {
                return res.status(500).json({
                    success: false,
                    error: 'Erreur mise à jour',
                    details: err.message
                });
            }

            logAdminAction(admin_id, 'update_promo_code', 'promo_code', codeId, 'Mise à jour code promo');

            res.json({
                success: true,
                message: 'Code promo mis à jour',
                changes: this.changes
            });
        }
    );
});

app.delete('/admin/promo-codes/:codeId', (req, res) => {
    const { codeId } = req.params;
    const { admin_id } = req.body;

    if (!admin_id) {
        return res.status(400).json({
            success: false,
            error: 'ID admin requis'
        });
    }

    db.get('SELECT code FROM promo_codes WHERE id = ?', [codeId], (err, code) => {
        if (err || !code) {
            return res.status(404).json({
                success: false,
                error: 'Code promo non trouvé'
            });
        }

        db.run('DELETE FROM promo_codes WHERE id = ?', [codeId], function(err) {
            if (err) {
                return res.status(500).json({
                    success: false,
                    error: 'Erreur suppression',
                    details: err.message
                });
            }

            logAdminAction(admin_id, 'delete_promo_code', 'promo_code', codeId, `Suppression code promo ${code.code}`);

            res.json({
                success: true,
                message: 'Code promo supprimé'
            });
        });
    });
});

app.get('/admin/promo-codes/:codeId/uses', (req, res) => {
    const { codeId } = req.params;

    db.all(
        `SELECT pcu.*, u.username, s.server_name 
         FROM promo_code_uses pcu
         JOIN users u ON pcu.user_id = u.id
         JOIN servers s ON pcu.server_id = s.id
         WHERE pcu.promo_code_id = ?
         ORDER BY pcu.used_at DESC`,
        [codeId],
        (err, uses) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    error: 'Erreur récupération utilisations'
                });
            }
            res.json({ success: true, uses });
        }
    );
});

app.get('/admin/servers', (req, res) => {
    const { status, type, user_id, limit = 50, offset = 0 } = req.query;

    let query = `
        SELECT s.*, u.username, u.email 
        FROM servers s
        JOIN users u ON s.user_id = u.id
        WHERE 1=1
    `;
    const params = [];

    if (status) {
        query += ' AND s.server_status = ?';
        params.push(status);
    }
    if (type) {
        query += ' AND s.server_type = ?';
        params.push(type);
    }
    if (user_id) {
        query += ' AND s.user_id = ?';
        params.push(user_id);
    }

    query += ' ORDER BY s.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    db.all(query, params, (err, servers) => {
        if (err) {
            return res.status(500).json({
                success: false,
                error: 'Erreur récupération serveurs'
            });
        }

        db.get('SELECT COUNT(*) as total FROM servers', [], (err, count) => {
            res.json({
                success: true,
                servers,
                total: count?.total || 0,
                limit: parseInt(limit),
                offset: parseInt(offset)
            });
        });
    });
});

app.post('/admin/servers/:serverId/delete', (req, res) => {
    const { serverId } = req.params;
    const { admin_id, force } = req.body;

    if (!admin_id) {
        return res.status(400).json({
            success: false,
            error: 'ID admin requis'
        });
    }

    db.get('SELECT * FROM servers WHERE id = ?', [serverId], async (err, server) => {
        if (err || !server) {
            return res.status(404).json({
                success: false,
                error: 'Serveur non trouvé'
            });
        }

        try {
            await deletePterodactylServer(server.pterodactyl_id);

            db.run('DELETE FROM servers WHERE id = ?', [serverId], function(err) {
                if (err) {
                    return res.status(500).json({
                        success: false,
                        error: 'Erreur suppression'
                    });
                }

                logAdminAction(
                    admin_id,
                    'delete_server',
                    'server',
                    serverId,
                    `Suppression serveur ${server.server_name} (${server.server_type})`
                );

                res.json({
                    success: true,
                    message: 'Serveur supprimé'
                });
            });
        } catch (error) {
            console.error('❌ Erreur suppression serveur:', error);
            res.status(500).json({
                success: false,
                error: 'Erreur suppression serveur',
                details: error.message
            });
        }
    });
});

app.get('/admin/users', (req, res) => {
    const { search, role, banned, limit = 50, offset = 0 } = req.query;

    let query = `
        SELECT u.*, 
               (SELECT COUNT(*) FROM servers WHERE user_id = u.id) as server_count,
               (SELECT COUNT(*) FROM transactions WHERE user_id = u.id) as transaction_count,
               (SELECT COUNT(*) FROM deployments WHERE user_id = u.id) as deployment_count,
               (SELECT COUNT(*) FROM github_connections WHERE user_id = u.id) as github_connected
        FROM users u
        WHERE 1=1
    `;
    const params = [];

    if (search) {
        query += ' AND (u.username LIKE ? OR u.email LIKE ?)';
        params.push(`%${search}%`, `%${search}%`);
    }
    if (role) {
        query += ' AND u.role = ?';
        params.push(role);
    }
    if (banned !== undefined) {
        query += ' AND u.banned = ?';
        params.push(banned === 'true' ? 1 : 0);
    }

    query += ' ORDER BY u.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    db.all(query, params, (err, users) => {
        if (err) {
            return res.status(500).json({
                success: false,
                error: 'Erreur récupération utilisateurs'
            });
        }

        db.get('SELECT COUNT(*) as total FROM users', [], (err, count) => {
            res.json({
                success: true,
                users,
                total: count?.total || 0,
                limit: parseInt(limit),
                offset: parseInt(offset)
            });
        });
    });
});

app.post('/admin/users/:userId/ban', (req, res) => {
    const { userId } = req.params;
    const { reason, duration_hours, admin_id } = req.body;

    if (!admin_id) {
        return res.status(400).json({
            success: false,
            error: 'ID admin requis'
        });
    }

    if (parseInt(userId) === parseInt(admin_id)) {
        return res.status(400).json({
            success: false,
            error: 'Impossible de se bannir soi-même'
        });
    }

    let banExpires = null;
    if (duration_hours && duration_hours > 0) {
        banExpires = new Date();
        banExpires.setHours(banExpires.getHours() + duration_hours);
    }

    db.run(
        'UPDATE users SET banned = 1, ban_reason = ?, ban_expires = ? WHERE id = ?',
        [reason || null, banExpires?.toISOString(), userId],
        function(err) {
            if (err) {
                return res.status(500).json({
                    success: false,
                    error: 'Erreur bannissement'
                });
            }

            logAdminAction(
                admin_id,
                'ban_user',
                'user',
                userId,
                `Bannissement: ${reason || 'Aucune raison'}${duration_hours ? ` (${duration_hours}h)` : ' (permanent)'}`
            );

            res.json({
                success: true,
                message: 'Utilisateur banni',
                ban_expires: banExpires
            });
        }
    );
});

app.post('/admin/users/:userId/unban', (req, res) => {
    const { userId } = req.params;
    const { admin_id } = req.body;

    if (!admin_id) {
        return res.status(400).json({
            success: false,
            error: 'ID admin requis'
        });
    }

    db.run(
        'UPDATE users SET banned = 0, ban_reason = NULL, ban_expires = NULL WHERE id = ?',
        [userId],
        function(err) {
            if (err) {
                return res.status(500).json({
                    success: false,
                    error: 'Erreur débannissement'
                });
            }

            logAdminAction(admin_id, 'unban_user', 'user', userId, 'Débannissement');

            res.json({
                success: true,
                message: 'Utilisateur débanni'
            });
        }
    );
});

app.post('/admin/users/:userId/coins', (req, res) => {
    const { userId } = req.params;
    const { amount, action, reason, admin_id } = req.body;

    if (!admin_id) {
        return res.status(400).json({ success: false, error: 'ID admin requis' });
    }
    if (amount === undefined || amount === null || amount === '') {
        return res.status(400).json({ success: false, error: 'Montant invalide' });
    }

    const numAmount = parseInt(amount);
    if (isNaN(numAmount)) {
        return res.status(400).json({ success: false, error: 'Montant invalide' });
    }

    db.get('SELECT id, username, coins FROM users WHERE id = ?', [userId], (err, user) => {
        if (err || !user) {
            return res.status(404).json({ success: false, error: 'Utilisateur non trouvé' });
        }

        const isSet = action === 'set';
        const sql = isSet
            ? 'UPDATE users SET coins = ? WHERE id = ?'
            : 'UPDATE users SET coins = MAX(0, coins + ?) WHERE id = ?';
        const finalAmount = isSet ? Math.max(0, numAmount) : numAmount;
        const coinsEarned = isSet ? (finalAmount - user.coins) : numAmount;

        db.run(sql, [finalAmount, userId], function(err) {
            if (err) {
                return res.status(500).json({ success: false, error: 'Erreur modification coins' });
            }

            db.run(
                'INSERT INTO user_activities (user_id, activity_type, coins_earned, description) VALUES (?, ?, ?, ?)',
                [userId, 'admin_coins', coinsEarned, reason || `Ajustement admin: ${action === 'set' ? '=' : coinsEarned > 0 ? '+' : ''}${coinsEarned} coins`]
            );

            if (admin_id) {
                logAdminAction(admin_id, 'adjust_coins', 'user', userId,
                    `${action === 'set' ? 'Défini à' : coinsEarned > 0 ? '+' : ''}${coinsEarned} coins - ${reason || 'Aucune raison'}`);
            }

            res.json({ success: true, message: `Coins ${action === 'add' ? 'ajoutés' : action === 'remove' ? 'retirés' : 'définis'}`, amount: finalAmount });
        });
    });
});

app.delete('/admin/users/:userId', (req, res) => {
    const { userId } = req.params;
    const { admin_id } = req.body;

    db.get('SELECT id, username, role FROM users WHERE id = ?', [userId], (err, user) => {
        if (err || !user) return res.status(404).json({ success: false, error: 'Utilisateur non trouvé' });
        if (user.role === 'superadmin') return res.status(403).json({ success: false, error: 'Impossible de supprimer un superadmin' });

        db.serialize(() => {
            db.run('DELETE FROM servers WHERE user_id = ?', [userId]);
            db.run('DELETE FROM user_activities WHERE user_id = ?', [userId]);
            db.run('DELETE FROM user_credits WHERE user_id = ?', [userId]);
            db.run('DELETE FROM api_keys WHERE user_id = ?', [userId]);
            db.run('DELETE FROM user_subscriptions WHERE user_id = ?', [userId]);
            db.run('DELETE FROM marketplace_listings WHERE seller_id = ?', [userId]);
            db.run('DELETE FROM users WHERE id = ?', [userId], function(err2) {
                if (err2) return res.status(500).json({ success: false, error: 'Erreur suppression' });
                if (admin_id) logAdminAction(admin_id, 'delete_user', 'user', userId, `Suppression compte: ${user.username}`);
                res.json({ success: true, message: `Utilisateur ${user.username} supprimé` });
            });
        });
    });
});

app.get('/admin/stats', (req, res) => {
    const stats = {};

    Promise.all([
        new Promise(r => db.get('SELECT COUNT(*) as total FROM users', [], (e, row) => stats.totalUsers = row?.total || 0)),
        new Promise(r => db.get('SELECT COUNT(*) as verified FROM users WHERE email_verified = 1', [], (e, row) => stats.verifiedUsers = row?.total || 0)),
        new Promise(r => db.get('SELECT COUNT(*) as banned FROM users WHERE banned = 1', [], (e, row) => stats.bannedUsers = row?.total || 0)),
        new Promise(r => db.get('SELECT COUNT(*) as admins FROM users WHERE role IN ("admin", "superadmin")', [], (e, row) => stats.adminUsers = row?.total || 0)),
        
        new Promise(r => db.get('SELECT COUNT(*) as total FROM servers', [], (e, row) => stats.totalServers = row?.total || 0)),
        new Promise(r => db.get('SELECT COUNT(*) as active FROM servers WHERE is_active = 1', [], (e, row) => stats.activeServers = row?.total || 0)),
        new Promise(r => db.get('SELECT server_type, COUNT(*) as count FROM servers GROUP BY server_type', [], (e, rows) => stats.serversByType = rows || [])),
        
        new Promise(r => db.get('SELECT COUNT(*) as total FROM transactions WHERE status = "completed"', [], (e, row) => stats.totalTransactions = row?.total || 0)),
        new Promise(r => db.get('SELECT SUM(amount) as total FROM transactions WHERE status = "completed"', [], (e, row) => stats.totalRevenue = row?.total || 0)),
        
        new Promise(r => db.get('SELECT COUNT(*) as total FROM promo_codes', [], (e, row) => stats.totalPromoCodes = row?.total || 0)),
        new Promise(r => db.get('SELECT COUNT(*) as active FROM promo_codes WHERE is_active = 1', [], (e, row) => stats.activePromoCodes = row?.total || 0)),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM promo_code_uses', [], (e, row) => stats.totalPromoUses = row?.total || 0)),
        
        new Promise(r => db.get('SELECT COUNT(*) as today FROM users WHERE last_login > date("now")', [], (e, row) => stats.usersToday = row?.total || 0)),
        new Promise(r => db.get('SELECT COUNT(*) as week FROM users WHERE last_login > date("now", "-7 days")', [], (e, row) => stats.usersWeek = row?.total || 0)),
        
        new Promise(r => db.get('SELECT COUNT(*) as today FROM users WHERE created_at > date("now")', [], (e, row) => stats.newUsersToday = row?.total || 0)),
        new Promise(r => db.get('SELECT COUNT(*) as week FROM users WHERE created_at > date("now", "-7 days")', [], (e, row) => stats.newUsersWeek = row?.total || 0)),

        new Promise(r => db.get('SELECT COUNT(*) as total FROM deployments', [], (e, row) => stats.totalDeployments = row?.total || 0)),
        new Promise(r => db.get('SELECT COUNT(*) as github FROM deployments WHERE deploy_type = "github"', [], (e, row) => stats.githubDeployments = row?.total || 0)),
        new Promise(r => db.get('SELECT COUNT(*) as zip FROM deployments WHERE deploy_type = "zip"', [], (e, row) => stats.zipDeployments = row?.total || 0)),
        new Promise(r => db.get('SELECT COUNT(*) as template FROM deployments WHERE deploy_type = "template"', [], (e, row) => stats.templateDeployments = row?.total || 0)),
        new Promise(r => db.get('SELECT COUNT(*) as running FROM deployments WHERE status = "running"', [], (e, row) => stats.runningDeployments = row?.total || 0)),
        new Promise(r => db.get('SELECT COUNT(*) as failed FROM deployments WHERE status = "failed"', [], (e, row) => stats.failedDeployments = row?.total || 0)),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM github_connections', [], (e, row) => stats.githubConnections = row?.total || 0)),

        new Promise(r => db.get('SELECT COUNT(*) as total FROM panels', [], (e, row) => stats.totalPanels = row?.total || 0)),
        new Promise(r => db.get('SELECT COUNT(*) as active FROM panels WHERE is_active = 1', [], (e, row) => stats.activePanels = row?.total || 0)),
        new Promise(r => db.get('SELECT panel_type, COUNT(*) as count FROM panels GROUP BY panel_type', [], (e, rows) => stats.panelsByType = rows || [])),

        // Stats revendeur
        new Promise(r => db.get('SELECT COUNT(*) as total FROM reseller_profiles WHERE active = 1', [], (e, row) => stats.activeResellers = row?.total || 0)),
        new Promise(r => db.get('SELECT SUM(commission_balance) as total FROM reseller_profiles', [], (e, row) => stats.totalCommissionBalance = row?.total || 0)),
        new Promise(r => db.get('SELECT COUNT(*) as pending FROM withdrawal_requests WHERE status = "pending"', [], (e, row) => stats.pendingWithdrawals = row?.total || 0)),
        new Promise(r => db.get('SELECT SUM(amount) as total FROM withdrawal_requests WHERE status = "pending"', [], (e, row) => stats.pendingWithdrawalAmount = row?.total || 0)),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM bulk_purchases', [], (e, row) => stats.totalBulkPurchases = row?.total || 0)),
        new Promise(r => db.get('SELECT SUM(total_price) as total FROM bulk_purchases', [], (e, row) => stats.totalBulkRevenue = row?.total || 0))
    ]).then(() => {
        stats.verificationRate = stats.totalUsers > 0 ? (stats.verifiedUsers / stats.totalUsers * 100).toFixed(2) : 0;
        stats.activeServerRate = stats.totalServers > 0 ? (stats.activeServers / stats.totalServers * 100).toFixed(2) : 0;
        
        res.json({
            success: true,
            stats,
            timestamp: new Date().toISOString()
        });
    });
});

app.get('/admin/admins/list', authenticateToken, requireSuperAdmin, (req, res) => {
    db.all(`SELECT id, username, email, admin_expires_at, coins,
            (SELECT COUNT(*) FROM servers WHERE user_id = users.id) as server_count
            FROM users WHERE role = 'admin'
            ORDER BY admin_expires_at DESC`, [], (err, admins) => {
        res.json({ success: true, admins });
    });
});

app.post('/admin/users/:userId/set-admin', authenticateToken, requireSuperAdmin, (req, res) => {
    const { duration_days, free } = req.body;
    
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + (duration_days || 30));
    
    db.run(`UPDATE users SET 
        role = 'admin',
        admin_expires_at = ?,
        admin_access_active = 1
        WHERE id = ?`,
        [expiresAt.toISOString(), req.params.userId],
        function(err) {
            res.json({ success: true });
        }
    );
});

app.post('/admin/users/:userId/revoke-admin', authenticateToken, requireSuperAdmin, (req, res) => {
    db.run(`UPDATE users SET 
        role = 'user',
        admin_expires_at = NULL,
        admin_access_active = 0
        WHERE id = ?`,
        [req.params.userId],
        function(err) {
            res.json({ success: true });
        }
    );
});

app.get('/admin/platform/stats', authenticateToken, requireSuperAdmin, (req, res) => {
    Promise.all([
        new Promise(r => db.get('SELECT COUNT(*) as total FROM users', [], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM servers', [], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT SUM(amount) as total FROM transactions WHERE status = "completed"', [], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM deployments', [], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as active FROM users WHERE role = "admin" AND admin_access_active = 1', [], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM api_keys', [], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM user_credits WHERE balance > 0', [], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT SUM(balance) as total FROM user_credits', [], (e, row) => r(row?.total || 0)))
    ]).then(([users, servers, revenue, deployments, activeAdmins, apiKeys, usersWithCredits, totalCredits]) => {
        res.json({
            success: true,
            stats: {
                users, servers, revenue, deployments, activeAdmins, apiKeys,
                usersWithCredits, totalCredits: totalCredits || 0
            }
        });
    });
});

app.get('/admin/logs', (req, res) => {
    const { type, limit = 100, offset = 0 } = req.query;

    let query = 'SELECT * FROM system_logs';
    const params = [];

    if (type) {
        query += ' WHERE log_type = ?';
        params.push(type);
    }

    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    db.all(query, params, (err, logs) => {
        if (err) {
            return res.status(500).json({
                success: false,
                error: 'Erreur récupération logs'
            });
        }

        db.get('SELECT COUNT(*) as total FROM system_logs', [], (err, count) => {
            res.json({
                success: true,
                logs,
                total: count?.total || 0,
                limit: parseInt(limit),
                offset: parseInt(offset)
            });
        });
    });
});

app.get('/admin/admin-actions', (req, res) => {
    const { admin_id, limit = 50, offset = 0 } = req.query;

    let query = `
        SELECT a.*, u.username as admin_username 
        FROM admin_actions a
        LEFT JOIN users u ON a.admin_id = u.id
        WHERE 1=1
    `;
    const params = [];

    if (admin_id) {
        query += ' AND a.admin_id = ?';
        params.push(admin_id);
    }

    query += ' ORDER BY a.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    db.all(query, params, (err, actions) => {
        if (err) {
            return res.status(500).json({
                success: false,
                error: 'Erreur récupération actions'
            });
        }

        db.get('SELECT COUNT(*) as total FROM admin_actions', [], (err, count) => {
            res.json({
                success: true,
                actions,
                total: count?.total || 0,
                limit: parseInt(limit),
                offset: parseInt(offset)
            });
        });
    });
});

// GET /admin/tickets — tous les tickets avec username
app.get('/admin/tickets', (req, res) => {
    const { status, limit = 20, offset = 0 } = req.query;
    let query = `SELECT t.*, u.username FROM tickets t JOIN users u ON t.user_id = u.id WHERE 1=1`;
    const params = [];
    if (status) { query += ' AND t.status = ?'; params.push(status); }
    query += ' ORDER BY t.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    db.all(query, params, (err, tickets) => {
        db.get('SELECT COUNT(*) as total FROM tickets' + (status ? ' WHERE status = ?' : ''), status ? [status] : [], (e, count) => {
            res.json({ success: true, tickets: tickets || [], total: count?.total || 0 });
        });
    });
});

// GET /admin/servers/:id
app.get('/admin/servers/:id', (req, res) => {
    db.get(`SELECT s.*, u.username, u.email FROM servers s JOIN users u ON s.user_id = u.id WHERE s.id = ?`, 
        [req.params.id], (err, server) => {
        if (err || !server) return res.status(404).json({ success: false, error: 'Non trouvé' });
        res.json({ success: true, server });
    });
});

// GET /admin/users/:id  
app.get('/admin/users/:id', (req, res) => {
    db.get(`SELECT u.*, 
        (SELECT COUNT(*) FROM servers WHERE user_id = u.id) as server_count,
        (SELECT COUNT(*) FROM transactions WHERE user_id = u.id) as transaction_count,
        (SELECT COUNT(*) FROM deployments WHERE user_id = u.id) as deployment_count,
        (SELECT COUNT(*) FROM github_connections WHERE user_id = u.id) as github_connected
        FROM users u WHERE u.id = ?`, [req.params.id], (err, user) => {
        if (err || !user) return res.status(404).json({ success: false, error: 'Non trouvé' });
        res.json({ success: true, user });
    });
});

// GET /admin/transactions
app.get('/admin/transactions', (req, res) => {
    const { status, limit = 20, offset = 0 } = req.query;
    let query = `SELECT t.*, u.username FROM transactions t LEFT JOIN users u ON t.user_id = u.id WHERE 1=1`;
    const params = [];
    if (status && status !== 'all') { query += ' AND t.status = ?'; params.push(status); }
    query += ' ORDER BY t.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    db.all(query, params, (err, transactions) => {
        db.get('SELECT COUNT(*) as total FROM transactions', [], (e, count) => {
            res.json({ success: true, transactions: transactions || [], total: count?.total || 0 });
        });
    });
});

// GET /admin/transactions/:id
app.get('/admin/transactions/:id', (req, res) => {
    db.get(`SELECT t.*, u.username FROM transactions t LEFT JOIN users u ON t.user_id = u.id WHERE t.id = ?`,
        [req.params.id], (err, transaction) => {
        if (err || !transaction) return res.status(404).json({ success: false, error: 'Non trouvé' });
        res.json({ success: true, transaction });
    });
});

// GET /admin/promo-codes/:id
app.get('/admin/promo-codes/:id', (req, res) => {
    db.get(`SELECT pc.*, u.username as created_by_username FROM promo_codes pc LEFT JOIN users u ON pc.created_by = u.id WHERE pc.id = ?`,
        [req.params.id], (err, code) => {
        if (err || !code) return res.status(404).json({ success: false, error: 'Non trouvé' });
        res.json({ success: true, code });
    });
});

// GET /admin/resellers (accessible via requireInternalAccess)
app.get('/admin/resellers', (req, res) => {
    db.all(`SELECT u.id, u.username, u.email, rp.*,
        (SELECT COUNT(*) FROM reseller_clients WHERE reseller_id = u.id) as clients_count
        FROM reseller_profiles rp JOIN users u ON rp.user_id = u.id
        ORDER BY rp.created_at DESC`, [], (err, resellers) => {
        res.json({ success: true, resellers: resellers || [] });
    });
});

// POST /admin/resellers/:id/activate
app.post('/admin/resellers/:id/activate', (req, res) => {
    db.run(`UPDATE users SET role = 'admin' WHERE id = ?`, [req.params.id]);
    db.run(`UPDATE reseller_profiles SET active = 1 WHERE user_id = ?`, [req.params.id], function(err) {
        logAdminAction(req.body.admin_id || 1, 'activate_reseller', 'reseller', req.params.id, 'Activation revendeur');
        res.json({ success: true });
    });
});

// POST /admin/resellers/:id/deactivate  
app.post('/admin/resellers/:id/deactivate', (req, res) => {
    db.run(`UPDATE users SET role = 'user' WHERE id = ?`, [req.params.id]);
    db.run(`UPDATE reseller_profiles SET active = 0 WHERE user_id = ?`, [req.params.id], function(err) {
        logAdminAction(req.body.admin_id || 1, 'deactivate_reseller', 'reseller', req.params.id, 'Désactivation revendeur');
        res.json({ success: true });
    });
});

// GET /admin/withdrawals
app.get('/admin/withdrawals', (req, res) => {
    db.all(`SELECT wr.*, u.username as reseller_username, rp.business_name
        FROM withdrawal_requests wr 
        JOIN users u ON wr.reseller_id = u.id
        LEFT JOIN reseller_profiles rp ON u.id = rp.user_id
        ORDER BY wr.created_at DESC`, [], (err, withdrawals) => {
        res.json({ success: true, withdrawals: withdrawals || [] });
    });
});

// POST /admin/withdrawals/:id/process
app.post('/admin/withdrawals/:id/process', async (req, res) => {
    const { action, reference, admin_note, admin_id } = req.body;
    const withdrawal = await new Promise(r => db.get('SELECT * FROM withdrawal_requests WHERE id = ?', [req.params.id], (e, row) => r(row)));
    if (!withdrawal) return res.status(404).json({ success: false, error: 'Non trouvé' });
    if (action === 'approved') {
        db.run(`UPDATE withdrawal_requests SET status='approved', processed_by=?, processed_at=CURRENT_TIMESTAMP, reference=?, admin_note=? WHERE id=?`,
            [admin_id, reference, admin_note, req.params.id]);
        db.run('UPDATE reseller_profiles SET total_withdrawn = total_withdrawn + ? WHERE user_id = ?', [withdrawal.amount, withdrawal.reseller_id]);
    } else {
        db.run(`UPDATE withdrawal_requests SET status='rejected', processed_by=?, processed_at=CURRENT_TIMESTAMP, admin_note=? WHERE id=?`,
            [admin_id, admin_note, req.params.id]);
        db.run('UPDATE reseller_profiles SET commission_balance = commission_balance + ? WHERE user_id = ?', [withdrawal.amount, withdrawal.reseller_id]);
    }
    res.json({ success: true, action });
});

app.get('/admin/settings', (req, res) => {
    db.all('SELECT * FROM system_settings ORDER BY key', [], (err, settings) => {
        if (err) {
            return res.status(500).json({
                success: false,
                error: 'Erreur récupération paramètres'
            });
        }

        const settingsObj = {};
        settings.forEach(s => settingsObj[s.key] = s.value);

        res.json({
            success: true,
            settings: settingsObj
        });
    });
});

app.post('/admin/settings', (req, res) => {
    const { key, value, admin_id } = req.body;

    if (!key || !admin_id) {
        return res.status(400).json({
            success: false,
            error: 'Clé et ID admin requis'
        });
    }

    db.run(
        'INSERT OR REPLACE INTO system_settings (key, value, updated_at, updated_by) VALUES (?, ?, CURRENT_TIMESTAMP, ?)',
        [key, value, admin_id],
        function(err) {
            if (err) {
                return res.status(500).json({
                    success: false,
                    error: 'Erreur mise à jour paramètre'
                });
            }

            logAdminAction(admin_id, 'update_setting', 'system', null, `Modification paramètre ${key}=${value}`);

            res.json({
                success: true,
                message: 'Paramètre mis à jour'
            });
        }
    );
});

// =============================================
// AUTRES ROUTES PUBLIQUES
// =============================================

app.get('/api/promo/validate', authenticateToken, (req, res) => {
    const { code } = req.query;

    if (!code) {
        return res.status(400).json({ 
            success: false, 
            valid: false,
            error: 'Code promo requis' 
        });
    }

    // Chercher d'abord dans les codes promo standards
    db.get(
        `SELECT id, server_type, duration_hours, max_uses, current_uses, expires_at 
         FROM promo_codes 
         WHERE code = ? AND is_active = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))`,
        [code],
        (err, promoCode) => {
            if (err) {
                console.error('Erreur validation code promo:', err);
                return res.status(500).json({ 
                    success: false, 
                    valid: false,
                    error: 'Erreur de validation' 
                });
            }

            // Si trouvé dans les codes standards
            if (promoCode) {
                // Vérifier si le code n'a pas atteint sa limite
                if (promoCode.current_uses >= promoCode.max_uses) {
                    return res.json({ 
                        valid: false,
                        error: 'Ce code promo a atteint sa limite d\'utilisations' 
                    });
                }

                return res.json({
                    valid: true,
                    code: promoCode.code,
                    server_type: promoCode.server_type,
                    duration_hours: promoCode.duration_hours,
                    max_uses: promoCode.max_uses,
                    current_uses: promoCode.current_uses,
                    expires_at: promoCode.expires_at,
                    type: 'standard'
                });
            }

            // Si pas trouvé, chercher dans les codes promo revendeur
            db.get(
                `SELECT id, server_type, duration_hours, max_uses, current_uses, expires_at 
                 FROM reseller_promo_codes 
                 WHERE code = ? AND is_active = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))`,
                [code],
                (err, resellerCode) => {
                    if (err) {
                        console.error('Erreur validation code promo revendeur:', err);
                        return res.status(500).json({ 
                            success: false, 
                            valid: false,
                            error: 'Erreur de validation' 
                        });
                    }

                    if (resellerCode) {
                        // Vérifier si le code n'a pas atteint sa limite
                        if (resellerCode.current_uses >= resellerCode.max_uses) {
                            return res.json({ 
                                valid: false,
                                error: 'Ce code promo a atteint sa limite d\'utilisations' 
                            });
                        }

                        return res.json({
                            valid: true,
                            code: code,
                            server_type: resellerCode.server_type,
                            duration_hours: resellerCode.duration_hours,
                            max_uses: resellerCode.max_uses,
                            current_uses: resellerCode.current_uses,
                            expires_at: resellerCode.expires_at,
                            type: 'reseller'
                        });
                    }

                    // Code non trouvé
                    return res.json({ 
                        valid: false,
                        error: 'Code promo invalide ou expiré' 
                    });
                }
            );
        }
    );
});

// Version enrichie qui retourne aussi les infos du plan
app.get('/api/promo/details', authenticateToken, (req, res) => {
    const { code } = req.query;

    db.get(
        `SELECT code, server_type, duration_hours, max_uses, current_uses 
         FROM promo_codes 
         WHERE code = ? AND is_active = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))
         UNION
         SELECT code, server_type, duration_hours, max_uses, current_uses 
         FROM reseller_promo_codes 
         WHERE code = ? AND is_active = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))`,
        [code, code],
        (err, promo) => {
            if (err || !promo) {
                return res.json({ valid: false });
            }

            if (promo.current_uses >= promo.max_uses) {
                return res.json({ 
                    valid: false, 
                    error: 'Limite d\'utilisations atteinte' 
                });
            }

            // Récupérer les détails du plan correspondant
            const planDetails = PLANS_CONFIG[promo.server_type];
            
            res.json({
                valid: true,
                promo: {
                    code: promo.code,
                    server_type: promo.server_type,
                    duration_hours: promo.duration_hours,
                    remaining_uses: promo.max_uses - promo.current_uses
                },
                plan: planDetails ? {
                    memory: planDetails.memory,
                    disk: planDetails.disk,
                    cpu: planDetails.cpu,
                    price_coins: PLAN_COINS_PRICES[promo.server_type]
                } : null
            });
        }
    );
});

app.get('/api/referral/info', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    
    db.get('SELECT referral_code FROM users WHERE id = ?', [userId], (err, user) => {
        if (err || !user) {
            return res.status(404).json({
                success: false,
                error: 'Utilisateur non trouvé',
                code: 'USER_NOT_FOUND'
            });
        }
        
        db.get(
            'SELECT COUNT(*) as count, SUM(coins_rewarded) as total_coins FROM referrals WHERE referrer_id = ?',
            [userId],
            (err, result) => {
                if (err) {
                    return res.status(500).json({
                        success: false,
                        error: 'Erreur base de données',
                        code: 'DATABASE_ERROR'
                    });
                }
                
                db.all(
                    `SELECT u.username, r.created_at, r.coins_rewarded 
                     FROM referrals r
                     JOIN users u ON r.referred_id = u.id
                     WHERE r.referrer_id = ?
                     ORDER BY r.created_at DESC
                     LIMIT 10`,
                    [userId],
                    (err, recent) => {
                        const referralUrl = `${WEB_CONFIG.SITE_URL}/register?ref=${user.referral_code}`;
                        
                        res.json({
                            success: true,
                            referral_code: user.referral_code,
                            referral_url: referralUrl,
                            referral_count: result?.count || 0,
                            total_coins_earned: result?.total_coins || 0,
                            recent_referrals: recent || []
                        });
                    }
                );
            }
        );
    });
});

// ─────────────────────────────────────────────
// UTILS
// ─────────────────────────────────────────────

/**
 * Retourne la date actuelle en format ISO YYYY-MM-DD
 * basée sur l'heure UTC pour éviter les décalages serveur.
 */
function getTodayUTC() {
  return new Date().toISOString().split('T')[0];
}

/**
 * Vérifie si deux dates ISO string sont consécutives (hier/aujourd'hui).
 */
function isConsecutiveDay(previousDateStr, todayStr) {
  if (!previousDateStr) return false;
  const prev = new Date(previousDateStr + 'T00:00:00Z');
  const today = new Date(todayStr + 'T00:00:00Z');
  const diffMs = today - prev;
  const diffDays = diffMs / (1000 * 60 * 60 * 24);
  return diffDays === 1;
}

/**
 * Calcule les heures restantes avant de pouvoir réclamer à nouveau.
 * Retourne 0 si le délai est écoulé.
 */
function getHoursUntilNextClaim(lastClaimDateStr, cooldownHours = 20) {
  if (!lastClaimDateStr) return 0;
  const lastClaim = new Date(lastClaimDateStr + 'T00:00:00Z');
  const nextClaim = new Date(lastClaim.getTime() + cooldownHours * 60 * 60 * 1000);
  const diff = nextClaim - Date.now();
  return diff > 0 ? Math.ceil(diff / (1000 * 60 * 60)) : 0;
}

// ─────────────────────────────────────────────
// HELPERS DB (promisifiés pour un code plus propre)
// ─────────────────────────────────────────────

function dbGet(query, params) {
  return new Promise((resolve, reject) => {
    db.get(query, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}

function dbRun(query, params) {
  return new Promise((resolve, reject) => {
    db.run(query, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

// ─────────────────────────────────────────────
// CALCUL DE LA RÉCOMPENSE
// ─────────────────────────────────────────────

function computeReward({ lastDailyLogin, dailyLoginStreak, totalLoginDays, accountCreated }, today) {
  const todayDate = new Date(today + 'T00:00:00Z');
  const isStreak = isConsecutiveDay(lastDailyLogin, today);

  const streakCount = isStreak ? (dailyLoginStreak || 0) + 1 : 1;

  let coinsReward = 5;
  let bonusApplied = false;
  let specialBonus = 0;

  // Bonus de streak
  if (isStreak) {
    coinsReward += 2;
    bonusApplied = true;
  }

  // Bonus spéciaux
  const accountAgeDays = Math.floor(
    (todayDate - new Date(accountCreated)) / (1000 * 60 * 60 * 24)
  );
  const newTotalDays = (totalLoginDays || 0) + 1;

  if (accountAgeDays === 365) {
    specialBonus = 50;
  } else if (accountAgeDays === 100) {
    specialBonus = 30;
  } else if (newTotalDays % 7 === 0) {
    specialBonus = 10;
  }

  coinsReward += specialBonus;

  return { streakCount, coinsReward, bonusApplied, specialBonus };
}

// ─────────────────────────────────────────────
// POST /api/daily-reward/claim
// ─────────────────────────────────────────────

app.post('/api/daily-reward/claim', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const today = getTodayUTC(); // ✅ Fix principal : date UTC cohérente

  try {
    const user = await dbGet(
      `SELECT last_daily_login, daily_login_streak, total_login_days, account_created
       FROM users WHERE id = ?`,
      [userId]
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'Utilisateur non trouvé',
        code: 'USER_NOT_FOUND',
      });
    }

    // ✅ Vérification propre : même date UTC
    if (user.last_daily_login === today) {
      return res.status(400).json({
        success: false,
        error: "Vous avez déjà réclamé votre récompense aujourd'hui.",
        code: 'DAILY_REWARD_ALREADY_CLAIMED',
      });
    }

    // ✅ Cooldown de 20h basé sur la vraie date/heure du dernier claim
    const hoursLeft = getHoursUntilNextClaim(user.last_daily_login, 20);
    if (hoursLeft > 0) {
      return res.status(400).json({
        success: false,
        error: `Vous devez attendre encore ${hoursLeft} heure${hoursLeft > 1 ? 's' : ''}.`,
        code: 'DAILY_REWARD_TOO_EARLY',
        hours_left: hoursLeft,
      });
    }

    // Calcul de la récompense
    const { streakCount, coinsReward, bonusApplied, specialBonus } = computeReward(user, today);

    // ✅ Mise à jour atomique de l'utilisateur
    await dbRun(
      `UPDATE users
       SET daily_login_streak = ?,
           last_daily_login    = ?,
           total_login_days    = total_login_days + 1,
           coins               = coins + ?
       WHERE id = ?`,
      [streakCount, today, coinsReward, userId]
    );

    // Logs asynchrones (non bloquants)
    dbRun(
      `INSERT INTO daily_rewards (user_id, reward_date, coins_earned, streak_count, bonus_applied)
       VALUES (?, ?, ?, ?, ?)`,
      [userId, today, coinsReward, streakCount, bonusApplied ? 1 : 0]
    ).catch(err => console.error('[daily_rewards insert]', err));

    dbRun(
      `INSERT INTO user_activities (user_id, activity_type, coins_earned, description)
       VALUES (?, ?, ?, ?)`,
      [
        userId,
        'daily_login',
        coinsReward,
        `Récompense quotidienne — Série : ${streakCount} jour${streakCount > 1 ? 's' : ''}${
          specialBonus > 0 ? ` (Bonus : +${specialBonus})` : ''
        }`,
      ]
    ).catch(err => console.error('[user_activities insert]', err));

    updateUserBadges(userId);

    return res.json({
      success: true,
      message: 'Récompense réclamée avec succès !',
      coins_earned: coinsReward,
      streak: streakCount,
      bonus_applied: bonusApplied,
      special_bonus: specialBonus > 0 ? specialBonus : null,
      next_reward_in: '24h',
    });
  } catch (err) {
    console.error('[/api/daily-reward/claim]', err);
    return res.status(500).json({
      success: false,
      error: 'Erreur interne du serveur.',
      code: 'SERVER_ERROR',
    });
  }
});

// ─────────────────────────────────────────────
// GET /api/daily-reward/status
// ─────────────────────────────────────────────

app.get('/api/daily-reward/status', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const today = getTodayUTC(); // ✅ Même référence UTC

  try {
    const user = await dbGet(
      `SELECT last_daily_login, daily_login_streak, total_login_days FROM users WHERE id = ?`,
      [userId]
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'Utilisateur non trouvé',
        code: 'USER_NOT_FOUND',
      });
    }

    const alreadyClaimed = user.last_daily_login === today;
    const hoursLeft = alreadyClaimed ? getHoursUntilNextClaim(user.last_daily_login, 20) : 0;

    // Prévisualisation de la prochaine récompense
    const nextStreakCount = isConsecutiveDay(user.last_daily_login, today)
      ? (user.daily_login_streak || 0) + 1
      : 1;
    const nextCoins = 5 + (nextStreakCount > 1 ? 2 : 0);

    return res.json({
      success: true,
      can_claim: !alreadyClaimed && hoursLeft === 0,
      already_claimed_today: alreadyClaimed,
      current_streak: user.daily_login_streak || 0,
      total_login_days: user.total_login_days || 0,
      hours_until_next: hoursLeft,
      next_reward_at:
        !alreadyClaimed && hoursLeft === 0
          ? 'maintenant'
          : new Date(Date.now() + hoursLeft * 60 * 60 * 1000).toISOString(),
      next_reward_preview: {
        coins: nextCoins,
        streak: nextStreakCount,
      },
    });
  } catch (err) {
    console.error('[/api/daily-reward/status]', err);
    return res.status(500).json({
      success: false,
      error: 'Erreur interne du serveur.',
      code: 'SERVER_ERROR',
    });
  }
});

app.get('/api/leaderboard', (req, res) => {
    db.all(`SELECT username, coins, level, badges, 
            (SELECT COUNT(*) FROM servers WHERE user_id = users.id) as servers,
            daily_login_streak
            FROM users 
            WHERE email_verified = 1
            ORDER BY coins DESC 
            LIMIT 10`, [], (err, users) => {
        res.json({ success: true, leaderboard: users || [] });
    });
});

const MISSIONS = [
    { id: 'first_server', name: 'Premier serveur', reward: 20, condition: 'server_count >= 1' },
    { id: 'streak_7', name: '7 jours de suite', reward: 50, condition: 'streak >= 7' },
    { id: 'invite_5', name: 'Inviter 5 amis', reward: 100, condition: 'referrals >= 5' },
    { id: 'first_deploy', name: 'Premier déploiement', reward: 30, condition: 'deployments >= 1' },
    { id: 'admin_grade', name: 'Devenir Admin', reward: 200, condition: 'role === admin' }
];

app.get('/api/missions', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    
    db.all('SELECT mission_id, completed FROM missions WHERE user_id = ?', [userId], (err, userMissions) => {
        const completedSet = new Set((userMissions || []).map(m => m.mission_id));
        
        Promise.all([
            new Promise(r => db.get('SELECT COUNT(*) as count FROM servers WHERE user_id = ?', [userId], (e, row) => r(row?.count || 0))),
            new Promise(r => db.get('SELECT daily_login_streak FROM users WHERE id = ?', [userId], (e, row) => r(row?.daily_login_streak || 0))),
            new Promise(r => db.get('SELECT COUNT(*) as count FROM referrals WHERE referrer_id = ?', [userId], (e, row) => r(row?.count || 0))),
            new Promise(r => db.get('SELECT COUNT(*) as count FROM deployments WHERE user_id = ?', [userId], (e, row) => r(row?.count || 0))),
            new Promise(r => db.get('SELECT role FROM users WHERE id = ?', [userId], (e, row) => r(row?.role || 'user')))
        ]).then(([servers, streak, referrals, deployments, role]) => {
            const missionsWithStatus = MISSIONS.map(m => {
                let completed = completedSet.has(m.id);
                if (!completed) {
                    if (m.id === 'first_server') completed = servers >= 1;
                    else if (m.id === 'streak_7') completed = streak >= 7;
                    else if (m.id === 'invite_5') completed = referrals >= 5;
                    else if (m.id === 'first_deploy') completed = deployments >= 1;
                    else if (m.id === 'admin_grade') completed = role === 'admin' || role === 'superadmin';
                }
                return { ...m, completed };
            });
            res.json({ success: true, missions: missionsWithStatus });
        });
    });
});

app.post('/api/market/sell-coins', authenticateToken, async (req, res) => {
    const { amount, price_per_coin } = req.body;
    const userId = req.user.userId;
    
    db.get('SELECT coins FROM users WHERE id = ?', [userId], (err, user) => {
        if (err || !user) return res.status(404).json({ success: false, error: 'Utilisateur non trouvé' });
        if (user.coins < amount) return res.status(400).json({ success: false, error: 'Coins insuffisants' });
        
        db.run(`INSERT INTO coin_market (seller_id, amount, price_per_coin, status) 
                VALUES (?, ?, ?, 'active')`,
            [userId, amount, price_per_coin],
            function(err) {
                if (err) return res.status(500).json({ success: false, error: 'Erreur création offre' });
                res.json({ success: true, message: 'Offre créée !' });
            }
        );
    });
});

app.post('/api/tickets', authenticateToken, (req, res) => {
    const { title, subject, description, message, category, priority } = req.body;
    const finalTitle = subject || title || 'Sans titre';
    const finalDesc = message || description || '';
    const finalCategory = category || 'general';
    const finalPriority = priority || 'medium';
    db.run(
        `INSERT INTO tickets (user_id, title, description, category, priority, status) VALUES (?, ?, ?, ?, ?, 'open')`,
        [req.user.userId, finalTitle, finalDesc, finalCategory, finalPriority],
        function(err) {
            if (err) return res.status(500).json({ success: false, error: 'Erreur création ticket' });
            res.json({ success: true, id: this.lastID, ticket_id: this.lastID });
        }
    );
});

app.get('/api/tickets', authenticateToken, (req, res) => {
    db.all(
        `SELECT t.*, u.username FROM tickets t LEFT JOIN users u ON t.user_id = u.id WHERE t.user_id = ? ORDER BY t.created_at DESC`,
        [req.user.userId],
        (err, tickets) => {
            if (err) return res.status(500).json({ success: false, error: err.message });
            const mapped = (tickets || []).map(t => ({
                ...t,
                subject: t.title,
                message: t.description
            }));
            res.json({ success: true, tickets: mapped });
        }
    );
});

app.post('/api/tickets/:id/response', authenticateToken, (req, res) => {
    const { response } = req.body;
    db.run(
        'UPDATE tickets SET admin_response = ?, status = "closed" WHERE id = ?',
        [response, req.params.id],
        function(err) {
            if (err) return res.status(500).json({ success: false, error: 'Erreur' });
            res.json({ success: true });
        }
    );
});

app.get('/api/tickets/:id/replies', authenticateToken, (req, res) => {
    const ticketId = req.params.id;
    db.get('SELECT * FROM tickets WHERE id = ? AND user_id = ?', [ticketId, req.user.userId], (err, ticket) => {
        if (!ticket && req.user.role !== 'admin' && req.user.role !== 'superadmin')
            return res.status(403).json({ success: false, error: 'Accès refusé' });
        db.all(
            `SELECT r.*, u.username, u.role FROM ticket_replies r LEFT JOIN users u ON r.user_id = u.id WHERE r.ticket_id = ? ORDER BY r.created_at ASC`,
            [ticketId],
            (err, replies) => {
                if (err) return res.status(500).json({ success: false, error: err.message });
                const mapped = (replies || []).map(r => ({
                    ...r,
                    author: r.username || 'Utilisateur',
                    content: r.message,
                    role: r.is_admin ? 'admin' : (r.role || 'user')
                }));
                res.json({ success: true, replies: mapped });
            }
        );
    });
});

app.post('/api/tickets/:id/reply', authenticateToken, (req, res) => {
    const ticketId = req.params.id;
    const { message } = req.body;
    if (!message || !message.trim()) return res.status(400).json({ success: false, error: 'Message requis' });
    db.get('SELECT * FROM tickets WHERE id = ?', [ticketId], (err, ticket) => {
        if (!ticket) return res.status(404).json({ success: false, error: 'Ticket introuvable' });
        if (ticket.user_id !== req.user.userId && req.user.role !== 'admin' && req.user.role !== 'superadmin')
            return res.status(403).json({ success: false, error: 'Accès refusé' });
        const isAdmin = req.user.role === 'admin' || req.user.role === 'superadmin' ? 1 : 0;
        db.run(
            'INSERT INTO ticket_replies (ticket_id, user_id, is_admin, message) VALUES (?, ?, ?, ?)',
            [ticketId, req.user.userId, isAdmin, message.trim()],
            function(err2) {
                if (err2) return res.status(500).json({ success: false, error: err2.message });
                if (isAdmin) {
                    db.run('UPDATE tickets SET status = "answered" WHERE id = ?', [ticketId]);
                    // Notifier l'utilisateur qu'un admin a répondu
                    createUserNotification(ticket.user_id,
                        `🎧 Réponse à votre ticket #${ticketId}`,
                        `L'équipe support a répondu à votre ticket "${ticket.title}". Consultez votre réponse.`,
                        'info', '/tickets');
                } else {
                    db.run('UPDATE tickets SET status = "pending" WHERE id = ?', [ticketId]);
                    // Notifier les admins qu'un utilisateur a répondu (broadcast)
                    db.all(`SELECT id FROM users WHERE role IN ('admin','superadmin')`, [], (e, admins) => {
                        (admins || []).forEach(a => createUserNotification(a.id,
                            `🎫 Nouveau message ticket #${ticketId}`,
                            `Un utilisateur a répondu au ticket "${ticket.title}".`,
                            'info', '/tickets'));
                    });
                }
                res.json({ success: true, id: this.lastID });
            }
        );
    });
});

app.get('/api/credits', authenticateToken, (req, res) => {
    db.get('SELECT * FROM user_credits WHERE user_id = ?', [req.user.userId], (err, credits) => {
        res.json({
            success: true,
            credits: {
                balance: credits?.balance || 0,
                total_purchased: credits?.total_purchased || 0,
                currency: 'XOF'
            }
        });
    });
});

app.post('/api/credits/purchase', authenticateToken, async (req, res) => {
    const { amount, phone_number } = req.body;
    
    if (amount < CREDITS_CONFIG.minimum_purchase) {
        return res.status(400).json({
            success: false,
            error: `Minimum d'achat: ${CREDITS_CONFIG.minimum_purchase} XOF`
        });
    }
    
    const paymentId = 'CREDIT_' + crypto.randomBytes(8).toString('hex');
    
    const paymentData = {
        totalPrice: parseInt(amount),
        article: [{
            name: `Achat de crédits FLYHOST`,
            price: parseInt(amount)
        }],
        personal_Info: [{
            userId: req.user.userId,
            paymentId: paymentId,
            type: 'credit_purchase',
            amount: amount
        }],
        numeroSend: phone_number || '',
        nomclient: req.user.username,
        return_url: `${WEB_CONFIG.SITE_URL}/credits/callback?payment_id=${paymentId}`,
        webhook_url: `${WEB_CONFIG.SITE_URL}/api/credits/webhook`
    };
    
    try {
        const response = await fetch(MONEYFUSION_CONFIG.api_url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(paymentData)
        });
        const result = await response.json();
        
        if (result.statut && result.url) {
            res.json({ success: true, paymentUrl: result.url, paymentId });
        } else {
            throw new Error('Erreur MoneyFusion');
        }
    } catch (error) {
        res.status(500).json({ success: false, error: 'Erreur paiement' });
    }
});

app.post('/api/credits/webhook', express.json(), async (req, res) => {
    const { event, tokenPay, Montant, personal_Info } = req.body;
    
    if (event !== 'payin.session.completed') {
        return res.json({ success: true });
    }
    
    const userId = personal_Info[0].userId;
    const amount = parseFloat(Montant);
    
    db.get('SELECT * FROM user_credits WHERE user_id = ?', [userId], (err, credits) => {
        const newBalance = (credits?.balance || 0) + amount;
        
        db.run(`INSERT INTO user_credits (user_id, balance, total_purchased, last_purchase)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(user_id) DO UPDATE SET
                balance = balance + ?,
                total_purchased = total_purchased + ?,
                last_purchase = CURRENT_TIMESTAMP`,
            [userId, amount, amount, amount, amount]
        );
        
        db.run(`INSERT INTO credit_transactions 
                (user_id, type, amount, balance_after, description, payment_id)
                VALUES (?, 'purchase', ?, ?, 'Achat de crédits', ?)`,
            [userId, amount, newBalance, tokenPay]
        );
        
        if (global.sendNotification) {
            global.sendNotification(userId, {
                title: '💰 Crédits ajoutés !',
                message: `${amount} XOF ont été ajoutés à votre compte`,
                type: 'success'
            });
        }
    });
    
    res.json({ success: true });
});

function formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;

    const parts = [];
    if (days > 0) parts.push(`${days}j`);
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    if (secs > 0 || parts.length === 0) parts.push(`${secs}s`);

    return parts.join(' ');
}

app.get('/api/health', (req, res) => {
    db.get('SELECT 1', (err) => {
        const dbStatus = !err;

        res.json({
            success: true,
            status: 'operational',
            timestamp: new Date().toISOString(),
            version: '8.0.0',
            database: dbStatus ? 'connected' : 'disconnected',
            features: {
                authentication: true,
                server_management: true,
                promo_codes: true,
                daily_rewards: true,
                referrals: true,
                api_rate_limiting: true,
                internal_api: true,
                email_notifications: true,
                auto_cleanup: true,
                github_deploy: true,
                zip_deploy: true,
                template_deploy: true,
                websocket_logs: true,
                template_system: true,
                moneyfusion_payments: true,
                admin_grade: true,
                credits: true,
                external_api: true,
                webhooks: true,
                file_editor: true,
                snapshots: true,
                missions: true,
                market: true,
                tickets: true,
                leaderboard: true,
                // Nouvelles fonctionnalités
                reseller_program: true,
                three_tier_api_keys: true,
                bulk_purchasing: true,
                affiliate_system: true,
                commission_tracking: true,
                withdrawal_requests: true,
                reseller_dashboard: true,
                client_management: true,
                superadmin_financial_reports: true
            },
            uptime: process.uptime(),
            memory: process.memoryUsage()
        });
    });
});

app.get('/api/pricing', (req, res) => {
    const pricing = Object.keys(PLANS_CONFIG).map(plan => ({
        name: plan,
        memory: PLANS_CONFIG[plan].memory,
        disk: PLANS_CONFIG[plan].disk,
        cpu: PLANS_CONFIG[plan].cpu,
        price: PLAN_COINS_PRICES[plan],
        duration_days: plan === 'free' ? 1 : PLANS_CONFIG[plan].duration,
        api_calls_per_day: PLANS_CONFIG[plan].api_calls_per_day,
        max_servers: PLANS_CONFIG[plan].max_servers
    }));
    
    res.json({
        success: true,
        pricing
    });
});

app.get('/api/public/stats', (req, res) => {
    Promise.all([
        new Promise(r => db.get('SELECT COUNT(*) as total FROM users', [], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM servers WHERE is_active = 1', [], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM servers', [], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT SUM(amount) as total FROM transactions WHERE status = "completed"', [], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM deployments', [], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT COUNT(*) as total FROM panels', [], (e, row) => r(row?.total || 0))),
        // Stats revendeur publiques
        new Promise(r => db.get('SELECT COUNT(*) as total FROM reseller_profiles WHERE active = 1', [], (e, row) => r(row?.total || 0))),
        new Promise(r => db.get('SELECT SUM(commission_balance) as total FROM reseller_profiles', [], (e, row) => r(row?.total || 0)))
    ]).then(([users, activeServers, totalServers, revenue, totalDeployments, totalPanels, activeResellers, totalResellerBalance]) => {
        res.json({
            success: true,
            stats: {
                total_users: users,
                active_servers: activeServers,
                total_servers_created: totalServers,
                total_deployments: totalDeployments,
                total_panels: totalPanels,
                total_revenue: revenue,
                active_resellers: activeResellers,
                total_reseller_earnings: totalResellerBalance,
                uptime: '99.9%'
            }
        });
    });
});

// =============================================
// ROUTES STATIQUES
// =============================================

// Serve the animated demo reel video (graceful if not built)
const demoDist = path.join(__dirname, 'flyhost-demo-dist');
if (fs.existsSync(demoDist)) {
    app.use('/flyhost-demo', express.static(demoDist));
    app.get('/flyhost-demo', (req, res) => res.sendFile(path.join(demoDist, 'index.html')));
} else {
    app.get('/flyhost-demo*', (req, res) => res.status(404).send('Demo not built'));
}

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));
app.get('/root', (req, res) => res.sendFile(path.join(__dirname, 'superadmin.html')));
app.get('/reseller', (req, res) => res.sendFile(path.join(__dirname, 'panel-admin.html')));
app.get('/dev', (req, res) => res.sendFile(path.join(__dirname, 'info.html')));
app.get('/info', (req, res) => res.sendFile(path.join(__dirname, 'info.html')));
app.get('/payment', (req, res) => res.sendFile(path.join(__dirname, 'payment.html')));
app.get('/profile', (req, res) => res.sendFile(path.join(__dirname, 'profile.html')));
app.get('/server', (req, res) => res.sendFile(path.join(__dirname, 'server.html')));
app.get('/forgot-password', (req, res) => res.sendFile(path.join(__dirname, 'forgot-password.html')));
app.get('/payment-success', (req, res) => res.sendFile(path.join(__dirname, 'payment-success.html')));
app.get('/payment-cancel', (req, res) => res.sendFile(path.join(__dirname, 'payment-cancel.html')));
app.get('/payment-pending', (req, res) => res.sendFile(path.join(__dirname, 'payment-pending.html')));
app.get('/email-verification', (req, res) => res.sendFile(path.join(__dirname, 'email-verification.html')));
app.get('/api-keys', (req, res) => res.sendFile(path.join(__dirname, 'api.html')));
app.get('/chat', (req, res) => res.sendFile(path.join(__dirname, 'chat.html')));
app.get('/pricing', (req, res) => res.sendFile(path.join(__dirname, 'pricing.html')));
app.get('/deploy', (req, res) => res.sendFile(path.join(__dirname, 'deploy.html')));
app.get('/panel-admin', (req, res) => res.sendFile(path.join(__dirname, 'panel-admin.html')));
app.get('/referral', (req, res) => res.sendFile(path.join(__dirname, 'referral.html')));
app.get('/reseller-contract', (req, res) => res.sendFile(path.join(__dirname, 'reseller-contract.html')));
app.get('/status', (req, res) => res.sendFile(path.join(__dirname, 'status.html')));
app.get('/history', (req, res) => res.sendFile(path.join(__dirname, 'history.html')));

// =============================================
// NOUVELLES ROUTES V2
// =============================================

// ---- ANNONCES ----
app.get('/api/announcements', (req, res) => {
    db.all(
        `SELECT * FROM announcements WHERE active = 1 AND (expires_at IS NULL OR expires_at > datetime('now')) ORDER BY created_at DESC`,
        [], (err, rows) => res.json({ success: true, announcements: rows || [] })
    );
});
app.post('/api/admin/announcements', authenticateToken, requireAdmin, (req, res) => {
    const { title, message, type = 'info', expires_at } = req.body;
    if (!title || !message) return res.status(400).json({ success: false, error: 'title et message requis' });
    db.run('INSERT INTO announcements (title, message, type, expires_at, created_by) VALUES (?,?,?,?,?)',
        [title, message, type, expires_at || null, req.user?.userId || null],
        function(err) {
            if (err) return res.status(500).json({ success: false, error: err.message });
            res.json({ success: true, id: this.lastID });
        }
    );
});
app.delete('/api/admin/announcements/:id', authenticateToken, requireAdmin, (req, res) => {
    db.run('UPDATE announcements SET active = 0 WHERE id = ?', [req.params.id],
        err => res.json({ success: !err, error: err?.message })
    );
});

// =============================================
// PROMOTIONS / RÉDUCTIONS VISUELLES
// =============================================

// Créer la table promotions si nécessaire
db.run(`CREATE TABLE IF NOT EXISTS promotions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    subtitle TEXT,
    discount_percent INTEGER DEFAULT 0,
    server_type TEXT,
    original_price INTEGER,
    promo_price INTEGER,
    badge_text TEXT DEFAULT 'PROMO',
    color_scheme TEXT DEFAULT 'purple',
    cta_text TEXT DEFAULT 'En profiter',
    cta_url TEXT DEFAULT '/pricing',
    show_countdown BOOLEAN DEFAULT 1,
    display_type TEXT DEFAULT 'banner',
    active BOOLEAN DEFAULT 1,
    pinned BOOLEAN DEFAULT 0,
    starts_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    ends_at DATETIME,
    created_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// GET /api/promotions — public
app.get('/api/promotions', (req, res) => {
    db.all(
        `SELECT * FROM promotions WHERE active = 1
         AND (starts_at IS NULL OR starts_at <= datetime('now'))
         AND (ends_at IS NULL OR ends_at > datetime('now'))
         ORDER BY pinned DESC, created_at DESC`,
        [], (err, rows) => res.json({ success: true, promotions: rows || [] })
    );
});

// POST /api/admin/promotions — créer
app.post('/api/admin/promotions', authenticateToken, requireAdmin, (req, res) => {
    const { title, subtitle, discount_percent = 0, server_type, original_price, promo_price,
            badge_text = 'PROMO', color_scheme = 'purple', cta_text = 'En profiter',
            cta_url = '/pricing', show_countdown = 1, display_type = 'banner',
            pinned = 0, ends_at } = req.body;
    if (!title) return res.status(400).json({ success: false, error: 'title requis' });
    db.run(`INSERT INTO promotions (title, subtitle, discount_percent, server_type, original_price,
            promo_price, badge_text, color_scheme, cta_text, cta_url, show_countdown,
            display_type, pinned, ends_at, created_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [title, subtitle||null, discount_percent, server_type||null, original_price||null,
         promo_price||null, badge_text, color_scheme, cta_text, cta_url,
         show_countdown?1:0, display_type, pinned?1:0, ends_at||null, req.user?.userId||null],
        function(err) {
            if (err) return res.status(500).json({ success: false, error: err.message });
            const newId = this.lastID;
            // Auto-broadcast push notification à tous les utilisateurs
            const planLabel = server_type ? {
                free:'Starter', '1gb':'1 GB', '2gb':'2 GB', '4gb':'4 GB',
                '8gb':'8 GB', unlimited:'Unlimited', admin:'Admin'
            }[server_type] || server_type : 'tous les plans';
            const notifTitle = `🔥 ${badge_text || 'PROMO'} — ${title}`;
            const notifMsg = discount_percent > 0
                ? `-${discount_percent}% sur ${planLabel} ! ${subtitle || 'Offre limitée.'}`
                : subtitle || 'Nouvelle promotion disponible sur FLYHOST !';
            db.all('SELECT id FROM users', [], (e2, users) => {
                if (e2 || !users) return;
                const stmt = db.prepare(
                    'INSERT INTO user_notifications (user_id, title, message, type, link) VALUES (?,?,?,?,?)'
                );
                users.forEach(u => stmt.run(u.id, notifTitle, notifMsg, 'success', cta_url || '/pricing'));
                stmt.finalize();
            });
            res.json({ success: true, id: newId });
        }
    );
});

// PUT /api/admin/promotions/:id — modifier
app.put('/api/admin/promotions/:id', authenticateToken, requireAdmin, (req, res) => {
    const { title, subtitle, discount_percent, server_type, original_price, promo_price,
            badge_text, color_scheme, cta_text, cta_url, show_countdown, display_type,
            pinned, ends_at, active } = req.body;
    db.run(`UPDATE promotions SET title=COALESCE(?,title), subtitle=COALESCE(?,subtitle),
            discount_percent=COALESCE(?,discount_percent), server_type=COALESCE(?,server_type),
            original_price=COALESCE(?,original_price), promo_price=COALESCE(?,promo_price),
            badge_text=COALESCE(?,badge_text), color_scheme=COALESCE(?,color_scheme),
            cta_text=COALESCE(?,cta_text), cta_url=COALESCE(?,cta_url),
            show_countdown=COALESCE(?,show_countdown), display_type=COALESCE(?,display_type),
            pinned=COALESCE(?,pinned), ends_at=COALESCE(?,ends_at),
            active=COALESCE(?,active) WHERE id=?`,
        [title||null, subtitle||null, discount_percent!=null?discount_percent:null,
         server_type||null, original_price!=null?original_price:null,
         promo_price!=null?promo_price:null, badge_text||null, color_scheme||null,
         cta_text||null, cta_url||null,
         show_countdown!=null?show_countdown:null, display_type||null,
         pinned!=null?pinned:null, ends_at||null, active!=null?active:null,
         req.params.id],
        err => res.json({ success: !err, error: err?.message })
    );
});

// DELETE /api/admin/promotions/:id
app.delete('/api/admin/promotions/:id', authenticateToken, requireAdmin, (req, res) => {
    db.run('UPDATE promotions SET active = 0 WHERE id = ?', [req.params.id],
        err => res.json({ success: !err, error: err?.message })
    );
});

// ---- NOTIFICATIONS UTILISATEUR ----
app.get('/api/user/notifications', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    db.all('SELECT * FROM user_notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
        [userId], (err, rows) => res.json({ success: true, notifications: rows || [] }));
});

app.get('/api/user/notifications/unread-count', authenticateToken, (req, res) => {
    db.get('SELECT COUNT(*) as cnt FROM user_notifications WHERE user_id = ? AND is_read = 0',
        [req.user.userId], (err, row) => res.json({ success: true, count: row?.cnt || 0 }));
});

app.put('/api/user/notifications/:id/read', authenticateToken, (req, res) => {
    db.run('UPDATE user_notifications SET is_read = 1 WHERE id = ? AND user_id = ?',
        [req.params.id, req.user.userId], err => res.json({ success: !err }));
});

app.put('/api/user/notifications/read-all', authenticateToken, (req, res) => {
    db.run('UPDATE user_notifications SET is_read = 1 WHERE user_id = ?',
        [req.user.userId], err => res.json({ success: !err }));
});

// ---- BROADCAST — MESSAGE GROUPÉ ADMIN ----
app.post('/api/admin/broadcast/notification', authenticateToken, requireSuperAdmin, async (req, res) => {
    const { title, message, type = 'info', link, target = 'all' } = req.body;
    if (!title || !message) return res.status(400).json({ success: false, error: 'title et message requis' });
    try {
        let query = 'SELECT id FROM users WHERE 1=1';
        const params = [];
        if (target === 'active') { query += ' AND (SELECT COUNT(*) FROM servers WHERE user_id = users.id AND is_active = 1) > 0'; }
        const users = await new Promise(resolve => db.all(query, params, (e, r) => resolve(r || [])));
        const stmt = db.prepare('INSERT INTO user_notifications (user_id, title, message, type, link) VALUES (?,?,?,?,?)');
        users.forEach(u => stmt.run([u.id, title, message, type, link || null]));
        stmt.finalize();
        auditLog(req, 'broadcast_notification', 'system', null, `"${title}" → ${users.length} utilisateurs`);
        res.json({ success: true, sent_to: users.length, message: `Notification envoyée à ${users.length} utilisateur(s)` });
    } catch(e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/admin/broadcast/email', authenticateToken, requireSuperAdmin, async (req, res) => {
    const { subject, message, type = 'info', target = 'all', also_announce = false, announce_title } = req.body;
    if (!subject || !message) return res.status(400).json({ success: false, error: 'subject et message requis' });
    const typeEmojis = { info: 'ℹ️', warning: '⚠️', success: '✅', incident: '🔴', maintenance: '🔧' };
    const emoji = typeEmojis[type] || 'ℹ️';
    try {
        let query = 'SELECT id, email, username FROM users WHERE email IS NOT NULL AND email != ""';
        if (target === 'active') { query += ' AND (SELECT COUNT(*) FROM servers WHERE user_id = users.id AND is_active = 1) > 0'; }
        const users = await new Promise(resolve => db.all(query, [], (e, r) => resolve(r || [])));
        let sent = 0, failed = 0;
        const htmlTemplate = (username) => `
        <div style="font-family:'Segoe UI',sans-serif;max-width:600px;margin:0 auto;background:#0f172a;border-radius:16px;overflow:hidden;">
            <div style="background:linear-gradient(135deg,#6366f1,#8b5cf6);padding:28px 32px;text-align:center;">
                <div style="font-size:32px;margin-bottom:8px;">${emoji}</div>
                <h1 style="color:#fff;font-size:22px;margin:0;font-weight:800;">${subject}</h1>
            </div>
            <div style="padding:28px 32px;color:#e2e8f0;">
                <p style="margin:0 0 12px;">Bonjour <strong>${username}</strong>,</p>
                <div style="background:#1e293b;border-radius:12px;padding:20px;white-space:pre-wrap;color:#e2e8f0;line-height:1.6;">${message}</div>
                <p style="margin:20px 0 0;color:#94a3b8;font-size:13px;">— L'équipe FLYHOST</p>
            </div>
        </div>`;
        for (const user of users) {
            try { await sendEmail(user.email, `${emoji} ${subject}`, htmlTemplate(user.username)); sent++; }
            catch(e) { failed++; }
            // Petite pause pour éviter le spam throttle
            if (sent % 10 === 0) await new Promise(r => setTimeout(r, 200));
        }
        // Créer aussi une annonce en app si demandé
        if (also_announce && announce_title) {
            await new Promise(resolve => db.run(
                'INSERT INTO announcements (title, message, type, created_by) VALUES (?,?,?,?)',
                [announce_title, subject + ' — ' + message.slice(0, 200), type, req.user.userId], resolve
            ));
        }
        auditLog(req, 'broadcast_email', 'system', null, `"${subject}" → ${sent} envoyés, ${failed} échecs`);
        res.json({ success: true, sent, failed, total: users.length, message: `Email envoyé à ${sent}/${users.length} utilisateur(s)` });
    } catch(e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/admin/broadcast/history', authenticateToken, requireSuperAdmin, (req, res) => {
    db.all(`SELECT al.*, u.username as admin_name FROM admin_audit_logs al 
            LEFT JOIN users u ON al.admin_id = u.id
            WHERE al.action IN ('broadcast_email','broadcast_notification','create_announcement')
            ORDER BY al.created_at DESC LIMIT 50`,
        [], (err, rows) => res.json({ success: true, history: rows || [] }));
});

// ---- PAGE DE STATUT PUBLIC ----
app.get('/api/status', async (req, res) => {
    try {
        const stats = await new Promise((resolve) => {
            db.get(`SELECT
                (SELECT COUNT(*) FROM users) as total_users,
                (SELECT COUNT(*) FROM servers WHERE is_active = 1) as active_servers,
                (SELECT COUNT(*) FROM servers WHERE server_status = 'running') as running_servers,
                (SELECT COUNT(*) FROM deployments WHERE status = 'success') as total_deployments,
                (SELECT COUNT(*) FROM transactions WHERE status = 'completed') as total_payments
            `, [], (err, row) => resolve(row || {}));
        });
        const incidents = await new Promise((resolve) => {
            db.all(`SELECT * FROM announcements WHERE type = 'incident' AND active = 1 ORDER BY created_at DESC LIMIT 5`,
                [], (err, rows) => resolve(rows || []));
        });
        let panelOnline = false;
        try {
            const r = await callPterodactylAPI('/api/application/users?per_page=1', 'GET');
            panelOnline = !!r;
        } catch(e) {}
        res.json({ success: true, stats, incidents, panel_online: panelOnline, api_online: true, timestamp: new Date().toISOString() });
    } catch(e) {
        res.json({ success: false, error: e.message });
    }
});

// ---- HISTORIQUE DES TRANSACTIONS ----
app.get('/api/history', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const { type, limit = 50, offset = 0 } = req.query;
    let query = `SELECT * FROM user_activities WHERE user_id = ?`;
    const params = [userId];
    if (type) { query += ' AND activity_type = ?'; params.push(type); }
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    db.all(query, params, (err, rows) => {
        db.get('SELECT COUNT(*) as total FROM user_activities WHERE user_id = ?', [userId], (e, c) => {
            res.json({ success: true, history: rows || [], total: c?.total || 0 });
        });
    });
});

// ---- RÉPONSES TICKETS ----
app.get('/api/tickets/:id/replies', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.all(
        `SELECT tr.*, CASE WHEN tr.is_admin = 1 THEN 'Support FLYHOST' ELSE u.username END as sender_name
         FROM ticket_replies tr LEFT JOIN users u ON tr.user_id = u.id
         WHERE tr.ticket_id = ? ORDER BY tr.created_at ASC`,
        [id], (err, rows) => res.json({ success: true, replies: rows || [] })
    );
});
app.post('/api/tickets/:id/reply', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { message } = req.body;
    const userId = req.user.userId;
    if (!message?.trim()) return res.status(400).json({ success: false, error: 'Message requis' });
    db.run('INSERT INTO ticket_replies (ticket_id, user_id, is_admin, message) VALUES (?,?,0,?)',
        [id, userId, message.trim()], function(err) {
            if (err) return res.status(500).json({ success: false, error: err.message });
            db.run('UPDATE tickets SET status = ?, replied_at = CURRENT_TIMESTAMP WHERE id = ?', ['waiting', id]);
            res.json({ success: true, id: this.lastID });
        }
    );
});
app.post('/admin/tickets/:id/reply', authenticateToken, requireAdmin, (req, res) => {
    const { id } = req.params;
    const { message, status = 'answered' } = req.body;
    if (!message?.trim()) return res.status(400).json({ success: false, error: 'Message requis' });
    db.run('INSERT INTO ticket_replies (ticket_id, user_id, is_admin, message) VALUES (?,?,1,?)',
        [id, req.user?.userId || null, message.trim()], function(err) {
            if (err) return res.status(500).json({ success: false, error: err.message });
            db.run('UPDATE tickets SET status = ?, admin_reply = ?, replied_at = CURRENT_TIMESTAMP WHERE id = ?',
                [status, message.trim(), id]);
            res.json({ success: true });
        }
    );
});
app.put('/admin/tickets/:id/status', authenticateToken, requireAdmin, (req, res) => {
    const { status } = req.body;
    db.run('UPDATE tickets SET status = ? WHERE id = ?', [status, req.params.id],
        err => res.json({ success: !err, error: err?.message })
    );
});

// ---- AUTO-RENOUVELLEMENT ----
app.post('/api/servers/:serverId/auto-renew', authenticateToken, (req, res) => {
    const { serverId } = req.params;
    const { enabled } = req.body;
    db.run('UPDATE servers SET auto_renew = ? WHERE id = ? AND user_id = ?',
        [enabled ? 1 : 0, serverId, req.user.userId],
        err => res.json({ success: !err, error: err?.message })
    );
});

// ---- BACKUP PLANIFIÉ ----
app.post('/api/servers/:serverId/backup-schedule', authenticateToken, (req, res) => {
    const { serverId } = req.params;
    const { schedule } = req.body;
    const valid = ['hourly', 'daily', 'weekly', null];
    if (!valid.includes(schedule)) return res.status(400).json({ success: false, error: 'Valeur invalide' });
    db.run('UPDATE servers SET backup_schedule = ? WHERE id = ? AND user_id = ?',
        [schedule, serverId, req.user.userId],
        err => res.json({ success: !err, error: err?.message })
    );
});

// ---- GRAPHIQUES DE REVENUS (superadmin) ----
app.get('/api/admin/revenue-chart', authenticateToken, requireSuperAdmin, (req, res) => {
    const days = parseInt(req.query.days) || 30;
    db.all(
        `SELECT date(created_at) as day, SUM(amount) as revenue, COUNT(*) as count
         FROM transactions WHERE status = 'completed' AND created_at >= date('now', '-' || ? || ' days')
         GROUP BY date(created_at) ORDER BY day ASC`,
        [days], (err, rows) => {
            db.get(`SELECT SUM(amount) as total FROM transactions WHERE status = 'completed' AND created_at >= date('now', '-' || ? || ' days')`,
                [days], (e2, total) => {
                    res.json({ success: true, chart: rows || [], total: total?.total || 0, days });
                }
            );
        }
    );
});

// ---- GRAPHIQUES REVENUS RESELLER ----
app.get('/api/reseller/revenue-chart', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const days = parseInt(req.query.days) || 30;
    db.all(
        `SELECT date(cl.created_at) as day, SUM(cl.amount) as revenue, COUNT(*) as count
         FROM commission_logs cl WHERE cl.reseller_id = ? AND cl.created_at >= date('now', '-' || ? || ' days')
         GROUP BY date(cl.created_at) ORDER BY day ASC`,
        [userId, days], (err, rows) => {
            db.get(`SELECT SUM(amount) as total FROM commission_logs WHERE reseller_id = ? AND created_at >= date('now', '-' || ? || ' days')`,
                [userId, days], (e2, total) => {
                    res.json({ success: true, chart: rows || [], total: total?.total || 0, days });
                }
            );
        }
    );
});

// ---- RESELLER TICKETS (clients du revendeur) ----
app.get('/api/reseller/tickets', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    db.all(
        `SELECT t.*, u.username FROM tickets t
         JOIN users u ON t.user_id = u.id
         JOIN reseller_clients rc ON rc.client_id = t.user_id AND rc.reseller_id = ?
         ORDER BY t.created_at DESC LIMIT 50`,
        [userId], (err, rows) => {
            if (err) return res.status(500).json({ success: false, error: err.message });
            res.json({ success: true, tickets: rows || [] });
        }
    );
});

// ---- CUSTOM TEMPLATES (resellers) ----
app.get('/api/reseller/templates', authenticateToken, (req, res) => {
    db.all('SELECT * FROM custom_templates WHERE reseller_id = ? ORDER BY created_at DESC', [req.user.userId],
        (err, rows) => res.json({ success: true, templates: rows || [] })
    );
});
app.post('/api/reseller/templates', authenticateToken, (req, res) => {
    const { name, description, category, game, ram_mb, disk_mb, cpu, docker_image, startup, env_vars } = req.body;
    if (!name || !game) return res.status(400).json({ success: false, error: 'name et game requis' });
    db.run(
        `INSERT INTO custom_templates (reseller_id, name, description, category, game, ram_mb, disk_mb, cpu, docker_image, startup, env_vars)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
        [req.user.userId, name, description, category, game, ram_mb||512, disk_mb||1024, cpu||100, docker_image, startup, env_vars ? JSON.stringify(env_vars) : null],
        function(err) {
            if (err) return res.status(500).json({ success: false, error: err.message });
            res.json({ success: true, id: this.lastID });
        }
    );
});
app.put('/api/reseller/templates/:id', authenticateToken, (req, res) => {
    const { name, description, category, ram_mb, disk_mb, cpu, startup, env_vars } = req.body;
    db.run(
        `UPDATE custom_templates SET name=?, description=?, category=?, ram_mb=?, disk_mb=?, cpu=?, startup=?, env_vars=?, updated_at=CURRENT_TIMESTAMP
         WHERE id=? AND reseller_id=?`,
        [name, description, category, ram_mb, disk_mb, cpu, startup, env_vars ? JSON.stringify(env_vars) : null, req.params.id, req.user.userId],
        err => res.json({ success: !err, error: err?.message })
    );
});
app.delete('/api/reseller/templates/:id', authenticateToken, (req, res) => {
    db.run('DELETE FROM custom_templates WHERE id = ? AND reseller_id = ?', [req.params.id, req.user.userId],
        err => res.json({ success: !err, error: err?.message })
    );
});
app.get('/api/templates/public/:resellerId', (req, res) => {
    db.all('SELECT id, name, description, category, game, ram_mb, disk_mb, cpu FROM custom_templates WHERE reseller_id = ? AND is_public = 1',
        [req.params.resellerId], (err, rows) => res.json({ success: true, templates: rows || [] })
    );
});

// ---- AUTO-RENEW + BACKUP STATUS dans GET server ----
app.get('/api/servers/:serverId/settings', authenticateToken, (req, res) => {
    db.get('SELECT auto_renew, backup_schedule, last_backup_at FROM servers WHERE id = ? AND user_id = ?',
        [req.params.serverId, req.user.userId],
        (err, row) => {
            if (err || !row) return res.status(404).json({ success: false, error: 'Non trouvé' });
            res.json({ success: true, settings: row });
        }
    );
});

// =============================================
// V3 - NOUVELLES FONCTIONNALITÉS
// =============================================

// ---- AUDIT LOG HELPER ----
function auditLog(req, action, targetType, targetId, details) {
    try {
        const adminId = req.user?.userId || null;
        db.get('SELECT username FROM users WHERE id = ?', [adminId], (err, row) => {
            db.run('INSERT INTO admin_audit_logs (admin_id, admin_name, action, target_type, target_id, details, ip) VALUES (?,?,?,?,?,?,?)',
                [adminId, row?.username || 'system', action, targetType, targetId, JSON.stringify(details), req.ip]);
        });
    } catch(e) {}
}

// ---- SERVER ACTIVITY LOG HELPER ----
function serverLog(serverId, userId, action, details) {
    db.run('INSERT INTO server_activity_logs (server_id, user_id, action, details) VALUES (?,?,?,?)',
        [serverId, userId, action, details]);
}

// ---- AUDIT LOG API ----
app.get('/api/admin/audit-logs', authenticateToken, requireSuperAdmin, (req, res) => {
    const { limit = 100, offset = 0, action } = req.query;
    let q = 'SELECT * FROM admin_audit_logs';
    const params = [];
    if (action) { q += ' WHERE action LIKE ?'; params.push(`%${action}%`); }
    q += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    db.all(q, params, (err, rows) => res.json({ success: true, logs: rows || [] }));
});

// ---- HISTORIQUE TRANSACTIONS COINS (ADMIN) ----
app.get('/api/admin/coin-transactions', authenticateToken, requireSuperAdmin, (req, res) => {
    const { limit = 100, offset = 0, user_id, type } = req.query;
    let q = `SELECT ct.*, u.username, u.email FROM coin_transactions ct JOIN users u ON ct.user_id = u.id`;
    const params = [];
    const conds = [];
    if (user_id) { conds.push('ct.user_id = ?'); params.push(user_id); }
    if (type) { conds.push('ct.type = ?'); params.push(type); }
    if (conds.length) q += ' WHERE ' + conds.join(' AND ');
    q += ' ORDER BY ct.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    db.all(q, params, (err, rows) => res.json({ success: true, transactions: rows || [] }));
});

// ---- EXPORT CSV ----
app.get('/api/admin/export/users.csv', authenticateToken, requireSuperAdmin, (req, res) => {
    auditLog(req, 'EXPORT_USERS_CSV', 'system', null, {});
    db.all('SELECT id, username, email, role, coins, current_plan, created_at, last_login FROM users ORDER BY created_at DESC', [], (err, rows) => {
        if (err) return res.status(500).json({ success: false });
        const header = 'ID,Username,Email,Role,Coins,Plan,Créé le,Dernière connexion\n';
        const csv = header + (rows || []).map(r =>
            `${r.id},"${r.username}","${r.email}","${r.role}",${r.coins},"${r.current_plan}","${r.created_at}","${r.last_login || ''}"`
        ).join('\n');
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="flyhost_users.csv"');
        res.send(csv);
    });
});

app.get('/api/admin/export/transactions.csv', authenticateToken, requireSuperAdmin, (req, res) => {
    auditLog(req, 'EXPORT_TRANSACTIONS_CSV', 'system', null, {});
    db.all(`SELECT t.id, u.username, u.email, t.amount, t.currency, t.description, t.status, t.created_at
            FROM transactions t LEFT JOIN users u ON t.user_id = u.id
            ORDER BY t.created_at DESC LIMIT 10000`, [], (err, rows) => {
        if (err) return res.status(500).json({ success: false });
        const header = 'ID,Username,Email,Montant,Devise,Description,Statut,Date\n';
        const csv = header + (rows || []).map(r =>
            `${r.id},"${r.username || ''}","${r.email || ''}",${r.amount},"${r.currency}","${(r.description || '').replace(/"/g, "'")}","${r.status}","${r.created_at}"`
        ).join('\n');
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="flyhost_transactions.csv"');
        res.send(csv);
    });
});

// ---- CLASSEMENT REVENDEURS ----
app.get('/api/leaderboard/resellers', (req, res) => {
    db.all(`SELECT u.id, u.username, u.role,
            COUNT(DISTINCT rc.client_id) as clients,
            COALESCE(SUM(cl.amount),0) as total_revenue,
            COUNT(DISTINCT cl.id) as total_commissions
            FROM users u
            LEFT JOIN reseller_clients rc ON u.id = rc.reseller_id
            LEFT JOIN commission_logs cl ON u.id = cl.reseller_id
            WHERE u.role IN ('reseller','admin','superadmin')
            GROUP BY u.id ORDER BY total_revenue DESC LIMIT 20`,
        [], (err, rows) => res.json({ success: true, leaderboard: rows || [] }));
});

// ---- FORUM ----
app.get('/api/forum/threads', (req, res) => {
    const { category, limit = 30, offset = 0 } = req.query;
    let q = `SELECT ft.*, u.username as author_name FROM forum_threads ft LEFT JOIN users u ON ft.author_id = u.id`;
    const params = [];
    if (category && category !== 'all') { q += ' WHERE ft.category = ?'; params.push(category); }
    q += ' ORDER BY ft.pinned DESC, ft.last_reply_at DESC, ft.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    db.all(q, params, (err, rows) => res.json({ success: true, threads: rows || [] }));
});

app.post('/api/forum/threads', authenticateToken, (req, res) => {
    const { title, category = 'general', content } = req.body;
    if (!title?.trim() || !content?.trim()) return res.status(400).json({ success: false, error: 'Titre et contenu requis' });
    const userId = req.user.userId;
    db.run('INSERT INTO forum_threads (title, category, author_id, last_reply_at) VALUES (?,?,?,?)',
        [title.trim(), category, userId, new Date().toISOString()], function(err) {
            if (err) return res.status(500).json({ success: false, error: err.message });
            const threadId = this.lastID;
            db.run('INSERT INTO forum_posts (thread_id, author_id, content) VALUES (?,?,?)',
                [threadId, userId, content.trim()], () => res.json({ success: true, id: threadId }));
        });
});

app.get('/api/forum/threads/:id', (req, res) => {
    const { id } = req.params;
    db.run('UPDATE forum_threads SET views = views + 1 WHERE id = ?', [id]);
    db.get('SELECT ft.*, u.username as author_name FROM forum_threads ft LEFT JOIN users u ON ft.author_id = u.id WHERE ft.id = ?', [id], (err, thread) => {
        if (err || !thread) return res.status(404).json({ success: false, error: 'Non trouvé' });
        db.all('SELECT fp.*, u.username as author_name FROM forum_posts fp LEFT JOIN users u ON fp.author_id = u.id WHERE fp.thread_id = ? ORDER BY fp.created_at ASC', [id], (e2, posts) => {
            res.json({ success: true, thread, posts: posts || [] });
        });
    });
});

app.post('/api/forum/threads/:id/reply', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { content } = req.body;
    if (!content?.trim()) return res.status(400).json({ success: false, error: 'Contenu requis' });
    db.get('SELECT locked FROM forum_threads WHERE id = ?', [id], (err, thread) => {
        if (!thread || thread.locked) return res.status(403).json({ success: false, error: 'Thread fermé ou inexistant' });
        db.run('INSERT INTO forum_posts (thread_id, author_id, content) VALUES (?,?,?)',
            [id, req.user.userId, content.trim()], function(err2) {
                if (err2) return res.status(500).json({ success: false });
                db.run('UPDATE forum_threads SET replies_count = replies_count + 1, last_reply_at = ? WHERE id = ?', [new Date().toISOString(), id]);
                res.json({ success: true, id: this.lastID });
            });
    });
});

app.delete('/api/forum/threads/:id', authenticateToken, requireSuperAdmin, (req, res) => {
    db.run('DELETE FROM forum_posts WHERE thread_id = ?', [req.params.id]);
    db.run('DELETE FROM forum_threads WHERE id = ?', [req.params.id], err => res.json({ success: !err }));
});

// ---- SERVER ACTIVITY LOGS ----
app.get('/api/servers/:serverId/activity', authenticateToken, (req, res) => {
    const { serverId } = req.params;
    db.get('SELECT id, user_id FROM servers WHERE id = ? AND user_id = ?', [serverId, req.user.userId], (err, srv) => {
        if (!srv) return res.status(403).json({ success: false, error: 'Non autorisé' });
        db.all('SELECT * FROM server_activity_logs WHERE server_id = ? ORDER BY created_at DESC LIMIT 100', [serverId],
            (e2, rows) => res.json({ success: true, logs: rows || [] }));
    });
});

// ---- SERVER SHARES ----
app.get('/api/servers/:serverId/shares', authenticateToken, (req, res) => {
    db.all('SELECT * FROM server_shares WHERE server_id = ? AND owner_id = ?', [req.params.serverId, req.user.userId],
        (err, rows) => res.json({ success: true, shares: rows || [] }));
});

app.post('/api/servers/:serverId/shares', authenticateToken, (req, res) => {
    const { serverId } = req.params;
    const { email, permission = 'view' } = req.body;
    if (!email) return res.status(400).json({ success: false, error: 'Email requis' });
    db.get('SELECT id FROM servers WHERE id = ? AND user_id = ?', [serverId, req.user.userId], (err, srv) => {
        if (!srv) return res.status(403).json({ success: false, error: 'Non autorisé' });
        db.get('SELECT id FROM users WHERE email = ?', [email], (e2, target) => {
            db.run('INSERT OR REPLACE INTO server_shares (server_id, owner_id, shared_with_email, shared_with_id, permission) VALUES (?,?,?,?,?)',
                [serverId, req.user.userId, email, target?.id || null, permission],
                function(e3) { res.json({ success: !e3, error: e3?.message }); });
        });
    });
});

app.delete('/api/servers/:serverId/shares/:shareId', authenticateToken, (req, res) => {
    db.run('DELETE FROM server_shares WHERE id = ? AND owner_id = ?', [req.params.shareId, req.user.userId],
        err => res.json({ success: !err }));
});

app.get('/api/shared-servers', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    db.get('SELECT email FROM users WHERE id = ?', [userId], (err, u) => {
        db.all(`SELECT ss.*, s.server_name, s.server_type, s.server_status, s.pterodactyl_id
                FROM server_shares ss LEFT JOIN servers s ON ss.server_id = s.id
                WHERE ss.shared_with_id = ? OR ss.shared_with_email = ?`,
            [userId, u?.email || ''], (e2, rows) => res.json({ success: true, servers: rows || [] }));
    });
});

// ---- REVIEWS / NOTES ----
app.get('/api/reviews', (req, res) => {
    const { serverId, userId } = req.query;
    let q = 'SELECT sr.*, u.username FROM server_reviews sr LEFT JOIN users u ON sr.user_id = u.id WHERE 1=1';
    const params = [];
    if (serverId) { q += ' AND sr.server_id = ?'; params.push(serverId); }
    if (userId) { q += ' AND sr.user_id = ?'; params.push(userId); }
    q += ' ORDER BY sr.created_at DESC LIMIT 50';
    db.all(q, params, (err, rows) => res.json({ success: true, reviews: rows || [] }));
});

app.post('/api/reviews', authenticateToken, (req, res) => {
    const { serverId, rating, comment } = req.body;
    if (!serverId || !rating) return res.status(400).json({ success: false, error: 'serverId et rating requis' });
    if (rating < 1 || rating > 5) return res.status(400).json({ success: false, error: 'Rating entre 1 et 5' });
    db.run('INSERT OR REPLACE INTO server_reviews (server_id, user_id, rating, comment) VALUES (?,?,?,?)',
        [serverId, req.user.userId, rating, comment || null],
        err => res.json({ success: !err, error: err?.message }));
});

// ---- CHALLENGES ----
app.get('/api/challenges', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const currentMonth = new Date().toISOString().slice(0, 7);
    db.all(`SELECT c.*, uc.progress, uc.completed, uc.reward_claimed
            FROM challenges c
            LEFT JOIN user_challenges uc ON c.id = uc.challenge_id AND uc.user_id = ?
            WHERE c.active = 1 AND (c.month IS NULL OR c.month = ?)
            ORDER BY c.created_at DESC`, [userId, currentMonth],
        (err, rows) => res.json({ success: true, challenges: rows || [] }));
});

app.post('/api/challenges/:id/claim', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    db.get(`SELECT uc.*, c.reward_coins, c.reward_badge, c.name FROM user_challenges uc
            JOIN challenges c ON uc.challenge_id = c.id
            WHERE uc.challenge_id = ? AND uc.user_id = ? AND uc.completed = 1 AND uc.reward_claimed = 0`,
        [req.params.id, userId], (err, row) => {
            if (!row) return res.status(400).json({ success: false, error: 'Challenge non complété ou déjà réclamé' });
            db.run('UPDATE user_challenges SET reward_claimed = 1 WHERE challenge_id = ? AND user_id = ?', [req.params.id, userId]);
            if (row.reward_coins > 0) {
                db.run('UPDATE users SET coins = coins + ? WHERE id = ?', [row.reward_coins, userId]);
                db.run('INSERT INTO user_activities (user_id, activity_type, coins_change, description) VALUES (?,?,?,?)',
                    [userId, 'challenge_reward', row.reward_coins, `Récompense challenge: ${row.name}`]);
            }
            res.json({ success: true, coins_earned: row.reward_coins });
        });
});

app.get('/api/admin/challenges', authenticateToken, requireSuperAdmin, (req, res) => {
    db.all('SELECT * FROM challenges ORDER BY created_at DESC', [], (err, rows) => res.json({ success: true, challenges: rows || [] }));
});

app.post('/api/admin/challenges', authenticateToken, requireSuperAdmin, (req, res) => {
    const { name, description, type = 'monthly', reward_coins = 0, reward_badge, target_value = 1, target_metric, month } = req.body;
    if (!name) return res.status(400).json({ success: false, error: 'Nom requis' });
    const currentMonth = month || new Date().toISOString().slice(0, 7);
    db.run('INSERT INTO challenges (name, description, type, reward_coins, reward_badge, target_value, target_metric, month) VALUES (?,?,?,?,?,?,?,?)',
        [name, description, type, reward_coins, reward_badge, target_value, target_metric, currentMonth],
        function(err) { res.json({ success: !err, id: this?.lastID, error: err?.message }); });
});

// ---- MARKETPLACE ----
app.get('/api/marketplace', (req, res) => {
    const { category, search, limit = 20, offset = 0, seller_id } = req.query;
    let q = `SELECT ml.*, u.username as seller_name FROM marketplace_listings ml LEFT JOIN users u ON ml.seller_id = u.id WHERE ml.active = 1`;
    const params = [];
    if (category) { q += ' AND ml.category = ?'; params.push(category); }
    if (search) { q += ' AND (ml.title LIKE ? OR ml.description LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
    if (seller_id) { q += ' AND ml.seller_id = ?'; params.push(parseInt(seller_id)); }
    q += ' ORDER BY ml.downloads DESC, ml.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    db.all(q, params, (err, rows) => res.json({ success: true, listings: rows || [] }));
});

app.post('/api/marketplace', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const userRole = req.user.role;
    if (userRole !== 'admin' && userRole !== 'superadmin') {
        return res.status(403).json({ success: false, error: 'Réservé aux revendeurs ayant signé le contrat' });
    }
    const doInsert = () => {
        const { title, description, category = 'template', price_coins, game, content } = req.body;
        if (!title || !price_coins || !content) return res.status(400).json({ success: false, error: 'Champs requis manquants' });
        const ALLOWED_CATS = ['template', 'config', 'script', 'api', 'command', 'function', 'file', 'plugin', 'autre'];
        const cat = ALLOWED_CATS.includes(category) ? category : 'autre';
        db.run('INSERT INTO marketplace_listings (seller_id, title, description, category, price_coins, game, content) VALUES (?,?,?,?,?,?,?)',
            [userId, title, description, cat, price_coins, game, content],
            function(err2) { res.json({ success: !err2, id: this?.lastID, error: err2?.message }); });
    };
    if (userRole === 'superadmin') return doInsert();
    db.get('SELECT contract_accepted FROM reseller_profiles WHERE user_id = ?', [userId], (err, rp) => {
        if (!rp || !rp.contract_accepted) {
            return res.status(403).json({ success: false, error: 'Vous devez signer le contrat revendeur pour accéder au marketplace' });
        }
        doInsert();
    });
});

app.post('/api/marketplace/:id/buy', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const { send_email } = req.body;
    db.get('SELECT * FROM marketplace_listings WHERE id = ? AND active = 1', [req.params.id], (err, listing) => {
        if (!listing) return res.status(404).json({ success: false, error: 'Introuvable' });
        if (listing.seller_id === userId) return res.status(400).json({ success: false, error: 'Impossible d\'acheter votre propre article' });
        db.get('SELECT id, coins, email, username FROM users WHERE id = ?', [userId], (e2, user) => {
            if ((user?.coins || 0) < listing.price_coins) return res.status(400).json({ success: false, error: 'Coins insuffisants' });
            db.run('UPDATE users SET coins = coins - ? WHERE id = ?', [listing.price_coins, userId]);
            db.run('UPDATE users SET coins = coins + ? WHERE id = ?', [Math.floor(listing.price_coins * 0.9), listing.seller_id]);
            db.run('UPDATE marketplace_listings SET downloads = downloads + 1 WHERE id = ?', [listing.id]);
            db.run('INSERT INTO marketplace_purchases (listing_id, buyer_id, coins_spent) VALUES (?,?,?)', [listing.id, userId, listing.price_coins]);
            db.run('INSERT INTO user_activities (user_id, activity_type, coins_change, description) VALUES (?,?,?,?)',
                [userId, 'marketplace_purchase', -listing.price_coins, `Achat marketplace: ${listing.title}`]);
            if (send_email && user?.email) {
                sendEmail(user.email, `Votre achat FLYHOST Marketplace : ${listing.title}`,
                    `<div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;">
                    <h2 style="color:#6366f1;">✅ Achat confirmé — FLYHOST Marketplace</h2>
                    <p>Bonjour <strong>${user.username}</strong>,</p>
                    <p>Votre achat de <strong>${listing.title}</strong> (${listing.price_coins} coins) a été validé.</p>
                    <hr style="border:1px solid #e5e7eb;margin:20px 0;">
                    <h3>Contenu de votre achat :</h3>
                    <pre style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px;white-space:pre-wrap;word-break:break-all;font-size:13px;">${listing.content}</pre>
                    <hr style="border:1px solid #e5e7eb;margin:20px 0;">
                    <p style="color:#64748b;font-size:12px;">Le contenu est aussi disponible dans votre compte FLYHOST.</p>
                    </div>`).catch(() => {});
            }
            res.json({ success: true, content: listing.content });
        });
    });
});

app.delete('/api/marketplace/:id', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const role = req.user.role;
    db.get('SELECT seller_id FROM marketplace_listings WHERE id = ?', [req.params.id], (err, listing) => {
        if (!listing) return res.status(404).json({ success: false, error: 'Article introuvable' });
        if (listing.seller_id !== userId && role !== 'superadmin') {
            return res.status(403).json({ success: false, error: 'Non autorisé' });
        }
        db.run('UPDATE marketplace_listings SET active = 0 WHERE id = ?', [req.params.id], (e2) => {
            res.json({ success: !e2, error: e2?.message });
        });
    });
});

// ---- BOUTIQUE PERSONNELLE ----
app.get('/api/shop/:slug', (req, res) => {
    const slug = req.params.slug.toLowerCase();
    db.get(`SELECT u.id, u.username, u.role, rp.business_name, rp.support_email
            FROM users u LEFT JOIN reseller_profiles rp ON rp.user_id = u.id
            WHERE LOWER(u.username) = ?`, [slug], (err, seller) => {
        if (!seller) return res.status(404).json({ success: false, error: 'Boutique introuvable' });
        const isSuperAdmin = seller.role === 'superadmin';
        db.get('SELECT contract_accepted, active FROM reseller_profiles WHERE user_id = ?', [seller.id], (e2, rp) => {
            if (!isSuperAdmin && (!rp || !rp.active || !rp.contract_accepted)) {
                return res.status(404).json({ success: false, error: 'Boutique introuvable' });
            }
            db.all(`SELECT ml.id, ml.title, ml.description, ml.category, ml.price_coins, ml.game, ml.downloads, ml.created_at
                    FROM marketplace_listings ml WHERE ml.seller_id = ? AND ml.active = 1
                    ORDER BY ml.downloads DESC, ml.created_at DESC LIMIT 50`, [seller.id], (e3, listings) => {
                res.json({
                    success: true,
                    seller: { username: seller.username, business_name: rp?.business_name || seller.username, support_email: rp?.support_email },
                    listings: listings || []
                });
            });
        });
    });
});
app.get('/shop/:slug', (req, res) => res.sendFile(path.join(__dirname, 'shop.html')));

// ---- ABONNEMENTS MENSUELS ----
app.get('/api/subscriptions/plans', (req, res) => {
    res.json({ success: true, plans: [
        { id: 'starter', name: 'Starter', price: 500, coins_per_month: 100, features: ['100 coins/mois', '1 serveur gratuit', 'Support prioritaire'] },
        { id: 'pro', name: 'Pro', price: 1500, coins_per_month: 350, features: ['350 coins/mois', '3 serveurs gratuits', 'Support VIP', 'Auto-renew inclus'] },
        { id: 'business', name: 'Business', price: 4000, coins_per_month: 1000, features: ['1000 coins/mois', 'Serveurs illimités', 'Support 24/7', 'Tableau de bord dédié', 'API illimitée'] }
    ]});
});

app.get('/api/subscriptions/me', authenticateToken, (req, res) => {
    db.get('SELECT * FROM subscriptions WHERE user_id = ? AND active = 1', [req.user.userId],
        (err, row) => res.json({ success: true, subscription: row || null }));
});

app.post('/api/subscriptions/subscribe', authenticateToken, (req, res) => {
    const { plan } = req.body;
    const plans = { starter: { price: 500, coins: 100 }, pro: { price: 1500, coins: 350 }, business: { price: 4000, coins: 1000 } };
    if (!plans[plan]) return res.status(400).json({ success: false, error: 'Plan invalide' });
    const userId = req.user.userId;
    db.get('SELECT coins FROM users WHERE id = ?', [userId], (err, user) => {
        if ((user?.coins || 0) < plans[plan].price) return res.status(400).json({ success: false, error: 'Coins insuffisants' });
        db.run('UPDATE subscriptions SET active = 0 WHERE user_id = ?', [userId]);
        const nextBilling = new Date(); nextBilling.setMonth(nextBilling.getMonth() + 1);
        db.run('INSERT INTO subscriptions (user_id, plan_name, price_per_month, coins_per_month, next_billing_at) VALUES (?,?,?,?,?)',
            [userId, plan, plans[plan].price, plans[plan].coins, nextBilling.toISOString()], function(e2) {
                if (e2) return res.status(500).json({ success: false });
                db.run('UPDATE users SET coins = coins - ? WHERE id = ?', [plans[plan].price, userId]);
                db.run('INSERT INTO user_activities (user_id, activity_type, coins_change, description) VALUES (?,?,?,?)',
                    [userId, 'subscription', -plans[plan].price, `Abonnement ${plan} souscrit`]);
                res.json({ success: true });
            });
    });
});

app.post('/api/subscriptions/cancel', authenticateToken, (req, res) => {
    db.run('UPDATE subscriptions SET active = 0 WHERE user_id = ?', [req.user.userId],
        err => res.json({ success: !err }));
});

// ---- REDÉMARRAGE AUTO PLANIFIÉ ----
app.get('/api/servers/:serverId/restart-schedule', authenticateToken, (req, res) => {
    db.get('SELECT rs.* FROM restart_schedules rs JOIN servers s ON rs.server_id = s.id WHERE rs.server_id = ? AND s.user_id = ?',
        [req.params.serverId, req.user.userId], (err, row) => res.json({ success: true, schedule: row || null }));
});

app.post('/api/servers/:serverId/restart-schedule', authenticateToken, (req, res) => {
    const { schedule, day_of_week, hour = 3 } = req.body;
    const valid = ['daily', 'weekly', null];
    if (!valid.includes(schedule)) return res.status(400).json({ success: false, error: 'Valeur invalide' });
    db.get('SELECT id FROM servers WHERE id = ? AND user_id = ?', [req.params.serverId, req.user.userId], (err, srv) => {
        if (!srv) return res.status(403).json({ success: false, error: 'Non autorisé' });
        if (!schedule) {
            db.run('DELETE FROM restart_schedules WHERE server_id = ?', [req.params.serverId], e => res.json({ success: !e }));
        } else {
            db.run('INSERT OR REPLACE INTO restart_schedules (server_id, schedule, day_of_week, hour) VALUES (?,?,?,?)',
                [req.params.serverId, schedule, day_of_week, hour], e => res.json({ success: !e, error: e?.message }));
        }
    });
});

// ---- GÉOLOCALISATION (stats admin) ----
app.get('/api/admin/geomap', authenticateToken, requireSuperAdmin, (req, res) => {
    db.all(`SELECT 
        SUBSTR(ip_address, 1, INSTR(ip_address || '.', '.') - 1) as ip_prefix,
        COUNT(*) as count, country_code, city
        FROM (SELECT ip_address, '' as country_code, '' as city FROM users WHERE ip_address IS NOT NULL)
        GROUP BY ip_address LIMIT 500`, [], (err, rows) => {
        db.all('SELECT ip_address, COUNT(*) as count FROM users WHERE ip_address IS NOT NULL GROUP BY ip_address ORDER BY count DESC LIMIT 200',
            [], (e2, ips) => res.json({ success: true, ips: ips || [] }));
    });
});

// =============================================
// PTERODACTYL EGG MANAGEMENT — Admin
// =============================================

// Lister tous les nests + eggs du panel Pterodactyl
app.get('/api/admin/pterodactyl/eggs', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const nestsData = await callPterodactylAPI('/api/application/nests');
        if (!nestsData || !nestsData.data) return res.json({ success: true, nests: [] });

        const nests = await Promise.all(nestsData.data.map(async nest => {
            try {
                const eggsData = await callPterodactylAPI(`/api/application/nests/${nest.attributes.id}/eggs`);
                return {
                    id: nest.attributes.id,
                    name: nest.attributes.name,
                    description: nest.attributes.description || '',
                    eggs: (eggsData.data || []).map(e => ({
                        id: e.attributes.id,
                        name: e.attributes.name,
                        description: e.attributes.description || '',
                        docker_image: e.attributes.docker_image || ''
                    }))
                };
            } catch { return { id: nest.attributes.id, name: nest.attributes.name, eggs: [] }; }
        }));

        res.json({ success: true, nests });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// Récupérer le mapping actuel tech → egg
// Backfill alloc_port pour serveurs existants
app.post('/api/admin/backfill-alloc-ports', authenticateToken, requireSuperAdmin, async (req, res) => {
    const servers = await new Promise(resolve =>
        db.all(`SELECT id, pterodactyl_id, server_identifier FROM servers WHERE is_active = 1 AND alloc_port IS NULL`, [], (e, r) => resolve(r || []))
    );
    let updated = 0, failed = 0;
    for (const srv of servers) {
        try {
            const data = await callPterodactylAPI(`/api/application/servers/${srv.pterodactyl_id}?include=allocations`);
            const allocData = data.attributes?.relationships?.allocations?.data || [];
            const primary = allocData.find(a => a.attributes?.is_default) || allocData[0];
            if (primary) {
                await new Promise(resolve =>
                    db.run(`UPDATE servers SET alloc_port = ?, alloc_ip = ? WHERE id = ?`,
                        [primary.attributes.port, primary.attributes.ip || '0.0.0.0', srv.id], resolve)
                );
                updated++;
            } else { failed++; }
        } catch { failed++; }
    }
    res.json({ success: true, updated, failed, total: servers.length });
});

app.get('/api/admin/egg-mapping', authenticateToken, requireSuperAdmin, (req, res) => {
    const keys = ['egg_nodejs','egg_python','egg_php','egg_java','egg_static','egg_discord',
                  'docker_nodejs','docker_python','docker_php','docker_java','docker_static'];
    const placeholders = keys.map(() => '?').join(',');
    db.all(`SELECT key, value FROM system_settings WHERE key IN (${placeholders})`, keys, (err, rows) => {
        const mapping = {};
        // defaults from env
        mapping.egg_nodejs  = process.env.EGG_NODEJS  || '15';
        mapping.egg_python  = process.env.EGG_PYTHON  || '18';
        mapping.egg_php     = process.env.EGG_PHP     || '19';
        mapping.egg_java    = process.env.EGG_JAVA    || '16';
        mapping.egg_static  = process.env.EGG_STATIC  || '15';
        mapping.egg_discord = process.env.EGG_DISCORD || '15';
        mapping.docker_nodejs  = process.env.DOCKER_NODEJS  || 'ghcr.io/parkervcp/yolks:nodejs_24';
        mapping.docker_python  = process.env.DOCKER_PYTHON  || 'ghcr.io/parkervcp/yolks:python_3.11';
        mapping.docker_php     = process.env.DOCKER_PHP     || 'ghcr.io/parkervcp/yolks:php_8.3';
        mapping.docker_java    = process.env.DOCKER_JAVA    || 'ghcr.io/parkervcp/yolks:java_21';
        mapping.docker_static  = process.env.DOCKER_STATIC  || 'ghcr.io/parkervcp/yolks:nodejs_24';
        (rows || []).forEach(r => { mapping[r.key] = r.value; });
        res.json({ success: true, mapping });
    });
});

// Sauvegarder le mapping tech → egg
app.post('/api/admin/egg-mapping', authenticateToken, requireSuperAdmin, (req, res) => {
    const allowed = ['egg_nodejs','egg_python','egg_php','egg_java','egg_static','egg_discord',
                     'docker_nodejs','docker_python','docker_php','docker_java','docker_static'];
    const updates = Object.entries(req.body).filter(([k]) => allowed.includes(k));
    if (!updates.length) return res.status(400).json({ success: false, error: 'Aucun champ valide' });
    const stmt = db.prepare('INSERT OR REPLACE INTO system_settings (key, value, updated_at, updated_by) VALUES (?, ?, CURRENT_TIMESTAMP, ?)');
    updates.forEach(([k, v]) => stmt.run(k, String(v), req.user.userId));
    stmt.finalize();
    // Reload TECH_ENVIRONMENTS egg ids at runtime
    updates.forEach(([k, v]) => {
        const techMap = { egg_nodejs: 'nodejs', egg_python: 'python', egg_php: 'php', egg_java: 'java', egg_static: 'static', egg_discord: 'discord' };
        const dockerMap = { docker_nodejs: 'nodejs', docker_python: 'python', docker_php: 'php', docker_java: 'java', docker_static: 'static' };
        if (techMap[k] && TECH_ENVIRONMENTS[techMap[k]]) TECH_ENVIRONMENTS[techMap[k]].egg = parseInt(v) || 15;
        if (dockerMap[k] && TECH_ENVIRONMENTS[dockerMap[k]]) TECH_ENVIRONMENTS[dockerMap[k]].docker_image = v;
    });
    res.json({ success: true, message: 'Mapping mis à jour et appliqué immédiatement' });
});

// ---- FACTURATION (invoice PDF endpoint) ----
app.get('/api/invoices', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    db.all('SELECT * FROM invoices WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', [userId],
        (err, rows) => res.json({ success: true, invoices: rows || [] }));
});

app.get('/api/invoices/:id/html', authenticateToken, (req, res) => {
    db.get('SELECT inv.*, u.username, u.email FROM invoices inv LEFT JOIN users u ON inv.user_id = u.id WHERE inv.id = ? AND inv.user_id = ?',
        [req.params.id, req.user.userId], (err, inv) => {
            if (!inv) return res.status(404).json({ success: false });
            const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Facture #${inv.id}</title>
            <style>body{font-family:Arial,sans-serif;max-width:700px;margin:40px auto;color:#1e293b;}
            .header{display:flex;justify-content:space-between;align-items:center;border-bottom:3px solid #6366f1;padding-bottom:20px;}
            .logo{font-size:28px;font-weight:800;color:#6366f1;}
            table{width:100%;border-collapse:collapse;margin-top:30px;}
            th{background:#f8fafc;padding:12px;text-align:left;border-bottom:1px solid #e2e8f0;}
            td{padding:12px;border-bottom:1px solid #f1f5f9;}
            .total{font-size:20px;font-weight:700;color:#6366f1;text-align:right;margin-top:20px;}
            .footer{margin-top:40px;text-align:center;color:#94a3b8;font-size:12px;}
            </style></head><body>
            <div class="header"><div class="logo">🚀 FLYHOST</div><div><strong>Facture #${inv.id}</strong><br>${new Date(inv.created_at).toLocaleDateString('fr-FR')}</div></div>
            <p><strong>Client:</strong> ${inv.username} (${inv.email})</p>
            <table><tr><th>Description</th><th>Montant</th></tr>
            <tr><td>${inv.description || 'Service FLYHOST'}</td><td>${inv.amount} ${inv.currency}</td></tr></table>
            <div class="total">Total: ${inv.amount} ${inv.currency}</div>
            <div class="footer">FLYHOST – flihost.site | Merci pour votre confiance !</div>
            </body></html>`;
            res.setHeader('Content-Type', 'text/html');
            res.send(html);
        });
});

// ---- FACTURE PDF ----
app.get('/api/invoices/:id/pdf', authenticateToken, (req, res) => {
    db.get('SELECT inv.*, u.username, u.email FROM invoices inv LEFT JOIN users u ON inv.user_id = u.id WHERE inv.id = ? AND inv.user_id = ?',
        [req.params.id, req.user.userId], (err, inv) => {
            if (!inv) return res.status(404).json({ success: false, error: 'Facture introuvable' });
            const doc = new PDFDocument({ margin: 50, size: 'A4' });
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', `attachment; filename="facture-flyhost-${inv.id}.pdf"`);
            doc.pipe(res);
            // Header
            doc.fontSize(28).fillColor('#6366f1').font('Helvetica-Bold').text('FLYHOST', 50, 50);
            doc.fontSize(12).fillColor('#64748b').font('Helvetica').text('flyhost.site', 50, 82);
            doc.fontSize(18).fillColor('#1e293b').font('Helvetica-Bold').text(`Facture #${inv.id}`, 380, 50, { align: 'right' });
            doc.fontSize(11).fillColor('#64748b').font('Helvetica').text(new Date(inv.created_at).toLocaleDateString('fr-FR'), 380, 75, { align: 'right' });
            doc.moveTo(50, 110).lineTo(545, 110).strokeColor('#6366f1').lineWidth(2).stroke();
            // Client info
            doc.fontSize(12).fillColor('#1e293b').font('Helvetica-Bold').text('Facturé à:', 50, 130);
            doc.font('Helvetica').fillColor('#475569').text(inv.username || 'Client', 50, 148);
            doc.text(inv.email || '', 50, 163);
            // Table header
            doc.rect(50, 210, 495, 30).fillColor('#f8fafc').fill();
            doc.fontSize(11).fillColor('#64748b').font('Helvetica-Bold');
            doc.text('Description', 60, 220);
            doc.text('Montant', 460, 220, { align: 'right', width: 75 });
            doc.moveTo(50, 240).lineTo(545, 240).strokeColor('#e2e8f0').lineWidth(1).stroke();
            // Table row
            doc.fontSize(11).fillColor('#1e293b').font('Helvetica');
            doc.text(inv.description || 'Service FLYHOST', 60, 255, { width: 380 });
            doc.text(`${inv.amount} ${inv.currency || 'coins'}`, 460, 255, { align: 'right', width: 75 });
            doc.moveTo(50, 285).lineTo(545, 285).strokeColor('#f1f5f9').lineWidth(1).stroke();
            // Total
            doc.rect(380, 300, 165, 35).fillColor('#f0f0ff').fill();
            doc.fontSize(14).fillColor('#6366f1').font('Helvetica-Bold').text(`Total: ${inv.amount} ${inv.currency || 'coins'}`, 385, 310, { width: 155, align: 'right' });
            // Footer
            doc.fontSize(10).fillColor('#94a3b8').font('Helvetica').text('Merci pour votre confiance — FLYHOST', 50, 740, { align: 'center', width: 495 });
            doc.moveTo(50, 730).lineTo(545, 730).strokeColor('#e2e8f0').lineWidth(1).stroke();
            doc.end();
        });
});

// ---- CLONE SNAPSHOT SERVEUR ----
app.post('/api/servers/:serverId/backups/:backupUuid/clone', authenticateToken, (req, res) => {
    const { serverId } = req.params;
    const { backupUuid } = req.params;
    const userId = req.user.userId;
    const { clone_name } = req.body;
    db.get('SELECT * FROM servers WHERE id = ? AND user_id = ?', [serverId, userId], (err, server) => {
        if (!server) return res.status(404).json({ success: false, error: 'Serveur introuvable' });
        const newName = clone_name || `${server.server_name}-clone`;
        const newExpiry = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
        db.run(`INSERT INTO servers (user_id, server_name, server_type, server_identifier, server_status, expires_at, is_active, notes)
                VALUES (?, ?, ?, ?, 'installing', ?, 1, ?)`,
            [userId, newName, server.server_type, `clone-${Date.now()}`, newExpiry, `Cloné depuis snapshot ${backupUuid.substring(0,8)} du serveur "${server.server_name}"`],
            function(e2) {
                if (e2) return res.status(500).json({ success: false, error: 'Erreur création clone' });
                const newServerId = this.lastID;
                db.run('INSERT INTO server_activity_logs (server_id, action, details) VALUES (?,?,?)',
                    [serverId, 'SNAPSHOT_CLONE', `Clone "${newName}" créé depuis snapshot ${backupUuid.substring(0,8)}`]);
                auditLog(req, 'clone_snapshot', 'server', serverId, `Clone "${newName}" créé`);
                res.json({ success: true, message: `Serveur "${newName}" créé depuis le snapshot`, new_server_id: newServerId });
            });
    });
});

// ---- PTERODACTYL RESOURCES (CPU/RAM) ----
app.get('/api/pterodactyl/servers/:pterodactylId/resources', authenticateToken, async (req, res) => {
    try {
        const identifier = req.params.pterodactylId;
        const result = await callPterodactylClientAPI(`/api/client/servers/${identifier}/resources`);
        const attrs = result?.attributes || {};
        res.json({ success: true, resources: {
            cpu_absolute: attrs.cpu_absolute || 0,
            memory_bytes: attrs.memory_bytes || 0,
            disk_bytes: attrs.disk_bytes || 0,
            network_rx_bytes: attrs.network_rx_bytes || 0,
            network_tx_bytes: attrs.network_tx_bytes || 0,
            current_state: attrs.current_state || 'offline'
        }});
    } catch(e) {
        res.json({ success: false, error: e.message, resources: null });
    }
});

// ---- MÉTRIQUES HISTORIQUES ----
app.get('/api/servers/:id/metrics', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { range } = req.query; // '1h', '24h', '7d'
    let since;
    if (range === '1h') since = "datetime('now', '-1 hour')";
    else if (range === '7d') since = "datetime('now', '-7 days')";
    else since = "datetime('now', '-24 hours')";
    db.get('SELECT id FROM servers WHERE id = ? AND user_id = ?', [id, req.user.userId], (err, srv) => {
        if (!srv) return res.status(404).json({ success: false });
        db.all(`SELECT cpu, ram_mb, disk_mb, net_rx_kb, net_tx_kb, recorded_at FROM server_metrics 
                WHERE server_id = ? AND recorded_at >= ${since} ORDER BY recorded_at ASC`,
            [id], (e2, rows) => res.json({ success: true, metrics: rows || [] }));
    });
});

// ---- VARIABLES D'ENVIRONNEMENT SERVEUR ----
app.get('/api/servers/:id/envvars', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.get('SELECT id, server_identifier FROM servers WHERE id = ? AND user_id = ?', [id, req.user.userId], async (err, srv) => {
        if (!srv) return res.status(404).json({ success: false });
        // Try Pterodactyl first
        try {
            if (srv.server_identifier) {
                const r = await callPterodactylClientAPI(`/api/client/servers/${srv.server_identifier}/startup`);
                const vars = (r?.data || []).map(v => ({
                    key: v.attributes?.env_variable,
                    value: v.attributes?.server_value ?? v.attributes?.default_value,
                    name: v.attributes?.name,
                    description: v.attributes?.description,
                    editable: v.attributes?.is_editable
                }));
                return res.json({ success: true, vars, source: 'pterodactyl' });
            }
        } catch(e) {}
        // Fallback to local DB
        db.all('SELECT key_name, value FROM server_envvars WHERE server_id = ?', [id],
            (e2, rows) => res.json({ success: true, vars: (rows || []).map(r => ({ key: r.key_name, value: r.value, editable: true })), source: 'local' }));
    });
});

app.put('/api/servers/:id/envvars', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { key, value } = req.body;
    if (!key) return res.status(400).json({ success: false, error: 'Clé requise' });
    db.get('SELECT id, server_identifier FROM servers WHERE id = ? AND user_id = ?', [id, req.user.userId], async (err, srv) => {
        if (!srv) return res.status(404).json({ success: false });
        try {
            if (srv.server_identifier) {
                await callPterodactylClientAPI(`/api/client/servers/${srv.server_identifier}/startup/variable`, 'PUT', { key, value });
                auditLog(req, 'update_envvar', 'server', id, `${key}=***`);
                return res.json({ success: true, message: 'Variable mise à jour via Pterodactyl' });
            }
        } catch(e) {}
        // Fallback local
        db.run(`INSERT INTO server_envvars (server_id, key_name, value, updated_at) VALUES (?,?,?,datetime('now'))
                ON CONFLICT(server_id, key_name) DO UPDATE SET value=excluded.value, updated_at=datetime('now')`,
            [id, key, value], (e2) => {
                if (e2) return res.status(500).json({ success: false, error: e2.message });
                auditLog(req, 'update_envvar', 'server', id, `${key}=***`);
                res.json({ success: true, message: 'Variable enregistrée localement' });
            });
    });
});

// ---- DUPLICATION SERVEUR ----
app.post('/api/servers/:id/duplicate', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.userId;
    const { name } = req.body;
    const isAdmin = req.user.role === 'admin' || req.user.role === 'superadmin';
    db.get('SELECT * FROM servers WHERE id = ? AND user_id = ?', [id, userId], async (err, srv) => {
        if (!srv) return res.status(404).json({ success: false, error: 'Serveur introuvable' });

        // Bloquer la duplication de serveurs gratuits pour les non-admins
        if (srv.server_type === 'free' && !isAdmin) {
            return res.status(403).json({
                success: false,
                error: 'Les serveurs gratuits ne peuvent pas être dupliqués. Un seul serveur gratuit est autorisé par compte.',
                code: 'FREE_SERVER_NO_DUPLICATE'
            });
        }

        const newName = name || `${srv.server_name}-copie`;
        const newExpiry = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
        // La copie hérite du type mais jamais de type 'free' pour les non-admins
        const newType = (!isAdmin && srv.server_type === 'free') ? 'cloned' : srv.server_type;
        db.run(`INSERT INTO servers (user_id, server_name, server_type, server_identifier, server_status, expires_at, is_active, notes)
                VALUES (?,?,?,?,?,?,1,?)`,
            [userId, newName, newType, `dup-${Date.now()}`, 'installing', newExpiry, `Dupliqué depuis "${srv.server_name}"`],
            function(e2) {
                if (e2) return res.status(500).json({ success: false, error: 'Erreur duplication' });
                db.run('INSERT INTO server_activity_logs (server_id, action, details) VALUES (?,?,?)',
                    [id, 'DUPLICATE', `Copie "${newName}" créée`]);
                auditLog(req, 'duplicate_server', 'server', id, `Copie: "${newName}"`);
                res.json({ success: true, new_server_id: this.lastID, name: newName });
            });
    });
});

// ---- WEBHOOK AUTO-DEPLOY GIT ----
app.get('/api/servers/:id/webhook', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.get('SELECT id FROM servers WHERE id = ? AND user_id = ?', [id, req.user.userId], (err, srv) => {
        if (!srv) return res.status(404).json({ success: false });
        db.get('SELECT * FROM deploy_webhooks WHERE server_id = ?', [id], (e2, wh) => {
            if (wh) return res.json({ success: true, webhook: wh });
            const token = crypto.randomBytes(24).toString('hex');
            db.run('INSERT INTO deploy_webhooks (server_id, token) VALUES (?,?)', [id, token], function(e3) {
                if (e3) return res.status(500).json({ success: false });
                res.json({ success: true, webhook: { server_id: id, token, branch: 'main' } });
            });
        });
    });
});

app.put('/api/servers/:id/webhook', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { branch, repo_url } = req.body;
    db.get('SELECT id FROM servers WHERE id = ? AND user_id = ?', [id, req.user.userId], (err, srv) => {
        if (!srv) return res.status(404).json({ success: false });
        db.run('UPDATE deploy_webhooks SET branch = ?, repo_url = ? WHERE server_id = ?',
            [branch || 'main', repo_url || null, id],
            () => res.json({ success: true }));
    });
});

app.post('/api/webhook/deploy/:token', (req, res) => {
    const { token } = req.params;
    const payload = req.body;
    db.get('SELECT dw.*, s.server_identifier, s.server_name FROM deploy_webhooks dw JOIN servers s ON dw.server_id = s.id WHERE dw.token = ?',
        [token], async (err, wh) => {
            if (!wh) return res.status(404).json({ success: false });
            const branch = payload?.ref?.replace('refs/heads/', '');
            if (wh.branch && branch && branch !== wh.branch) {
                return res.json({ success: false, message: 'Branch mismatch, skipping' });
            }
            try {
                if (wh.server_identifier) {
                    await callPterodactylClientAPI(`/api/client/servers/${wh.server_identifier}/power`, 'POST', { signal: 'restart' });
                }
                db.run('UPDATE deploy_webhooks SET last_deploy_at = datetime("now") WHERE token = ?', [token]);
                db.run('INSERT INTO server_activity_logs (server_id, action, details) VALUES (?,?,?)',
                    [wh.server_id, 'WEBHOOK_DEPLOY', `Auto-deploy depuis ${payload?.repository?.full_name || 'Git'} branche ${branch || wh.branch}`]);
                res.json({ success: true, message: `Auto-deploy déclenché sur ${wh.server_name}` });
            } catch(e) {
                res.status(500).json({ success: false, error: e.message });
            }
        });
});

// ---- ROLLBACK DÉPLOIEMENT ----
app.post('/api/servers/:id/rollback', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { deployment_id } = req.body;
    db.get('SELECT d.*, s.server_identifier, s.server_name FROM deployments d JOIN servers s ON d.server_id = s.id WHERE d.id = ? AND s.user_id = ?',
        [deployment_id, req.user.userId], async (err, dep) => {
            if (!dep) return res.status(404).json({ success: false, error: 'Déploiement introuvable' });
            db.run('INSERT INTO server_activity_logs (server_id, action, details) VALUES (?,?,?)',
                [id, 'ROLLBACK', `Rollback vers déploiement #${deployment_id} (${dep.app_name || 'app'})`]);
            auditLog(req, 'rollback', 'server', id, `Rollback vers #${deployment_id}`);
            res.json({ success: true, message: `Rollback vers "${dep.app_name || `déploiement #${deployment_id}`}" effectué` });
        });
});

// ---- LEADERBOARD PAGE ----
app.get('/leaderboard', (req, res) => res.sendFile(path.join(__dirname, 'leaderboard.html')));

// ---- FORUM — redirige vers la page Communauté ----
app.get('/forum', (req, res) => res.redirect('/chat?tab=discussions'));
app.get('/forum/:id', (req, res) => res.redirect(`/chat?tab=discussions&thread=${req.params.id}`));

// ---- MARKETPLACE PAGE ----
app.get('/marketplace', (req, res) => res.sendFile(path.join(__dirname, 'marketplace.html')));

// ---- SUBSCRIPTION PAGE ----
app.get('/subscription', (req, res) => res.sendFile(path.join(__dirname, 'subscription.html')));
app.get('/tickets', (req, res) => res.sendFile(path.join(__dirname, 'tickets.html')));
app.get('/invoices', (req, res) => res.sendFile(path.join(__dirname, 'invoices.html')));

// =============================================
// GESTION DES ERREURS
// =============================================

app.use((err, req, res, next) => {
    console.error('❌ Erreur non gérée:', err);
    
    logSystem('error', 'Erreur non gérée', {
        message: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method,
        ip: req.ip
    });

    res.status(500).json({
        success: false,
        error: 'Erreur interne du serveur',
        code: 'INTERNAL_SERVER_ERROR'
    });
});

// =============================================
// INITIALISATION CRON JOBS
// =============================================

initializeCronJobs();

// =============================================
// DÉMARRAGE DU SERVEUR
// =============================================

const server = app.listen(PORT, '0.0.0.0', () => {
    console.log('\n' + '='.repeat(50));
    console.log(`🚀 SERVEUR FLYHOST REVENDEUR DÉMARRÉ`);
    console.log('='.repeat(50));
    console.log(`📡 Port: ${PORT}`);
    console.log(`🔒 Mode: Production`);
    console.log(`🌐 URL: http://localhost:${PORT}`);
    console.log(`🔑 Endpoint interne: http://localhost:${PORT}/internal`);
    console.log(`💼 Programme revendeur: ACTIVÉ`);
    console.log(`🔑 API Keys 3 niveaux: user | reseller | superadmin`);
    console.log('='.repeat(50) + '\n');
    ensureWildcardDNS();
    setTimeout(() => syncAllocPortsFromPterodactyl(), 5000);
});

// WebSocket upgrade pour les sous-domaines et domaines personnalisés
server.on('upgrade', async (req, socket, head) => {
    const host = (req.headers.host || '').split(':')[0].toLowerCase();
    const PROD_DOMAIN = 'flihost.site';

    let cacheKey, queryFn;
    if (host.endsWith(`.${PROD_DOMAIN}`)) {
        const subdomain = host.slice(0, -(PROD_DOMAIN.length + 1));
        if (!subdomain || subdomain === 'www' || subdomain.includes('.')) return;
        cacheKey = subdomain;
        queryFn = () => new Promise(resolve =>
            db.get(`SELECT alloc_port, alloc_ip FROM servers WHERE (server_identifier = ? OR custom_subdomain = ?) AND is_active = 1 LIMIT 1`,
                [subdomain, subdomain], (e, r) => resolve(r))
        );
    } else if (host !== 'flihost.site' && host !== 'www.flihost.site' && !host.includes('replit')) {
        cacheKey = 'domain:' + host;
        queryFn = () => new Promise(resolve =>
            db.get(`SELECT alloc_port, alloc_ip FROM servers WHERE custom_domain = ? AND is_active = 1 LIMIT 1`,
                [host], (e, r) => resolve(r))
        );
    } else { return; }

    const cached = subdomainCache.get(cacheKey);
    let target = cached && (Date.now() - cached.ts < SUBDOMAIN_CACHE_TTL) ? cached : null;
    if (!target) {
        const row = await queryFn();
        target = await resolveProxyTargetAsync(row);
        if (!target) return socket.destroy();
        subdomainCache.set(cacheKey, { ...target, ts: Date.now() });
    }
    subdomainProxy.ws(req, socket, head, { target: `ws://${target.ip}:${target.port}` });
});

// =============================================
// WEBSOCKET POUR LOGS EN TEMPS RÉEL
// =============================================

// =============================================
// SSE — LOGS DÉPLOIEMENT  (/api/servers/:id/logs/sse)
// =============================================
// Les SSE passent à travers tous les proxies HTTP (dont Replit worf.replit.dev)
// car ce sont de simples réponses HTTP en streaming — pas de WebSocket upgrade.

const sseLogsClients = new Map();   // serverId -> Set<res>
const sseUserClients = new Map();   // userId  -> res

function sseSend(res, data) {
    try {
        res.write(`data: ${JSON.stringify(data)}\n\n`);
        if (typeof res.flush === 'function') res.flush();
    } catch(e) {}
}

app.get('/api/servers/:serverId/logs/sse', (req, res) => {
    const { serverId } = req.params;
    const token = req.query.token;
    if (!token) { res.status(401).end(); return; }

    jwt.verify(token, WEB_CONFIG.JWT_SECRET, (err, user) => {
        if (err) { res.status(401).end(); return; }

        db.get('SELECT role FROM users WHERE id = ?', [user.userId], (e2, userRow) => {
            const isAdmin = userRow?.role === 'superadmin' || userRow?.role === 'admin';
            const q = isAdmin ? 'SELECT id FROM servers WHERE id = ?' : 'SELECT id FROM servers WHERE id = ? AND user_id = ?';
            const p = isAdmin ? [serverId] : [serverId, user.userId];

            db.get(q, p, (e3, srv) => {
                if (e3 || !srv) { res.status(404).end(); return; }

                res.writeHead(200, {
                    'Content-Type': 'text/event-stream',
                    'Cache-Control': 'no-cache',
                    'Connection': 'keep-alive',
                    'X-Accel-Buffering': 'no',
                    'Access-Control-Allow-Origin': '*'
                });
                res.flushHeaders();

                if (!sseLogsClients.has(serverId)) sseLogsClients.set(serverId, new Set());
                sseLogsClients.get(serverId).add(res);
                sseUserClients.set(String(user.userId), res);

                sseSend(res, { type: 'connected', message: `🔌 Connecté aux logs du serveur ${serverId}` });

                // Heartbeat — envoi de données vides toutes les 2s pour garder la connexion via proxy
                const hb = setInterval(() => sseSend(res, { type: 'hb' }), 2000);

                // Derniers logs du dernier déploiement
                db.get('SELECT build_log FROM deployments WHERE server_id = ? ORDER BY created_at DESC LIMIT 1', [serverId], (e4, dep) => {
                    if (dep?.build_log) {
                        dep.build_log.split('\n').slice(-50).forEach(line => {
                            if (line.trim()) sseSend(res, { type: 'log', level: 'info', message: line });
                        });
                    }
                });

                req.on('close', () => {
                    clearInterval(hb);
                    const s = sseLogsClients.get(serverId);
                    if (s) { s.delete(res); if (s.size === 0) sseLogsClients.delete(serverId); }
                    sseUserClients.delete(String(user.userId));
                });
            });
        });
    });
});

global.broadcastLog = (serverId, logData) => {
    const clients = sseLogsClients.get(String(serverId));
    if (!clients) return;
    const data = { type: 'log', ...logData, timestamp: new Date().toISOString() };
    clients.forEach(r => sseSend(r, data));
};

global.broadcastDeployStatus = (serverId, status, message, diagnosis = null) => {
    const clients = sseLogsClients.get(String(serverId));
    if (!clients) return;
    const data = { type: 'deploy_status', status, message, diagnosis, timestamp: new Date().toISOString() };
    clients.forEach(r => sseSend(r, data));
};

// Helper: récupère le build_log d'un déploiement, analyse l'erreur, et broadcast avec diagnostic
global.broadcastDeployFailed = async (serverId, deploymentId, errorMessage, tech) => {
    try {
        const depRow = await new Promise(r => db.get('SELECT build_log FROM deployments WHERE id = ?', [deploymentId], (e, row) => r(row)));
        const fullLog = (depRow?.build_log || '') + '\n' + errorMessage;
        const diagnosis = analyzeDeployError(fullLog, tech || 'nodejs');
        global.broadcastDeployStatus(serverId, 'failed', errorMessage, diagnosis);
    } catch(_) {
        global.broadcastDeployStatus(serverId, 'failed', errorMessage);
    }
};

global.sendNotification = (userId, notification) => {
    const r = sseUserClients.get(String(userId));
    if (r) sseSend(r, { type: 'notification', ...notification, timestamp: new Date().toISOString() });
};

console.log('✅ SSE logs initialisé sur /api/servers/:id/logs/sse');

// =============================================
// WEBSOCKET POUR LE CHAT
// =============================================

const chatWss = new WebSocketServer({ server, path: '/ws/chat' });
const chatConnections = new Map(); // userId -> Set de WebSockets

chatWss.on('connection', (ws, req) => {
    const urlParams = new URLSearchParams(req.url.split('?')[1]);
    const token = urlParams.get('token');

    if (!token) {
        ws.close(1008, 'Token requis');
        return;
    }

    jwt.verify(token, WEB_CONFIG.JWT_SECRET, (err, user) => {
        if (err) {
            ws.close(1008, 'Token invalide');
            return;
        }

        // Ajouter la connexion
        if (!chatConnections.has(String(user.userId))) {
            chatConnections.set(String(user.userId), new Set());
        }
        chatConnections.get(String(user.userId)).add(ws);

        // Envoyer la confirmation de connexion
        ws.send(JSON.stringify({
            type: 'connected',
            message: 'Connecté au chat',
            user_id: user.userId
        }));

        // Mettre à jour le statut en ligne pour tous
        broadcastChatMembersUpdate();

        // Gérer les messages du client
        ws.on('message', (data) => {
            try {
                const msg = JSON.parse(data);
                if (msg.type === 'ping') {
                    ws.send(JSON.stringify({ type: 'pong' }));
                } else if (msg.type === 'typing') {
                    broadcastTypingStatus(user.userId, msg.is_typing);
                }
            } catch (e) {}
        });

        // Gérer la déconnexion
        ws.on('close', () => {
            const conns = chatConnections.get(String(user.userId));
            if (conns) {
                conns.delete(ws);
                if (conns.size === 0) {
                    chatConnections.delete(String(user.userId));
                }
            }
            broadcastChatMembersUpdate();
        });
    });
});

// Fonctions de broadcast pour le chat
function broadcastChatMessage(message) {
    const msgString = JSON.stringify({
        type: 'message',
        message
    });

    chatConnections.forEach(connections => {
        connections.forEach(ws => {
            if (ws.readyState === 1) {
                ws.send(msgString);
            }
        });
    });
}

function broadcastChatUpdate(type, data) {
    const msgString = JSON.stringify({
        type,
        ...data,
        timestamp: new Date().toISOString()
    });

    chatConnections.forEach(connections => {
        connections.forEach(ws => {
            if (ws.readyState === 1) {
                ws.send(msgString);
            }
        });
    });
}

function broadcastChatMembersUpdate() {
    db.all(
        `SELECT u.id, u.username, u.role,
                u.last_login > datetime('now', '-5 minutes') as online
         FROM users u
         WHERE u.email_verified = 1`,
        [],
        (err, members) => {
            if (err) return;

            const msgString = JSON.stringify({
                type: 'members_update',
                members: members || []
            });

            chatConnections.forEach(connections => {
                connections.forEach(ws => {
                    if (ws.readyState === 1) {
                        ws.send(msgString);
                    }
                });
            });
        }
    );
}

function broadcastTypingStatus(userId, isTyping) {
    db.get('SELECT username FROM users WHERE id = ?', [userId], (err, user) => {
        if (err || !user) return;

        const msgString = JSON.stringify({
            type: 'typing',
            user_id: userId,
            username: user.username,
            is_typing: isTyping
        });

        chatConnections.forEach(connections => {
            connections.forEach(ws => {
                if (ws.readyState === 1) {
                    ws.send(msgString);
                }
            });
        });
    });
}

// Mettre à jour les membres en ligne toutes les 30 secondes
setInterval(broadcastChatMembersUpdate, 30000);

console.log('✅ WebSocket chat initialisé sur /ws/chat');

// =============================================
// SSE — CONSOLE PTERODACTYL (/api/servers/:id/console/sse)
// =============================================
// Le backend maintient UN WebSocket Pterodactyl par serveur (partagé).
// La sortie console est streamée aux clients via SSE (HTTP pur, proxy-friendly).
// Les commandes vont via POST /api/servers/:id/command (endpoint existant).

function stripAnsi(str) {
    return String(str).replace(/\x1B\[[0-9;]*[mGKHF]/g, '').replace(/\x1B\[[0-9;]*[A-Za-z]/g, '');
}

// Map: serverIdentifier -> { pterWs, clients: Set<res>, reconnTimer, authToken, socketUrl, closed }
const pterSessions = new Map();

function sseConsoleBroadcast(identifier, data) {
    const s = pterSessions.get(identifier);
    if (!s) return;
    s.clients.forEach(r => sseSend(r, data));
}

async function ensurePterodactylSession(identifier) {
    if (pterSessions.has(identifier)) return pterSessions.get(identifier);
    const session = { pterWs: null, clients: new Set(), reconnTimer: null, authToken: null, socketUrl: null, closed: false };
    pterSessions.set(identifier, session);
    await connectPterodactylSession(identifier, session);
    return session;
}

async function fetchPterodactylToken(identifier) {
    const resp = await fetch(
        `${PTERODACTYL_CONFIG.url}/api/client/servers/${identifier}/websocket`,
        { headers: { 'Authorization': `Bearer ${PTERODACTYL_CONFIG.clientApiKey}`, 'Accept': 'application/json' } }
    );
    const body = await resp.json();
    if (!body?.data?.token || !body?.data?.socket) throw new Error('Réponse API invalide');
    return { token: body.data.token, socket: body.data.socket };
}

async function refreshPterodactylToken(identifier, session) {
    if (session.closed) return;
    try {
        const { token } = await fetchPterodactylToken(identifier);
        session.authToken = token;
        if (session.pterWs?.readyState === 1) {
            session.pterWs.send(JSON.stringify({ event: 'auth', args: [token] }));
        }
    } catch(e) {
        clearTimeout(session.reconnTimer);
        session.reconnTimer = setTimeout(() => connectPterodactylSession(identifier, session), 8000);
    }
}

async function connectPterodactylSession(identifier, session) {
    if (session.closed) return;
    if (session.pterWs) {
        try { session.pterWs.terminate(); } catch(_) {}
        session.pterWs = null;
    }
    try {
        const { token, socket } = await fetchPterodactylToken(identifier);
        session.authToken = token;
        session.socketUrl = socket;
    } catch(e) {
        clearTimeout(session.reconnTimer);
        session.reconnTimer = setTimeout(() => connectPterodactylSession(identifier, session), 15000);
        return;
    }

    const pterWs = new WsClient(session.socketUrl, { origin: PTERODACTYL_CONFIG.url });
    session.pterWs = pterWs;

    pterWs.on('open', () => {
        pterWs.send(JSON.stringify({ event: 'auth', args: [session.authToken] }));
    });

    pterWs.on('message', (raw) => {
        try {
            const msg = JSON.parse(raw.toString());
            const ev = msg.event; const args = msg.args || [];
            if (ev === 'auth success') {
                pterWs.send(JSON.stringify({ event: 'send logs', args: [] }));
                sseConsoleBroadcast(identifier, { type: 'sys', message: '✅ Console connectée' });
            } else if (ev === 'console output') {
                args.forEach(line => {
                    if (line && line.trim()) sseConsoleBroadcast(identifier, { type: 'console', message: stripAnsi(line) });
                });
            } else if (ev === 'status') {
                sseConsoleBroadcast(identifier, { type: 'status', status: args[0] });
            } else if (ev === 'token expiring' || ev === 'token expired') {
                clearTimeout(session.reconnTimer);
                refreshPterodactylToken(identifier, session);
            }
        } catch(e) {}
    });

    pterWs.on('close', () => {
        if (session.pterWs === pterWs) session.pterWs = null;
        if (!session.closed && session.clients.size > 0) {
            clearTimeout(session.reconnTimer);
            session.reconnTimer = setTimeout(() => connectPterodactylSession(identifier, session), 8000);
        }
    });

    pterWs.on('error', () => {});
}

function sendToPterodactyl(identifier, command) {
    const s = pterSessions.get(identifier);
    if (s?.pterWs?.readyState === 1) {
        s.pterWs.send(JSON.stringify({ event: 'send command', args: [command] }));
        return true;
    }
    return false;
}

app.get('/api/servers/:serverId/console/sse', (req, res) => {
    const { serverId } = req.params;
    const token = req.query.token;
    if (!token) { res.status(401).end(); return; }

    jwt.verify(token, WEB_CONFIG.JWT_SECRET, (err, user) => {
        if (err) { res.status(401).end(); return; }

        db.get('SELECT role FROM users WHERE id = ?', [user.userId], (e2, userRow) => {
            const isAdmin = userRow?.role === 'superadmin' || userRow?.role === 'admin';
            const q = isAdmin ? 'SELECT * FROM servers WHERE id = ?' : 'SELECT * FROM servers WHERE id = ? AND user_id = ?';
            const p = isAdmin ? [serverId] : [serverId, user.userId];

            db.get(q, p, (e3, srv) => {
                if (e3 || !srv) { res.status(404).end(); return; }

                res.writeHead(200, {
                    'Content-Type': 'text/event-stream',
                    'Cache-Control': 'no-cache',
                    'Connection': 'keep-alive',
                    'X-Accel-Buffering': 'no',
                    'Access-Control-Allow-Origin': '*'
                });
                res.flushHeaders();

                const identifier = srv.server_identifier;
                sseSend(res, { type: 'sys', message: '🔌 Connexion à la console...' });

                ensurePterodactylSession(identifier).then(session => {
                    session.clients.add(res);
                    // Heartbeat SSE data toutes les 2s pour garder la connexion via proxy Replit
                    const hb = setInterval(() => sseSend(res, { type: 'hb' }), 2000);
                    req.on('close', () => {
                        clearInterval(hb);
                        session.clients.delete(res);
                        // Si plus personne écoute, on ferme la session Pterodactyl
                        if (session.clients.size === 0) {
                            session.closed = true;
                            clearTimeout(session.reconnTimer);
                            if (session.pterWs) { session.pterWs.terminate(); session.pterWs = null; }
                            pterSessions.delete(identifier);
                        }
                    });
                }).catch(() => sseSend(res, { type: 'error', message: '❌ Erreur session' }));
            });
        });
    });
});

// Endpoint pour envoyer une commande via SSE console (en plus du /command existant)
app.post('/api/servers/:serverId/console/command', authenticateToken, async (req, res) => {
    const { serverId } = req.params;
    const { command } = req.body;
    const userId = req.user.userId;
    if (!command) { res.status(400).json({ success: false, error: 'Commande requise' }); return; }

    db.get('SELECT role FROM users WHERE id = ?', [userId], (e2, userRow) => {
        const isAdmin = userRow?.role === 'superadmin' || userRow?.role === 'admin';
        const q = isAdmin ? 'SELECT * FROM servers WHERE id = ?' : 'SELECT * FROM servers WHERE id = ? AND user_id = ?';
        const p = isAdmin ? [serverId] : [serverId, userId];
        db.get(q, p, (e3, srv) => {
            if (e3 || !srv) { res.status(404).json({ success: false, error: 'Serveur non trouvé' }); return; }
            const ok = sendToPterodactyl(srv.server_identifier, command);
            if (ok) {
                sseConsoleBroadcast(srv.server_identifier, { type: 'cmd_echo', message: `> ${command}` });
                res.json({ success: true });
            } else {
                res.status(503).json({ success: false, error: 'Console non connectée' });
            }
        });
    });
});

console.log('✅ SSE console Pterodactyl initialisé sur /api/servers/:id/console/sse');

// Catch-all 404 — doit être APRÈS toutes les routes API et SSE
app.get('/{*path}', (req, res) => res.sendFile(path.join(__dirname, '404.html')));

// =============================================
// GESTION DES SIGNAUX D'ARRÊT
// =============================================

process.on('SIGINT', () => {
    console.log('\n🛑 Arrêt du serveur...');
    
    server.close(() => {
        console.log('✅ Serveur HTTP arrêté');
        
        db.close((err) => {
            if (err) {
                console.error('❌ Erreur fermeture BD:', err);
            } else {
                console.log('✅ Base de données fermée');
            }
            process.exit(0);
        });
    });
});

process.on('SIGTERM', () => {
    console.log('\n🛑 Signal d\'arrêt reçu');
    process.exit(0);
});

process.on('uncaughtException', (err) => {
    console.error('❌ Exception non capturée:', err);
    logSystem('critical', 'Exception non capturée', {
        message: err.message,
        stack: err.stack
    });
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Rejet non géré:', reason);
    logSystem('critical', 'Rejet non géré', {
        reason: reason?.toString(),
        promise
    });
});

console.log('✅ Système FLYHOST initialisé avec succès');