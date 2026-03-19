# FLYHOST Platform

## Overview
A comprehensive hosting platform featuring:
- Gaming panels (Pterodactyl integration)
- Web deployment panels
- Reseller system with 3-tier API (user | reseller | superadmin)
- MoneyFusion payment integration
- Real-time WebSocket chat
- SSE-based server console streaming

## Architecture
- **Runtime**: Node.js 18+ (ESM modules)
- **Framework**: Express 5
- **Database**: SQLite3 (`flyhost.db`)
- **Real-time**: WebSocket (ws) + Server-Sent Events
- **Auth**: JWT (jsonwebtoken) + bcryptjs
- **Port**: 5000

## Key Files
- `index.js` - Main server (15k+ lines, all-in-one backend + static file server)
- `flyhost.db` - SQLite database (persisted)
- `*.html` - Frontend pages served as static files
- `whatsapp-bot.js` - WhatsApp bot integration
- `uploads/` - User-uploaded files (chat images, deployment archives)

## Running the App
```bash
node index.js
```
Server starts on port 5000.

## Deployment
- Target: `vm` (always-running, needed for WebSockets and SQLite persistence)
- Run command: `node index.js`

## Environment Variables (Optional)
- `PORT` - Override default port (5000)
- `SMTP_*` - Email configuration for nodemailer
- `NODE_ENV` - Set to `production` to disable cache headers
