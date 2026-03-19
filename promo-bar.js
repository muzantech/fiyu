/**
 * FLYHOST Promo Bar — Bandeau de promotions / réductions
 * Incluez ce script sur n'importe quelle page pour afficher les promos actives.
 * Usage : <script src="/promo-bar.js"></script>
 */
(function() {
    'use strict';

    const PALETTES = {
        purple:  { bg: 'linear-gradient(135deg,#6366f1 0%,#7c3aed 100%)', badge: '#fff', badgeBg: 'rgba(255,255,255,.22)', ticker: '#6366f1', glow: 'rgba(99,102,241,.45)' },
        orange:  { bg: 'linear-gradient(135deg,#f97316 0%,#ef4444 100%)', badge: '#fff', badgeBg: 'rgba(255,255,255,.22)', ticker: '#f97316', glow: 'rgba(249,115,22,.45)' },
        green:   { bg: 'linear-gradient(135deg,#10b981 0%,#06b6d4 100%)', badge: '#fff', badgeBg: 'rgba(255,255,255,.22)', ticker: '#10b981', glow: 'rgba(16,185,129,.45)' },
        red:     { bg: 'linear-gradient(135deg,#ef4444 0%,#dc2626 100%)', badge: '#fff', badgeBg: 'rgba(255,255,255,.22)', ticker: '#ef4444', glow: 'rgba(239,68,68,.45)' },
        blue:    { bg: 'linear-gradient(135deg,#3b82f6 0%,#2563eb 100%)', badge: '#fff', badgeBg: 'rgba(255,255,255,.22)', ticker: '#3b82f6', glow: 'rgba(59,130,246,.45)' },
        gold:    { bg: 'linear-gradient(135deg,#f59e0b 0%,#d97706 100%)', badge: '#fff', badgeBg: 'rgba(255,255,255,.22)', ticker: '#f59e0b', glow: 'rgba(245,158,11,.45)' },
    };

    // ───────── STYLES ─────────
    const CSS = `
    #fh-promo-root { font-family: 'Plus Jakarta Sans', 'Segoe UI', sans-serif; }

    /* ── TICKER BAR (slim, top of page) ── */
    #fh-ticker-bar {
        position: fixed; top: 0; left: 0; right: 0; z-index: 99999;
        height: 36px; display: flex; align-items: center; overflow: hidden;
        box-shadow: 0 2px 16px var(--promo-glow,rgba(99,102,241,.4));
        transition: top .3s;
    }
    #fh-ticker-bar .fh-ticker-close {
        flex-shrink: 0; width: 28px; height: 28px; border-radius: 50%;
        background: rgba(255,255,255,.18); border: none; color: #fff;
        font-size: 13px; cursor: pointer; margin-right: 6px; transition: background .2s;
        display: flex; align-items: center; justify-content: center;
    }
    #fh-ticker-bar .fh-ticker-close:hover { background: rgba(255,255,255,.35); }
    .fh-ticker-track { flex: 1; overflow: hidden; position: relative; white-space: nowrap; }
    .fh-ticker-content {
        display: inline-block; white-space: nowrap;
        animation: fhTickerScroll 28s linear infinite;
        color: #fff; font-size: 13px; font-weight: 700; letter-spacing: .02em;
    }
    .fh-ticker-content:hover { animation-play-state: paused; }
    .fh-ticker-sep { margin: 0 28px; opacity: .5; }
    .fh-ticker-tag {
        display: inline-block; background: rgba(255,255,255,.25);
        border-radius: 20px; padding: 1px 10px; margin-right: 10px; font-size: 11px;
    }
    .fh-ticker-pct {
        display: inline-block; background: #fff; color: var(--promo-ticker, #6366f1);
        border-radius: 20px; padding: 0px 9px; font-size: 12px; font-weight: 900;
        margin: 0 6px;
    }
    @keyframes fhTickerScroll { from { transform: translateX(100vw); } to { transform: translateX(-100%); } }

    /* ── PROMO CARDS (injected into page) ── */
    #fh-promo-cards-wrap {
        width: 100%; box-sizing: border-box; display: flex; flex-direction: column; gap: 12px;
        margin-bottom: 20px;
    }
    .fh-promo-card {
        border-radius: 18px; overflow: hidden; position: relative;
        box-shadow: 0 8px 32px var(--promo-glow,rgba(99,102,241,.3));
        display: flex; min-height: 120px;
    }
    .fh-promo-bg {
        position: absolute; inset: 0; z-index: 0;
    }
    .fh-promo-pattern {
        position: absolute; inset: 0; z-index: 1; pointer-events: none;
        background-image: radial-gradient(circle at 80% 50%, rgba(255,255,255,.08) 0%, transparent 60%),
                          url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.04'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
    }
    .fh-promo-body {
        position: relative; z-index: 2; padding: 18px 20px;
        display: flex; align-items: center; gap: 16px; flex: 1; flex-wrap: wrap;
    }
    .fh-promo-badge {
        flex-shrink: 0; background: rgba(255,255,255,.22);
        border: 2px solid rgba(255,255,255,.4); border-radius: 16px;
        padding: 10px 14px; text-align: center; min-width: 80px;
    }
    .fh-promo-badge-pct { font-size: 30px; font-weight: 900; color: #fff; line-height: 1; }
    .fh-promo-badge-label { font-size: 10px; font-weight: 700; color: rgba(255,255,255,.8); letter-spacing: .06em; text-transform: uppercase; margin-top: 2px; }
    .fh-promo-info { flex: 1; min-width: 160px; }
    .fh-promo-tag { display: inline-block; background: rgba(255,255,255,.25); color: #fff; border-radius: 20px; padding: 2px 12px; font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: .06em; margin-bottom: 6px; }
    .fh-promo-title { font-size: 18px; font-weight: 800; color: #fff; line-height: 1.2; margin-bottom: 4px; }
    .fh-promo-sub { font-size: 13px; color: rgba(255,255,255,.82); font-weight: 500; }
    .fh-promo-pricing { display: flex; align-items: center; gap: 10px; margin-top: 8px; }
    .fh-promo-orig { font-size: 14px; color: rgba(255,255,255,.55); text-decoration: line-through; font-weight: 600; }
    .fh-promo-new { font-size: 22px; font-weight: 900; color: #fff; }
    .fh-promo-unit { font-size: 12px; color: rgba(255,255,255,.7); font-weight: 600; }
    .fh-promo-right { display: flex; flex-direction: column; align-items: flex-end; gap: 10px; flex-shrink: 0; }
    .fh-countdown { display: flex; gap: 6px; align-items: center; }
    .fh-cd-unit { background: rgba(0,0,0,.25); border-radius: 8px; padding: 4px 8px; text-align: center; min-width: 38px; }
    .fh-cd-val { font-size: 18px; font-weight: 800; color: #fff; line-height: 1; }
    .fh-cd-lbl { font-size: 9px; color: rgba(255,255,255,.65); text-transform: uppercase; font-weight: 700; }
    .fh-cd-sep { font-size: 18px; font-weight: 900; color: rgba(255,255,255,.6); margin-top: -4px; }
    .fh-promo-cta {
        display: inline-flex; align-items: center; gap: 7px;
        background: #fff; border-radius: 10px; padding: 10px 20px;
        font-size: 13px; font-weight: 800; text-decoration: none; cursor: pointer; border: none;
        color: var(--promo-ticker, #6366f1); font-family: inherit;
        box-shadow: 0 4px 16px rgba(0,0,0,.2); transition: transform .2s, box-shadow .2s;
        white-space: nowrap;
    }
    .fh-promo-cta:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,0,0,.25); }
    .fh-promo-close-card {
        position: absolute; top: 10px; right: 12px; z-index: 3;
        background: rgba(255,255,255,.18); border: none; color: #fff;
        width: 24px; height: 24px; border-radius: 50%; cursor: pointer;
        font-size: 12px; display: flex; align-items: center; justify-content: center;
        transition: background .2s;
    }
    .fh-promo-close-card:hover { background: rgba(255,255,255,.35); }

    /* ── POPUP MODAL ── */
    #fh-promo-popup-overlay {
        position: fixed; inset: 0; background: rgba(0,0,0,.65); z-index: 99998;
        display: flex; align-items: center; justify-content: center;
        backdrop-filter: blur(6px); padding: 20px; box-sizing: border-box;
        animation: fhFadeIn .3s ease;
    }
    @keyframes fhFadeIn { from { opacity: 0; } to { opacity: 1; } }
    .fh-popup-inner {
        border-radius: 24px; overflow: hidden; max-width: 480px; width: 100%;
        box-shadow: 0 30px 80px rgba(0,0,0,.5); animation: fhSlideUp .4s cubic-bezier(.34,1.56,.64,1);
        position: relative;
    }
    @keyframes fhSlideUp { from { transform: translateY(40px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
    .fh-popup-header {
        position: relative; padding: 36px 28px 28px; text-align: center;
        display: flex; flex-direction: column; align-items: center; gap: 10px;
    }
    .fh-popup-badge { font-size: 52px; font-weight: 900; color: #fff; line-height: 1; }
    .fh-popup-badge-sub { font-size: 13px; font-weight: 700; color: rgba(255,255,255,.8); text-transform: uppercase; letter-spacing: .08em; margin-top: -6px; }
    .fh-popup-title { font-size: 22px; font-weight: 800; color: #fff; }
    .fh-popup-sub { font-size: 14px; color: rgba(255,255,255,.82); font-weight: 500; }
    .fh-popup-body { background: #fff; padding: 24px 28px; display: flex; flex-direction: column; align-items: center; gap: 16px; }
    .fh-popup-pricing { display: flex; align-items: baseline; gap: 10px; justify-content: center; }
    .fh-popup-orig { font-size: 16px; text-decoration: line-through; color: #94a3b8; font-weight: 600; }
    .fh-popup-new { font-size: 36px; font-weight: 900; color: var(--promo-ticker,#6366f1); }
    .fh-popup-unit { font-size: 13px; color: #94a3b8; font-weight: 600; }
    .fh-popup-cta {
        display: inline-flex; align-items: center; justify-content: center; gap: 8px;
        width: 100%; padding: 14px 20px; border-radius: 12px; border: none;
        font-size: 15px; font-weight: 800; cursor: pointer; font-family: inherit;
        color: #fff; text-decoration: none; transition: transform .2s, box-shadow .2s;
        box-shadow: 0 6px 20px rgba(0,0,0,.2);
    }
    .fh-popup-cta:hover { transform: translateY(-2px); box-shadow: 0 10px 28px rgba(0,0,0,.25); }
    .fh-popup-close {
        position: absolute; top: 14px; right: 16px; background: rgba(255,255,255,.2);
        border: none; color: #fff; width: 28px; height: 28px; border-radius: 50%;
        cursor: pointer; font-size: 13px; display: flex; align-items: center;
        justify-content: center; transition: background .2s;
    }
    .fh-popup-close:hover { background: rgba(255,255,255,.35); }
    .fh-popup-dismiss { font-size: 12px; color: #94a3b8; cursor: pointer; text-decoration: underline; }

    /* ── RESPONSIVE ── */
    @media(max-width:600px) {
        .fh-promo-body { flex-wrap: wrap; gap: 10px; padding: 16px 14px; }
        .fh-promo-badge { display: none; }
        .fh-promo-info { min-width: 0; flex: 1 1 100%; }
        .fh-promo-right { align-items: flex-start; flex: 1 1 auto; flex-direction: row; flex-wrap: wrap; gap: 10px; }
        .fh-promo-title { font-size: 15px; }
        .fh-promo-pricing { flex-wrap: wrap; gap: 6px; align-items: baseline; }
        .fh-promo-new { font-size: 17px; }
        .fh-promo-orig { font-size: 12px; }
        .fh-countdown { flex-wrap: wrap; }
        .fh-cd-val { font-size: 15px; }
        .fh-cd-unit { min-width: 30px; padding: 3px 6px; }
    }
    `;

    // ───────── INJECT STYLES ─────────
    function injectStyles() {
        const s = document.createElement('style');
        s.id = 'fh-promo-styles';
        s.textContent = CSS;
        document.head.appendChild(s);
    }

    // ───────── COUNTDOWN ─────────
    function startCountdown(el, endsAt, tickerColorVar) {
        if (!el || !endsAt) return;
        function update() {
            const diff = new Date(endsAt) - Date.now();
            if (diff <= 0) { el.textContent = 'Terminé'; return; }
            const d = Math.floor(diff / 86400000);
            const h = Math.floor((diff % 86400000) / 3600000);
            const m = Math.floor((diff % 3600000) / 60000);
            const s = Math.floor((diff % 60000) / 1000);
            const units = d > 0
                ? [['J', d], ['H', h], ['M', m], ['S', s]]
                : [['H', h], ['M', m], ['S', s]];
            el.innerHTML = units.map(([l, v], i) =>
                `${i > 0 ? '<span class="fh-cd-sep">:</span>' : ''}<div class="fh-cd-unit"><div class="fh-cd-val">${String(v).padStart(2,'0')}</div><div class="fh-cd-lbl">${l}</div></div>`
            ).join('');
        }
        update();
        setInterval(update, 1000);
    }

    // ───────── BUILD TICKER BAR ─────────
    function buildTickerBar(promos) {
        const tickerPromos = promos.filter(p => p.display_type === 'ticker' || p.display_type === 'banner');
        if (!tickerPromos.length) return;

        const dismissed = (localStorage.getItem('fh_ticker_dismissed') || '').split(',');
        const visible = tickerPromos.filter(p => !dismissed.includes(String(p.id)));
        if (!visible.length) return;

        const top = visible[0];
        const pal = PALETTES[top.color_scheme] || PALETTES.purple;

        const bar = document.createElement('div');
        bar.id = 'fh-ticker-bar';
        bar.style.background = pal.bg;
        bar.style.setProperty('--promo-glow', pal.glow);
        bar.style.setProperty('--promo-ticker', pal.ticker);

        const items = visible.map(p => {
            const pct = p.discount_percent ? `<span class="fh-ticker-pct">-${p.discount_percent}%</span>` : '';
            const price = p.promo_price ? `· ${p.promo_price} ` : '';
            return `<span class="fh-ticker-tag">${p.badge_text || 'PROMO'}</span>${pct}<strong>${p.title}</strong> ${p.subtitle ? '— '+p.subtitle+' ' : ''}${price}`;
        }).join('<span class="fh-ticker-sep">★</span>');

        bar.innerHTML = `
            <div style="padding:0 10px;flex-shrink:0;color:#fff;font-size:14px;">🔥</div>
            <div class="fh-ticker-track">
                <div class="fh-ticker-content">${items}<span class="fh-ticker-sep">★</span>${items}</div>
            </div>
            <button class="fh-ticker-close" title="Fermer">✕</button>`;

        bar.querySelector('.fh-ticker-close').onclick = () => {
            bar.style.opacity = '0';
            bar.style.transition = 'opacity .3s';
            setTimeout(() => bar.remove(), 300);
            const ids = visible.map(p => p.id).join(',');
            localStorage.setItem('fh_ticker_dismissed', ids);
            // Remove top offset from body
            document.body.style.paddingTop = '';
            document.querySelectorAll('[data-fh-offset]').forEach(el => el.style.marginTop = '');
        };

        document.body.prepend(bar);

        // Push content down
        setTimeout(() => {
            const h = bar.offsetHeight;
            // Push fixed navbars down if present
            const nav = document.querySelector('.fh-topbar, .topbar, .navbar, #topbar, header');
            if (nav) {
                nav.style.transition = 'top .3s';
                nav.style.top = h + 'px';
            }
            // Adjust notification panel top
            const notifPanel = document.querySelector('.fh-notif-panel');
            if (notifPanel) notifPanel.style.top = (h + 68) + 'px';
            document.body.style.paddingTop = (parseInt(document.body.style.paddingTop)||0) + h + 'px';
        }, 50);
    }

    // ───────── BUILD PROMO CARD ─────────
    function buildPromoCard(promo) {
        const pal = PALETTES[promo.color_scheme] || PALETTES.purple;
        const dismissed = (localStorage.getItem('fh_promo_dismissed') || '').split(',');
        if (dismissed.includes(String(promo.id))) return null;

        const card = document.createElement('div');
        card.className = 'fh-promo-card';
        card.style.setProperty('--promo-ticker', pal.ticker);
        card.style.setProperty('--promo-glow', pal.glow);

        const pricingHtml = (promo.original_price || promo.promo_price) ? `
            <div class="fh-promo-pricing">
                ${promo.original_price ? `<div class="fh-promo-orig">${promo.original_price}</div>` : ''}
                ${promo.promo_price ? `<div class="fh-promo-new">${promo.promo_price}</div>` : ''}
            </div>` : '';

        const cdHtml = (promo.show_countdown && promo.ends_at) ? `<div class="fh-countdown" id="fh-cd-${promo.id}"></div>` : '';

        card.innerHTML = `
            <div class="fh-promo-bg" style="background:${pal.bg}"></div>
            <div class="fh-promo-pattern"></div>
            <div class="fh-promo-body">
                ${promo.discount_percent ? `
                <div class="fh-promo-badge">
                    <div class="fh-promo-badge-pct">-${promo.discount_percent}%</div>
                    <div class="fh-promo-badge-label">${promo.badge_text || 'PROMO'}</div>
                </div>` : ''}
                <div class="fh-promo-info">
                    ${promo.server_type ? `<div class="fh-promo-tag">${promo.server_type}</div>` : `<div class="fh-promo-tag">${promo.badge_text || 'OFFRE'}</div>`}
                    <div class="fh-promo-title">${promo.title}</div>
                    ${promo.subtitle ? `<div class="fh-promo-sub">${promo.subtitle}</div>` : ''}
                    ${pricingHtml}
                </div>
                <div class="fh-promo-right">
                    ${cdHtml}
                    <a href="${promo.cta_url || '/pricing'}" class="fh-promo-cta" style="color:${pal.ticker}">
                        <i class="fas fa-bolt"></i> ${promo.cta_text || 'En profiter'}
                    </a>
                </div>
            </div>
            <button class="fh-promo-close-card" title="Fermer">✕</button>`;

        card.querySelector('.fh-promo-close-card').onclick = () => {
            card.style.transition = 'opacity .3s, transform .3s';
            card.style.opacity = '0';
            card.style.transform = 'translateY(-8px)';
            setTimeout(() => card.remove(), 300);
            const d = (localStorage.getItem('fh_promo_dismissed') || '').split(',').filter(Boolean);
            d.push(String(promo.id));
            localStorage.setItem('fh_promo_dismissed', d.join(','));
        };

        // Start countdown
        if (promo.show_countdown && promo.ends_at) {
            setTimeout(() => startCountdown(card.querySelector(`#fh-cd-${promo.id}`), promo.ends_at, pal.ticker), 10);
        }

        return card;
    }

    // ───────── BUILD POPUP ─────────
    function buildPopup(promo) {
        const pal = PALETTES[promo.color_scheme] || PALETTES.purple;
        const dismissed = (localStorage.getItem('fh_popup_dismissed') || '').split(',');
        if (dismissed.includes(String(promo.id))) return;

        const overlay = document.createElement('div');
        overlay.id = 'fh-promo-popup-overlay';
        overlay.style.setProperty('--promo-ticker', pal.ticker);

        const cdHtml = (promo.show_countdown && promo.ends_at) ? `<div class="fh-countdown" id="fh-popup-cd-${promo.id}" style="justify-content:center"></div>` : '';
        const pricingHtml = (promo.original_price || promo.promo_price) ? `
            <div class="fh-popup-pricing">
                ${promo.original_price ? `<div class="fh-popup-orig">${promo.original_price}</div>` : ''}
                ${promo.promo_price ? `<div class="fh-popup-new">${promo.promo_price}</div>` : ''}
            </div>` : '';

        overlay.innerHTML = `
            <div class="fh-popup-inner">
                <div class="fh-popup-header" style="background:${pal.bg}">
                    <button class="fh-popup-close">✕</button>
                    ${promo.discount_percent ? `<div class="fh-popup-badge">-${promo.discount_percent}%</div><div class="fh-popup-badge-sub">${promo.badge_text || 'de réduction'}</div>` : `<div class="fh-popup-badge">🎉</div>`}
                    <div class="fh-popup-title">${promo.title}</div>
                    ${promo.subtitle ? `<div class="fh-popup-sub">${promo.subtitle}</div>` : ''}
                </div>
                <div class="fh-popup-body">
                    ${pricingHtml}
                    ${cdHtml}
                    <a href="${promo.cta_url || '/pricing'}" class="fh-popup-cta" style="background:${pal.bg}">
                        <i class="fas fa-bolt"></i> ${promo.cta_text || 'En profiter'}
                    </a>
                    <span class="fh-popup-dismiss">Ne plus afficher cette offre</span>
                </div>
            </div>`;

        function close(dismiss) {
            overlay.style.opacity = '0';
            overlay.style.transition = 'opacity .3s';
            setTimeout(() => overlay.remove(), 300);
            if (dismiss) {
                const d = (localStorage.getItem('fh_popup_dismissed') || '').split(',').filter(Boolean);
                d.push(String(promo.id));
                localStorage.setItem('fh_popup_dismissed', d.join(','));
            }
        }

        overlay.querySelector('.fh-popup-close').onclick = () => close(false);
        overlay.querySelector('.fh-popup-dismiss').onclick = () => close(true);
        overlay.onclick = (e) => { if (e.target === overlay) close(false); };

        document.body.appendChild(overlay);

        if (promo.show_countdown && promo.ends_at) {
            setTimeout(() => startCountdown(overlay.querySelector(`#fh-popup-cd-${promo.id}`), promo.ends_at, pal.ticker), 10);
        }
    }

    // ───────── INJECT INTO PAGE ─────────
    function injectPromos(promos) {
        const bannerPromos = promos.filter(p => p.display_type === 'banner');
        const popupPromos  = promos.filter(p => p.display_type === 'popup');

        // Cards: inject into .promo-inject-zone or before first .stats-grid or first .card
        if (bannerPromos.length) {
            let zone = document.getElementById('promo-inject-zone');
            if (!zone) {
                zone = document.querySelector('.stats-grid, .cards-grid, .dashboard-cards, main .container');
            }
            if (zone) {
                const wrap = document.createElement('div');
                wrap.id = 'fh-promo-cards-wrap';
                bannerPromos.forEach(p => {
                    const card = buildPromoCard(p);
                    if (card) wrap.appendChild(card);
                });
                if (wrap.children.length) zone.appendChild(wrap);
            }
        }

        // Popup: show first popup after 1.5s
        if (popupPromos.length) {
            const seenThisSession = sessionStorage.getItem('fh_popup_seen');
            if (!seenThisSession) {
                setTimeout(() => {
                    buildPopup(popupPromos[0]);
                    sessionStorage.setItem('fh_popup_seen', '1');
                }, 1500);
            }
        }
    }

    // ───────── MAIN ─────────
    async function init() {
        injectStyles();
        try {
            const res = await fetch('/api/promotions');
            const data = await res.json();
            if (!data.success || !data.promotions?.length) return;
            const promos = data.promotions;
            buildTickerBar(promos);
            injectPromos(promos);
        } catch (e) {
            // Silently fail if no promos
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Expose globally for manual refresh
    window.FHPromoBar = { refresh: init };
})();
