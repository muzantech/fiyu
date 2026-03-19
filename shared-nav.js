/* ===== FLYHOST SHARED NAVIGATION — v2 ===== */
(function(){
'use strict';

const NAV_LINKS = [
    { section:'PRINCIPAL' },
    { href:'/dashboard',    icon:'fa-chart-pie',       label:'Dashboard' },
    { href:'/payment',      icon:'fa-credit-card',     label:'Paiement' },
    { href:'/deploy',       icon:'fa-code-branch',     label:'Déploiement' },
    { href:'/profile',      icon:'fa-user',            label:'Mon profil' },
    { href:'/history',      icon:'fa-clock-rotate-left',label:'Historique' },
    { href:'/referral',     icon:'fa-user-plus',       label:'Parrainage' },
    { section:'COMMUNAUTÉ' },
    { href:'/chat',         icon:'fa-comments',        label:'Communauté' },
    { href:'/leaderboard',  icon:'fa-trophy',          label:'Classement' },
    { href:'/status',       icon:'fa-circle-dot',      label:'Statut services' },
    { href:'/marketplace',  icon:'fa-store',           label:'Marketplace' },
    { section:'COMPTE' },
    { href:'/api-keys',     icon:'fa-key',             label:'API Keys' },
    { href:'/subscription', icon:'fa-gem',             label:'Abonnement' },
    { href:'/tickets',      icon:'fa-ticket-alt',      label:'Support' },
    { href:'/invoices',     icon:'fa-file-invoice',    label:'Factures' },
    { section:'REVENDEUR', id:'fh-nav-reseller-section', hidden:true },
    { href:'/panel-admin',  icon:'fa-store',           label:'Espace Revendeur', id:'fh-nav-reseller-link', hidden:true },
    { section:'ADMIN',     id:'fh-nav-admin-section',  hidden:true },
    { href:'/root',         icon:'fa-crown',           label:'Administration', id:'fh-nav-admin-link', hidden:true },
];

const NOTIF_ICONS = { info:'ℹ️', warning:'⚠️', success:'✅', incident:'🔴', maintenance:'🔧' };

let userData = null;
let notifOpen = false;
let searchOpen = false;

/* ---- Utils ---- */
function getToken(){ return localStorage.getItem('flyhost_token'); }
function timeAgo(s){
    if(!s) return '';
    const d=Math.floor((Date.now()-new Date(s+(s.includes('Z')?'':'Z')).getTime())/1000);
    if(d<60) return 'À l\'instant';
    if(d<3600) return Math.floor(d/60)+'min';
    if(d<86400) return Math.floor(d/3600)+'h';
    return Math.floor(d/86400)+'j';
}
function initials(name){ return (name||'?')[0].toUpperCase(); }

/* ---- Inject CSS ---- */
function injectCSS(){
    if(document.querySelector('link[data-fhnav]')) return;
    const l=document.createElement('link');
    l.rel='stylesheet'; l.href='/shared-nav.css'; l.dataset.fhnav='1';
    document.head.appendChild(l);
    const fa=document.querySelector('link[href*="font-awesome"]');
    if(!fa){
        const f=document.createElement('link');
        f.rel='stylesheet';
        f.href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css';
        document.head.appendChild(f);
    }
}

/* ---- Build nav HTML ---- */
function buildDrawerNav(){
    return NAV_LINKS.map(l=>{
        if(l.section){
            const hid=l.hidden?' style="display:none"':'';
            const id=l.id?` id="${l.id}"`:'';
            return `<div class="fh-nav-section"${id}${hid}>${l.section}</div>`;
        }
        const cur=window.location.pathname;
        const active=cur===l.href||cur.startsWith(l.href+'?')?' active':'';
        const hid=l.hidden?' style="display:none"':'';
        const id=l.id?` id="${l.id}"`:'';
        return `<a href="${l.href}" class="fh-nav-item${active}"${id}${hid}>
            <i class="fas ${l.icon}"></i><span>${l.label}</span></a>`;
    }).join('');
}

function injectHTML(){
    // Low coins banner
    const lowBanner=document.createElement('div');
    lowBanner.id='fh-low-coins-banner';
    lowBanner.className='fh-low-coins-banner';
    lowBanner.innerHTML=`<span><i class="fas fa-exclamation-triangle"></i> Votre solde est faible — pensez à <a href="/payment">ajouter des coins</a> pour ne pas perdre vos serveurs.</span>
        <button onclick="document.getElementById('fh-low-coins-banner').classList.remove('show');localStorage.setItem('fh_low_dismissed',Date.now());">&times;</button>`;
    document.body.appendChild(lowBanner);

    // Topbar
    const bar=document.createElement('header');
    bar.className='fh-topbar'; bar.id='fhTopbar';
    bar.innerHTML=`
        <button class="fh-hamburger" id="fhHamburger" onclick="FHNav.toggleDrawer()" aria-label="Menu">
            <span></span><span></span><span></span>
        </button>
        <a href="/dashboard" class="fh-logo">
            <div class="fh-logo-mark">FH</div>
            <span class="fh-logo-text">FLYHOST</span>
        </a>
        <div class="fh-search-wrap" id="fhSearchWrap">
            <i class="fas fa-search fh-search-icon"></i>
            <input type="text" id="fhSearchInput" placeholder="Rechercher..." autocomplete="off"
                oninput="FHNav.onSearch(this.value)" onfocus="FHNav.showSearchResults()" />
            <div class="fh-search-results" id="fhSearchResults"></div>
        </div>
        <div class="fh-spacer"></div>
        <a class="fh-coins-chip" id="fhCoinsChip" href="/payment" title="Solde de coins">
            <i class="fas fa-coins"></i>
            <span id="fhCoinsVal">…</span>
            <div class="low-alert"></div>
        </a>
        <div class="fh-notif-wrap" id="fhNotifWrap">
            <button class="fh-notif-btn" id="fhNotifBtn" onclick="FHNav.toggleNotif()" title="Notifications">
                <i class="fa-regular fa-bell"></i>
                <div class="fh-notif-badge" id="fhNotifBadge"></div>
            </button>
            <div class="fh-notif-panel" id="fhNotifPanel">
                <div class="fh-notif-head">
                    <span><i class="fas fa-bell" style="color:var(--accent);margin-right:7px;"></i>Notifications</span>
                    <button onclick="FHNav.markAllRead()">Tout lu</button>
                </div>
                <div class="fh-notif-body" id="fhNotifBody">
                    <div class="fh-notif-empty"><i class="fa-regular fa-bell-slash" style="font-size:26px;display:block;margin-bottom:8px;"></i>Aucune notification</div>
                </div>
            </div>
        </div>
        <button class="fh-theme-btn" id="fhThemeBtn" onclick="FHNav.toggleTheme()" title="Mode sombre/clair">
            <i class="fas fa-moon" id="fhThemeIcon"></i>
        </button>
        <div class="fh-avatar" id="fhTopbarAvatar" onclick="FHNav.toggleDrawer()">?</div>
    `;
    document.body.insertBefore(bar, document.body.firstChild);

    // Overlay
    const ov=document.createElement('div');
    ov.className='fh-drawer-overlay'; ov.id='fhDrawerOverlay';
    ov.onclick=()=>FHNav.closeDrawer();
    document.body.appendChild(ov);

    // Drawer
    const dr=document.createElement('aside');
    dr.className='fh-drawer'; dr.id='fhDrawer';
    dr.innerHTML=`
        <div class="fh-drawer-head">
            <div class="fh-drawer-logo">
                <div class="fh-logo-mark" style="width:32px;height:32px;font-size:13px;">FH</div>
                <span>FLYHOST</span>
            </div>
            <button class="fh-drawer-close" onclick="FHNav.closeDrawer()">&times;</button>
        </div>
        <div class="fh-drawer-user" id="fhDrawerUser">
            <div class="fh-drawer-avatar" id="fhDrawerAvatar">?</div>
            <div>
                <div class="fh-drawer-uname" id="fhDrawerName">Chargement…</div>
                <div class="fh-drawer-meta" id="fhDrawerEmail"></div>
                <div class="fh-drawer-coins-pill">
                    <i class="fas fa-coins"></i>
                    <span id="fhDrawerCoins">0</span> coins
                </div>
            </div>
        </div>
        <nav>${buildDrawerNav()}</nav>
        <div class="fh-drawer-footer">
            <button class="fh-logout-btn" onclick="FHNav.logout()">
                <i class="fas fa-sign-out-alt"></i> Déconnexion
            </button>
        </div>
    `;
    document.body.appendChild(dr);

    // Body class
    document.body.classList.add('fh-nav-active');
}

/* ---- Theme ---- */
function initTheme(){
    const t=localStorage.getItem('fh_theme')||'light';
    document.documentElement.setAttribute('data-theme',t);
    const icon=document.getElementById('fhThemeIcon');
    if(icon) icon.className=t==='dark'?'fas fa-sun':'fas fa-moon';
}

/* ---- User data ---- */
async function loadUser(){
    const token=getToken();
    if(!token){ window.location.href='/login'; return; }
    try{
        const r=await fetch('/api/user/me',{headers:{Authorization:'Bearer '+token}});
        if(r.status===401){ window.location.href='/login'; return; }
        const d=await r.json();
        if(!d.success){ window.location.href='/login'; return; }
        userData=d.user;
        updateUserUI();
        updateRoleNav(userData.role);
        checkLowCoins(userData.coins||0);
    }catch(e){ console.warn('FHNav: user load failed',e); }
}

function updateUserUI(){
    if(!userData) return;
    const name=userData.username||userData.email||'?';
    const coins=userData.coins||0;

    // Topbar avatar
    const av=document.getElementById('fhTopbarAvatar');
    if(av){
        if(userData.avatar){ av.innerHTML=`<img src="${userData.avatar}" alt="avatar">`; }
        else { av.textContent=initials(name); }
    }
    // Drawer
    const dn=document.getElementById('fhDrawerName');
    if(dn) dn.textContent=name;
    const de=document.getElementById('fhDrawerEmail');
    if(de) de.textContent=userData.email||'';
    const da=document.getElementById('fhDrawerAvatar');
    if(da){
        if(userData.avatar){ da.innerHTML=`<img src="${userData.avatar}" alt="avatar">`; }
        else { da.textContent=initials(name); }
    }
    updateCoins(coins);
}

function updateCoins(val){
    const chip=document.getElementById('fhCoinsVal');
    if(chip){
        const old=parseInt(chip.textContent)||0;
        chip.textContent=val;
        if(val!==old){
            const c=document.getElementById('fhCoinsChip');
            if(c){ c.classList.add('fh-coins-bump'); setTimeout(()=>c.classList.remove('fh-coins-bump'),400); }
        }
    }
    const dc=document.getElementById('fhDrawerCoins');
    if(dc) dc.textContent=val;
}

function checkLowCoins(coins){
    const threshold=parseInt(localStorage.getItem('fh_coins_alert_threshold')||'10');
    const banner=document.getElementById('fh-low-coins-banner');
    const chip=document.getElementById('fhCoinsChip');
    const dismissed=parseInt(localStorage.getItem('fh_low_dismissed')||'0');
    const cooldown=6*3600*1000;
    if(coins<threshold && banner && (Date.now()-dismissed>cooldown)){
        banner.classList.add('show');
        document.body.classList.add('fh-low-coins-active');
        if(chip) chip.classList.add('low-coins');
    }
}

function updateRoleNav(role){
    const isSuperAdmin=role==='superadmin';
    const isReseller=role==='reseller'||role==='admin';
    const rs=document.getElementById('fh-nav-reseller-section');
    const rl=document.getElementById('fh-nav-reseller-link');
    const as=document.getElementById('fh-nav-admin-section');
    const al=document.getElementById('fh-nav-admin-link');
    if(isSuperAdmin){
        if(as) as.style.display=''; if(al) al.style.display='';
    } else if(isReseller){
        if(rs) rs.style.display=''; if(rl) rl.style.display='';
    }
}

/* ---- Notifications ---- */
async function loadNotifs(){
    const body=document.getElementById('fhNotifBody');
    if(!body) return;
    const token=getToken(); if(!token) return;
    try{
        const r=await fetch('/api/user/notifications',{headers:{Authorization:'Bearer '+token}});
        const d=await r.json();
        if(!d.success||!d.notifications.length){
            body.innerHTML='<div class="fh-notif-empty"><i class="fa-regular fa-bell-slash" style="font-size:26px;display:block;margin-bottom:8px;"></i>Aucune notification</div>';
            return;
        }
        body.innerHTML=d.notifications.map(n=>`
            <div class="fh-notif-item${n.is_read?'':' unread'}" onclick="FHNav._clickNotif(${n.id},'${n.link||''}')">
                <div class="fh-notif-dot" style="background:${n.type==='success'?'rgba(16,185,129,.2)':n.type==='warning'?'rgba(245,158,11,.2)':n.type==='error'?'rgba(239,68,68,.2)':'rgba(99,102,241,.2)'};">${NOTIF_ICONS[n.type]||'ℹ️'}</div>
                <div style="flex:1;min-width:0;">
                    <div class="fh-notif-item-title">${n.title}${!n.is_read?'<span style="display:inline-block;width:6px;height:6px;background:var(--accent);border-radius:50%;margin-left:5px;vertical-align:middle;"></span>':''}</div>
                    <div class="fh-notif-item-msg">${n.message}</div>
                    <div class="fh-notif-item-time">${timeAgo(n.created_at)}</div>
                </div>
            </div>`).join('');
        updateNotifBadge(d.notifications.filter(n=>!n.is_read).length);
    }catch(e){}
}

async function refreshNotifCount(){
    const token=getToken(); if(!token) return;
    try{
        const r=await fetch('/api/user/notifications/unread-count',{headers:{Authorization:'Bearer '+token}});
        const d=await r.json();
        if(d.success) updateNotifBadge(d.count);
    }catch(e){}
}

function updateNotifBadge(n){
    const b=document.getElementById('fhNotifBadge');
    if(!b) return;
    if(n>0){ b.style.display='flex'; b.textContent=n>9?'9+':n; }
    else { b.style.display='none'; }
}

/* ---- Search ---- */
const SEARCH_PAGES=[
    {label:'Dashboard',href:'/dashboard',icon:'fa-chart-pie'},
    {label:'Paiement',href:'/payment',icon:'fa-credit-card'},
    {label:'Déploiement',href:'/deploy',icon:'fa-code-branch'},
    {label:'Profil',href:'/profile',icon:'fa-user'},
    {label:'Historique',href:'/history',icon:'fa-clock-rotate-left'},
    {label:'Parrainage',href:'/referral',icon:'fa-user-plus'},
    {label:'Communauté',href:'/chat',icon:'fa-comments'},
    {label:'Classement',href:'/leaderboard',icon:'fa-trophy'},
    {label:'Statut services',href:'/status',icon:'fa-circle-dot'},
    {label:'Marketplace',href:'/marketplace',icon:'fa-store'},
    {label:'Abonnement',href:'/subscription',icon:'fa-gem'},
    {label:'Support',href:'/tickets',icon:'fa-ticket-alt'},
    {label:'Factures',href:'/invoices',icon:'fa-file-invoice'},
    {label:'API Keys',href:'/api-keys',icon:'fa-key'},
];

function doSearch(q){
    const res=document.getElementById('fhSearchResults');
    if(!res) return;
    if(!q||q.length<1){ res.classList.remove('open'); return; }
    const matches=SEARCH_PAGES.filter(p=>p.label.toLowerCase().includes(q.toLowerCase()));
    if(!matches.length){ res.classList.remove('open'); return; }
    res.innerHTML=matches.map(p=>`
        <div class="fh-search-result-item" onclick="window.location.href='${p.href}'">
            <i class="fas ${p.icon}"></i>${p.label}
        </div>`).join('');
    res.classList.add('open');
}

/* ---- Public API ---- */
window.FHNav={
    toggleDrawer(){
        const dr=document.getElementById('fhDrawer');
        const ov=document.getElementById('fhDrawerOverlay');
        const hb=document.getElementById('fhHamburger');
        const open=dr.classList.contains('open');
        dr.classList.toggle('open',!open);
        ov.classList.toggle('open',!open);
        hb.classList.toggle('is-open',!open);
        document.body.style.overflow=open?'':'hidden';
    },
    closeDrawer(){
        const dr=document.getElementById('fhDrawer');
        const ov=document.getElementById('fhDrawerOverlay');
        const hb=document.getElementById('fhHamburger');
        dr.classList.remove('open'); ov.classList.remove('open'); hb.classList.remove('is-open');
        document.body.style.overflow='';
    },
    toggleNotif(){
        notifOpen=!notifOpen;
        const p=document.getElementById('fhNotifPanel');
        if(p) p.classList.toggle('open',notifOpen);
        if(notifOpen) loadNotifs();
    },
    toggleTheme(){
        const cur=document.documentElement.getAttribute('data-theme')||'light';
        const nxt=cur==='dark'?'light':'dark';
        document.documentElement.setAttribute('data-theme',nxt);
        localStorage.setItem('fh_theme',nxt);
        const icon=document.getElementById('fhThemeIcon');
        if(icon) icon.className=nxt==='dark'?'fas fa-sun':'fas fa-moon';
    },
    markAllRead: async function(){
        const token=getToken();
        try{ await fetch('/api/user/notifications/read-all',{method:'PUT',headers:{Authorization:'Bearer '+token}}); }catch(e){}
        await loadNotifs(); updateNotifBadge(0);
    },
    _clickNotif: async function(id,link){
        const token=getToken();
        try{ await fetch(`/api/user/notifications/${id}/read`,{method:'PUT',headers:{Authorization:'Bearer '+token}}); }catch(e){}
        if(link&&link!=='null'&&link!=='undefined') window.location.href=link;
        else { await loadNotifs(); await refreshNotifCount(); }
    },
    onSearch: function(v){ doSearch(v); },
    showSearchResults(){ const r=document.getElementById('fhSearchResults'); if(r&&r.innerHTML) r.classList.add('open'); },
    logout(){
        localStorage.removeItem('flyhost_token');
        localStorage.removeItem('flyhost_user');
        window.location.href='/';
    },
    updateCoins,
    getUser(){ return userData; },
};

/* ---- Close panels on outside click ---- */
document.addEventListener('click',(e)=>{
    if(notifOpen && !e.target.closest('#fhNotifWrap')){
        notifOpen=false;
        const p=document.getElementById('fhNotifPanel');
        if(p) p.classList.remove('open');
    }
    if(!e.target.closest('#fhSearchWrap')){
        const r=document.getElementById('fhSearchResults');
        if(r) r.classList.remove('open');
    }
});

/* ---- Init ---- */
function init(){
    injectCSS();
    injectHTML();
    initTheme();
    loadUser();
    setTimeout(refreshNotifCount,1500);
    setInterval(refreshNotifCount,60000);
}

if(document.readyState==='loading'){
    document.addEventListener('DOMContentLoaded',init);
} else {
    init();
}

})();
