/*
 ═══════════════════════════════════════════════════════════════════
  VOID // SENTINEL  —  Kage Design System & Command Center Logic
  Autonomous Cyber-Deception & Honeytoken Defense
 ═══════════════════════════════════════════════════════════════════
*/

/* ── A. Seed Constants & Canary Paths ────────────────────────────── */

const CANARY_ENDPOINTS = [
  { path: '/.env',                label: '.env',               id: 'env', kanji: '秘密' },
  { path: '/admin/dump.sql',      label: 'admin/dump.sql',     id: 'sql', kanji: '基盤' },
  { path: '/api/v1/auth/tokens',  label: 'api/v1/auth/tokens', id: 'api', kanji: '証標' },
  { path: '/wp-login.php',        label: 'wp-login.php',       id: 'wp',  kanji: '門鑑' },
  { path: '/.git/config',         label: '.git/config',        id: 'git', kanji: '履歴' },
];

const GEO_TAGS = [
  'RU-MOW (Moscow)', 'CN-SHA (Shanghai)', 'KP-FNJ (Pyongyang)',
  'IR-THR (Tehran)', 'NG-LAG (Lagos)', 'DE-FRA (Proxy Node)',
  'US-TOR (Tor Exit)', 'NL-AMS (VPN Node)', 'UA-KBP (Kyiv)',
];

const ATTACK_TEMPLATES = [
  { attack_type: 'Decoy Route Access',    endpoint: '/.env',                severity: 'CRITICAL', payload: 'GET /.env HTTP/1.1\nHost: sentinel.void\nUser-Agent: Python-urllib/3.11\nAccept: */*' },
  { attack_type: 'SQL Injection Probe',   endpoint: '/admin/dump.sql',      severity: 'CRITICAL', payload: "GET /admin/dump.sql?export=all' OR '1'='1'-- HTTP/1.1" },
  { attack_type: 'Token Harvest Attempt', endpoint: '/api/v1/auth/tokens',  severity: 'CRITICAL', payload: 'POST /api/v1/auth/tokens\nContent-Type: application/json\n{"grant_type":"password","username":"root"}' },
  { attack_type: 'Admin Panel Recon',     endpoint: '/admin/dashboard',     severity: 'HIGH',     payload: 'GET /admin/dashboard HTTP/1.1\nCookie: session=synthetic_guest' },
  { attack_type: 'Wordpress Exploit Scan',endpoint: '/wp-login.php',        severity: 'CRITICAL', payload: "POST /wp-login.php\nlog=admin&pwd=' OR 1=1 --\nUser-Agent: WPScan/3.8.22" },
  { attack_type: 'Blind SSRF Probe',      endpoint: '/api/v1/fetch',        severity: 'HIGH',     payload: 'POST /api/v1/fetch\n{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}' },
  { attack_type: 'RCE Shell Injection',   endpoint: '/cgi-bin/exec.sh',     severity: 'CRITICAL', payload: 'GET /cgi-bin/exec.sh?cmd=;cat+/etc/shadow HTTP/1.1' },
  { attack_type: 'Directory Traversal',   endpoint: '/static/../../../etc/passwd', severity: 'CRITICAL', payload: 'GET /static/../../../etc/passwd HTTP/1.1' },
  { attack_type: 'Credential Stuffing',   endpoint: '/api/v1/login',        severity: 'HIGH',     payload: 'POST /api/v1/login\n{"email":"secops@void.sentinel","password":"P@ssw0rd2026!"}' },
  { attack_type: 'Git Exposure Scan',     endpoint: '/.git/config',         severity: 'CRITICAL', payload: 'GET /.git/config HTTP/1.1\nUser-Agent: gitScanner/3.4' },
  { attack_type: 'Heartbeat Ingress',     endpoint: '/api/v1/ping',         severity: 'INFO',     payload: 'GET /api/v1/ping HTTP/1.1' },
];

const ACTIONS = {
  CRITICAL: [
    'Synthetic Decoy Served • Origin IP Flagged',
    'Honeypot Trap Sprung • Session Sandboxed',
    'Canary Token Dispatched • Blacklist Queued',
    'Poisoned Credentials Returned • Alert Dispatched',
  ],
  HIGH: [
    'Rate-Throttle Applied • Fingerprint Stored',
    'Synthetic Delay Injected (1400ms)',
    'CAPTCHA Gate Enforced',
  ],
  INFO: [
    'Benign Telemetry Recorded',
    'Passthrough Verified • Zero Risk',
  ],
};

const SAMPLE_EVENTS = [
  { id:'evt_100', timestamp:'2026-10-15T11:29:51Z', client_ip:'185.220.101.47', attack_type:'Decoy Route Access',    endpoint:'/.env',               payload:'GET /.env HTTP/1.1\nHost: sentinel.void\nUser-Agent: Python-urllib/3.11', severity:'CRITICAL', action_taken:'Honeypot Trap Sprung • Session Sandboxed', geo:'RU-MOW (Moscow)' },
  { id:'evt_101', timestamp:'2026-10-15T11:29:44Z', client_ip:'45.141.84.120',  attack_type:'SQL Injection Probe',        endpoint:'/admin/dump.sql',     payload:"GET /admin/dump.sql?export=all' OR '1'='1'--",            severity:'CRITICAL', action_taken:'Synthetic Decoy Served • Origin IP Flagged', geo:'CN-SHA (Shanghai)' },
  { id:'evt_102', timestamp:'2026-10-15T11:29:38Z', client_ip:'198.98.56.12',   attack_type:'Token Harvest Attempt',      endpoint:'/api/v1/auth/tokens', payload:'POST /api/v1/auth/tokens\n{"grant_type":"password","username":"root"}', severity:'CRITICAL', action_taken:'Poisoned Credentials Returned • Alert Dispatched', geo:'KP-FNJ (Pyongyang)' },
  { id:'evt_103', timestamp:'2026-10-15T11:29:22Z', client_ip:'172.16.0.43',    attack_type:'Admin Panel Recon',          endpoint:'/admin/dashboard',    payload:'GET /admin/dashboard HTTP/1.1\nCookie: session=synthetic_guest', severity:'HIGH', action_taken:'Rate-Throttle Applied • Fingerprint Stored', geo:'DE-FRA (Proxy Node)' },
  { id:'evt_104', timestamp:'2026-10-15T11:29:10Z', client_ip:'10.0.0.112',     attack_type:'Heartbeat Ingress',          endpoint:'/api/v1/ping',         payload:'GET /api/v1/ping HTTP/1.1', severity:'INFO', action_taken:'Benign Telemetry Recorded', geo:'US-TOR (Tor Exit)' },
  { id:'evt_105', timestamp:'2026-10-15T11:28:55Z', client_ip:'91.234.56.78',   attack_type:'Git Exposure Scan',          endpoint:'/.git/config',        payload:'GET /.git/config HTTP/1.1\nUser-Agent: gitScanner/3.4', severity:'CRITICAL', action_taken:'Canary Token Dispatched • Blacklist Queued', geo:'IR-THR (Tehran)' },
];

const DECOY_RESPONSES = {
  '/.env':               '# SYNTHETIC VOID HONEYTOKEN\nDB_HOST=10.240.91.4\nDB_PASS=v01d_k4g3_t0k3n_99f2\nJWT_SECRET=canary_sig_882a\nAWS_KEY=AKIA_CANARY_TRIPWIRE',
  '/admin/dump.sql':     '-- VOID SYNTHETIC DATABASE EXPORT\n-- Decoy schema generated by Sentinel Matrix.\n-- Access logged. Honeypot engaged.',
  '/api/v1/auth/tokens': '{\n  "access_token": "canary_eyJhbGciOi...VOID_SYNTHETIC",\n  "token_type": "Bearer",\n  "expires_in": 0,\n  "status": "monitored"\n}',
  '/wp-login.php':       '<!-- Synthetic WordPress authentication portal -->\n<form name="loginform" id="loginform">\nCredentials recorded and mirrored to security feed.',
  '/.git/config':        '[core]\n\trepositoryformatversion = CANARY\n[remote "origin"]\n\turl = void://sentinel.internal/honeypot.git',
};

/* ── B. Helper Utilities ────────────────────────────────────────── */

let evtCounter = 200;
const rand     = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;
const pickFrom = arr    => arr[rand(0, arr.length - 1)];
const randIP   = ()     => `${rand(1,254)}.${rand(0,255)}.${rand(0,255)}.${rand(0,255)}`;
const fmtTime  = iso    => new Date(iso).toISOString().substr(11, 8);

const makeEvent = (overrides = {}) => {
  const tmpl = pickFrom(ATTACK_TEMPLATES);
  const sev  = overrides.severity || tmpl.severity;
  return {
    id:           `evt_${evtCounter++}`,
    timestamp:    new Date().toISOString(),
    client_ip:    randIP(),
    attack_type:  tmpl.attack_type,
    endpoint:     tmpl.endpoint,
    payload:      tmpl.payload,
    severity:     sev,
    action_taken: pickFrom(ACTIONS[sev] || ACTIONS.INFO),
    geo:          pickFrom(GEO_TAGS),
    isNew:        true,
    ...overrides,
  };
};

const computeCanaryHits = (events) => {
  const counts = {};
  CANARY_ENDPOINTS.forEach(c => { counts[c.id] = 0; });
  events.forEach(e => {
    CANARY_ENDPOINTS.forEach(c => {
      if (e.endpoint.startsWith(c.path)) counts[c.id]++;
    });
  });
  return counts;
};

/* ── C. Sub-Components ──────────────────────────────────────────── */

/* Minimal Icon Set */
const Icon = ({ name, size = 15, className = '' }) => {
  const paths = {
    shield:       <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>,
    zap:          <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>,
    eye:          <><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></>,
    search:       <><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></>,
    x:            <><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></>,
    chevrondown:  <polyline points="6 9 12 15 18 9"/>,
    ban:          <><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></>,
    activity:     <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>,
    terminal:     <><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></>,
    play:         <polygon points="5 3 19 12 5 21 5 3"/>,
    pause:        <><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></>,
    crosshair:    <><circle cx="12" cy="12" r="10"/><line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/></>,
    moon:         <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>,
    sliders:      <><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></>,
  };
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
         stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"
         strokeLinejoin="round" className={className}>
      {paths[name]}
    </svg>
  );
};

/* Severity Badge */
const SeverityBadge = ({ sev }) => {
  const cfg = {
    CRITICAL: 'text-[#e0231c] bg-[rgba(224,35,28,0.12)] border border-[rgba(224,35,28,0.4)]',
    HIGH:     'text-[#c9a24a] bg-[rgba(201,162,74,0.12)] border border-[rgba(201,162,74,0.35)]',
    INFO:     'text-[#dfe7e0] bg-[rgba(223,231,224,0.06)] border border-[rgba(223,231,224,0.2)]',
  };
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium tracking-[0.14em] uppercase ${cfg[sev] || cfg.INFO}`}>
      <span className={`w-1 h-1 rounded-full ${sev === 'CRITICAL' ? 'bg-[#e0231c] threat-dot' : sev === 'HIGH' ? 'bg-[#c9a24a]' : 'bg-[#dfe7e0]'}`}/>
      {sev}
    </span>
  );
};

/* Kage Chapter Chip */
const ChapterChip = ({ num, title, value, desc, isCritical, isSuccess }) => (
  <div className={`chip group ${isCritical ? 'border-[rgba(224,35,28,0.3)] bg-[rgba(224,35,28,0.04)]' : ''}`} data-cursor>
    <div className={`num ${isCritical ? 'text-[#e0231c] glow-vermilion' : isSuccess ? 'text-emerald-400' : 'text-[#dfe7e0]'}`}>
      {value}
    </div>
    <div className="tx">
      <b className={`flex items-center gap-1.5 ${isCritical ? 'text-[#e0231c]' : ''}`}>
        <span>{num} — {title}</span>
        {isCritical && <span className="w-1.5 h-1.5 rounded-full bg-[#e0231c] threat-dot"/>}
      </b>
      <p>{desc}</p>
    </div>
  </div>
);

/* Kage Defense Matrix Toggle */
const MatrixToggle = ({ active, onChange }) => (
  <button
    onClick={() => onChange(!active)}
    className="flex items-center gap-3 px-3 py-1.5 rounded-full bg-[rgba(5,7,10,0.85)] border border-[rgba(223,231,224,0.14)] hover:border-[rgba(223,231,224,0.3)] transition-all"
    data-cursor
    title="Toggle VOID Cyber-Deception Matrix"
  >
    <span className="text-[10px] uppercase tracking-[0.2em] text-[#aab4ad] font-medium">Defense Matrix:</span>
    <div className={`relative w-9 h-4.5 rounded-full kage-toggle border transition-colors ${active ? 'bg-[rgba(224,35,28,0.3)] border-[#e0231c]' : 'bg-zinc-900 border-zinc-700'}`}>
      <div className={`absolute top-0.5 w-3.5 h-3.5 rounded-full kage-toggle-thumb transition-transform shadow-md ${active ? 'translate-x-4.5 bg-[#e0231c]' : 'translate-x-0.5 bg-zinc-500'}`}/>
    </div>
    <span className={`text-[10px] font-semibold tracking-[0.16em] uppercase ${active ? 'text-[#e0231c]' : 'text-zinc-600'}`}>
      {active ? 'ACTIVE' : 'BYPASSED'}
    </span>
  </button>
);

/* Canary Pathways List */
const CanaryPanel = ({ events }) => {
  const hits   = computeCanaryHits(events);
  const maxHit = Math.max(...Object.values(hits), 1);

  return (
    <div className="kage-panel rounded-xl p-5 relative overflow-hidden" id="canaries">
      <div className="flex items-baseline justify-between mb-4 pb-2 border-b border-[rgba(223,231,224,0.07)]">
        <div className="flex items-center gap-2">
          <div className="text-[#e0231c]"><Icon name="crosshair" size={13}/></div>
          <span className="text-[11px] font-medium uppercase tracking-[0.22em] text-[#dfe7e0]">
            VOID Canary Endpoints
          </span>
        </div>
        <span className="font-jp text-[11px] tracking-[0.3em] text-[#aab4ad]">蜜罠路</span>
      </div>

      <div className="space-y-3.5">
        {CANARY_ENDPOINTS.map(c => {
          const count = hits[c.id] || 0;
          const pct   = Math.min(100, Math.round((count / maxHit) * 100));
          const isHot = count > 0;
          return (
            <div key={c.id} className="group cursor-pointer">
              <div className="flex items-center justify-between mb-1.5 text-xs">
                <div className="flex items-center gap-2">
                  <span className="font-jp text-[10px] text-[rgba(223,231,224,0.45)] tracking-widest">{c.kanji}</span>
                  <span className={`font-mono text-xs ${isHot ? 'text-[#dfe7e0] font-medium' : 'text-[#78837c]'}`}>
                    {c.path}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`font-mono text-xs font-semibold ${isHot ? 'text-[#e0231c]' : 'text-[#78837c]'}`}>
                    {count} {count === 1 ? 'trip' : 'trips'}
                  </span>
                  <span className="text-[9px] uppercase tracking-wider text-[rgba(223,231,224,0.3)]">ARMED</span>
                </div>
              </div>
              <div className="h-[2px] bg-[rgba(223,231,224,0.08)] rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-700 ${isHot ? 'bg-[#e0231c]' : 'bg-[rgba(223,231,224,0.2)]'}`}
                  style={{ width: `${Math.max(pct, isHot ? 8 : 2)}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>

      <div className="mt-5 pt-3 border-t border-[rgba(223,231,224,0.07)] flex items-center justify-between text-[10px] text-[#78837c] uppercase tracking-wider">
        <span>Tripwire Latency: <strong>&lt; 2ms</strong></span>
        <span>Auto-Decoy: <strong className="text-emerald-400">ENGAGED</strong></span>
      </div>
    </div>
  );
};

/* Intrusion Inspector with Kage Lantern Light Glow */
const IntrusionInspector = ({ event, onBlacklist, blacklisted }) => {
  if (!event) {
    return (
      <div className="kage-panel rounded-xl p-6 flex flex-col items-center justify-center min-h-[260px] text-center relative overflow-hidden" id="inspector">
        <div className="text-[rgba(223,231,224,0.18)] mb-3">
          <svg viewBox="0 0 44 44" fill="none" className="w-10 h-10 mx-auto">
            <circle cx="22" cy="24" r="9.5" stroke="#dfe7e0" strokeWidth="1" strokeDasharray="3 3"/>
            <path d="M6 12h32M9.5 17h25M22 8v28" stroke="#dfe7e0" strokeWidth="1"/>
          </svg>
        </div>
        <p className="text-xs uppercase tracking-[0.2em] text-[#aab4ad]">Select an intrusion event</p>
        <span className="text-[11px] text-[#78837c] mt-1 font-jp">査定待機中</span>
      </div>
    );
  }

  const isBlacklisted = blacklisted.has(event.client_ip);
  const decoy = DECOY_RESPONSES[event.endpoint] || 'Synthetic decoy content dispatched. Real backend state hidden.';

  return (
    <div className="kage-panel rounded-xl p-5 relative overflow-hidden" id="inspector">
      {/* Kage Lantern Swell Glow Behind Card */}
      <i
        className="glow glow--flame"
        style={{
          '--gx': '85%',
          '--gy': '25%',
          '--gr': '90px',
          '--gt': '4s',
          '--gt2': '6s',
          '--gc1': 'rgba(224,35,28,0.45)',
          '--gc2': 'rgba(255,90,60,0.18)',
        }}
      />

      <div className="flex items-baseline justify-between mb-4 pb-2 border-b border-[rgba(223,231,224,0.07)] relative z-10">
        <div className="flex items-center gap-2">
          <div className="text-[#e0231c]"><Icon name="eye" size={13}/></div>
          <span className="text-[11px] font-medium uppercase tracking-[0.22em] text-[#dfe7e0]">
            Intrusion Inspector
          </span>
        </div>
        <SeverityBadge sev={event.severity}/>
      </div>

      <div className="space-y-2 text-xs relative z-10">
        <div className="flex items-center justify-between py-1 border-b border-[rgba(223,231,224,0.04)]">
          <span className="text-[#78837c] uppercase tracking-wider text-[10px]">Origin IP:</span>
          <span className="font-mono text-[#dfe7e0] font-medium">{event.client_ip}</span>
        </div>
        <div className="flex items-center justify-between py-1 border-b border-[rgba(223,231,224,0.04)]">
          <span className="text-[#78837c] uppercase tracking-wider text-[10px]">Geographic Tag:</span>
          <span className="font-mono text-[#c9a24a] text-xs">{event.geo}</span>
        </div>
        <div className="flex items-center justify-between py-1 border-b border-[rgba(223,231,224,0.04)]">
          <span className="text-[#78837c] uppercase tracking-wider text-[10px]">Threat Vector:</span>
          <span className="text-[#e0231c] font-medium">{event.attack_type}</span>
        </div>
        <div className="flex items-center justify-between py-1 border-b border-[rgba(223,231,224,0.04)]">
          <span className="text-[#78837c] uppercase tracking-wider text-[10px]">Target Route:</span>
          <span className="font-mono text-rose-300">{event.endpoint}</span>
        </div>
        <div className="flex items-center justify-between py-1 border-b border-[rgba(223,231,224,0.04)]">
          <span className="text-[#78837c] uppercase tracking-wider text-[10px]">Timestamp:</span>
          <span className="font-mono text-[#aab4ad]">{fmtTime(event.timestamp)} UTC</span>
        </div>
      </div>

      {/* Captured Payload Box */}
      <div className="mt-4 relative z-10">
        <div className="flex items-center justify-between text-[10px] text-[#78837c] uppercase tracking-wider mb-1">
          <span>Captured Payload</span>
          <span className="font-jp text-[10px]">暗号文</span>
        </div>
        <pre className="p-2.5 rounded bg-[rgba(5,7,10,0.85)] border border-[rgba(223,231,224,0.1)] text-[11px] font-mono text-[#c9a24a] leading-relaxed whitespace-pre-wrap break-all max-h-24 overflow-y-auto">
{event.payload}
        </pre>
      </div>

      {/* Decoy Served Box */}
      <div className="mt-3 relative z-10">
        <div className="flex items-center justify-between text-[10px] text-[#78837c] uppercase tracking-wider mb-1">
          <span>VOID Decoy Served</span>
          <span className="text-emerald-400 text-[10px]">FAKE DISPATCH</span>
        </div>
        <pre className="p-2.5 rounded bg-[rgba(5,7,10,0.85)] border border-[rgba(52,211,153,0.2)] text-[11px] font-mono text-emerald-400/90 leading-relaxed whitespace-pre-wrap break-all max-h-24 overflow-y-auto">
{decoy}
        </pre>
      </div>

      {/* Blacklist Action Button */}
      <button
        onClick={() => onBlacklist(event.client_ip)}
        disabled={isBlacklisted}
        className={`mt-4 w-full flex items-center justify-center gap-2 py-2 rounded-lg text-xs font-medium uppercase tracking-[0.2em] transition-all relative z-10 ${
          isBlacklisted
            ? 'bg-zinc-900/60 text-zinc-600 border border-zinc-800 cursor-not-allowed'
            : 'bg-[rgba(224,35,28,0.18)] hover:bg-[rgba(224,35,28,0.32)] text-[#e0231c] border border-[rgba(224,35,28,0.5)] hover:border-[#e0231c] hover:shadow-glow-vermilion cursor-pointer'
        }`}
        data-cursor
      >
        <Icon name="ban" size={13}/>
        <span>{isBlacklisted ? 'Origin IP Quarantined' : 'Quarantine Origin IP'}</span>
      </button>
    </div>
  );
};

/* ── D. Main App Component ──────────────────────────────────────── */

const { useState, useEffect, useRef } = React;

const App = () => {
  const [events,       setEvents]      = useState(SAMPLE_EVENTS);
  const [matrixActive, setMatrix]      = useState(true);
  const [selected,     setSelected]    = useState(SAMPLE_EVENTS[0]);
  const [blacklisted,  setBlacklisted] = useState(new Set());
  const [searchIP,     setSearchIP]    = useState('');
  const [sevFilter,    setSevFilter]   = useState('All');
  const [paused,       setPaused]      = useState(false);
  const [flashTick,    setFlashTick]   = useState(0);
  const [viewMode,     setViewMode]    = useState('cinematic'); // 'hud' | 'cinematic' | 'sanctuary'

  const feedRef     = useRef(null);
  const intervalRef = useRef(null);

  /* Derived stats */
  const honeytokens = events.filter(e => e.severity === 'CRITICAL').length;
  const quarantined = Math.min(honeytokens, 31) + blacklisted.size;

  /* Sync view mode to document.body attribute for CSS backdrop opacity */
  useEffect(() => {
    document.body.dataset.view = viewMode;
  }, [viewMode]);

  /* Live feed ticker */
  useEffect(() => {
    if (!paused) {
      intervalRef.current = setInterval(() => {
        const ev = makeEvent();
        setEvents(prev => [ev, ...prev].slice(0, 250));
        setFlashTick(n => n + 1);
        if (feedRef.current) feedRef.current.scrollTop = 0;
      }, 3400);
    }
    return () => clearInterval(intervalRef.current);
  }, [paused]);

  /* Clear new flash flag */
  useEffect(() => {
    const t = setTimeout(() => setEvents(prev => prev.map(e => ({ ...e, isNew: false }))), 2200);
    return () => clearTimeout(t);
  }, [flashTick]);

  /* Force critical simulated attack */
  const triggerSimulated = () => {
    const ev = makeEvent({ severity: 'CRITICAL' });
    setEvents(prev => [ev, ...prev].slice(0, 250));
    setSelected(ev);
    if (feedRef.current) feedRef.current.scrollTop = 0;
  };

  /* Filtered events */
  const filteredEvents = events.filter(e => {
    const matchSearch = !searchIP
      || e.client_ip.includes(searchIP)
      || e.endpoint.includes(searchIP);
    const matchSev =
      sevFilter === 'All'                              ||
      (sevFilter === 'Critical' && e.severity === 'CRITICAL') ||
      (sevFilter === 'Warning'  && e.severity === 'HIGH')     ||
      (sevFilter === 'Clean'    && e.severity === 'INFO');
    return matchSearch && matchSev;
  });

  return (
    <div className={`min-h-screen flex flex-col transition-all duration-500 ${!matrixActive ? 'brightness-75 saturate-50' : ''}`}>

      {/* ══ KAGE NAVIGATION BAR ════════════════════════════════════ */}
      <header className="sticky top-0 z-40 bg-[rgba(5,7,10,0.85)] backdrop-blur-xl border-b border-[rgba(223,231,224,0.08)] px-4 sm:px-8 py-3">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">

          {/* Left: Kage Moon Brand & Title */}
          <div className="flex items-center gap-3.5 min-w-0">
            <div className="relative w-9 h-9 flex items-center justify-center shrink-0">
              <svg viewBox="0 0 44 44" fill="none" className="w-9 h-9">
                <circle cx="22" cy="24" r="9.5" fill="#e0231c" fillOpacity="0.88" />
                <path d="M6 12h32M9.5 17h25M22 8v28" stroke="#dfe7e0" strokeWidth="1.3" />
              </svg>
              <div className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-[#e0231c] threat-dot"/>
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm tracking-[0.24em] text-[#dfe7e0] uppercase leading-none">
                  VOID // SENTINEL
                </span>
                <span className="font-jp text-[11px] text-[#e0231c] tracking-widest hidden sm:inline">
                  影の防壁
                </span>
              </div>
              <span className="text-[10px] text-[#78837c] tracking-[0.16em] uppercase mt-0.5 truncate">
                Autonomous Cyber-Deception &amp; Honeytoken Defense
              </span>
            </div>
            <div className="hidden xl:flex items-center gap-2 ml-2 px-3 py-1 rounded-full bg-[rgba(223,231,224,0.04)] border border-[rgba(223,231,224,0.08)]">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 radar-dot"/>
              <span className="text-[10px] font-medium tracking-[0.2em] text-[#aab4ad] uppercase">
                TRIPWIRES ACTIVE · LISTENING
              </span>
            </div>
          </div>

          {/* Center: Dual-Layer Sliding Nav Links */}
          <nav className="hidden lg:flex items-center gap-7">
            <a href="#feed" className="nav-link on">
              <span>Telemetry</span>
              <span className="alt">探信</span>
            </a>
            <a href="#canaries" className="nav-link">
              <span>Canaries</span>
              <span className="alt">蜜罠</span>
            </a>
            <a href="#inspector" className="nav-link">
              <span>Inspector</span>
              <span className="alt">査定</span>
            </a>
            <a href="/kage" target="_blank" rel="noopener noreferrer" className="nav-link">
              <span>Sanctuary 3D</span>
              <span className="alt">伽藍</span>
            </a>
          </nav>

          {/* Right Controls: Matrix Toggle, View Mode & Intrusion Trigger */}
          <div className="flex items-center gap-2.5 shrink-0">
            {/* View Mode Selector */}
            <div className="hidden md:flex items-center rounded-full bg-[rgba(5,7,10,0.8)] border border-[rgba(223,231,224,0.12)] p-0.5 text-[10px] uppercase tracking-wider">
              <button
                onClick={() => setViewMode('hud')}
                className={`px-2.5 py-1 rounded-full transition-all ${viewMode === 'hud' ? 'bg-[rgba(223,231,224,0.18)] text-white' : 'text-[#78837c] hover:text-[#dfe7e0]'}`}
                title="HUD focus: High contrast for SOC operations"
                data-cursor
              >
                HUD
              </button>
              <button
                onClick={() => setViewMode('cinematic')}
                className={`px-2.5 py-1 rounded-full transition-all ${viewMode === 'cinematic' ? 'bg-[rgba(224,35,28,0.25)] text-[#e0231c]' : 'text-[#78837c] hover:text-[#dfe7e0]'}`}
                title="Cinematic: Balanced blend of 3D temple and SOC feed"
                data-cursor
              >
                CINEMA
              </button>
              <button
                onClick={() => setViewMode('sanctuary')}
                className={`px-2.5 py-1 rounded-full transition-all ${viewMode === 'sanctuary' ? 'bg-[#e0231c] text-white' : 'text-[#78837c] hover:text-[#dfe7e0]'}`}
                title="Sanctuary 3D: Immersive temple background with full interaction"
                data-cursor
              >
                3D
              </button>
            </div>

            {/* Defense Matrix Toggle */}
            <MatrixToggle active={matrixActive} onChange={setMatrix} />

            {/* Pause / Resume */}
            <button
              onClick={() => setPaused(p => !p)}
              className="p-2 rounded-lg bg-[rgba(5,7,10,0.85)] border border-[rgba(223,231,224,0.14)] text-[#aab4ad] hover:text-[#dfe7e0] hover:border-[rgba(223,231,224,0.3)] transition-all"
              data-cursor
              title={paused ? 'Resume live telemetry stream' : 'Pause telemetry stream'}
            >
              <Icon name={paused ? 'play' : 'pause'} size={13}/>
            </button>

            {/* Trigger Simulated Intrusion Button */}
            <button
              onClick={triggerSimulated}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-full bg-[rgba(224,35,28,0.2)] hover:bg-[#e0231c] text-[#e0231c] hover:text-white border border-[rgba(224,35,28,0.6)] hover:border-[#e0231c] text-xs font-medium uppercase tracking-[0.18em] transition-all hover:shadow-glow-vermilion"
              data-cursor
            >
              <Icon name="zap" size={12}/>
              <span className="hidden sm:inline">Inject Intrusion</span>
              <span className="sm:hidden">INJECT</span>
            </button>
          </div>
        </div>
      </header>

      {/* Bypassed Defense Warning Banner */}
      {!matrixActive && (
        <div className="bg-[rgba(224,35,28,0.15)] border-b border-[rgba(224,35,28,0.4)] px-4 py-1.5 text-center">
          <span className="text-[#e0231c] text-xs font-medium uppercase tracking-[0.24em]">
            WARNING — VOID DEFENSE MATRIX BYPASSED — HONEYTOKENS DISARMED
          </span>
        </div>
      )}

      {/* ══ MAIN COMMAND CENTER CONTENT ════════════════════════════ */}
      <main className="flex-1 max-w-7xl mx-auto w-full p-4 sm:p-6 space-y-6">

        {/* ── KAGE CHAPTER CHIPS (4 METRIC COUNTERS) ─────────────── */}
        <div className="chapters">
          <ChapterChip
            num="01"
            title="Inbound Telemetry"
            value={events.length.toLocaleString()}
            desc="Real-time ingress streams inspected across sentinel edge nodes."
          />
          <ChapterChip
            num="02"
            title="Honeytokens Tripped"
            value={honeytokens.toLocaleString()}
            desc="Sprung canary credentials and synthetic decoy tripwires."
            isCritical={true}
          />
          <ChapterChip
            num="03"
            title="Adversaries Isolated"
            value={quarantined}
            desc={`Hostile scanner IPs quarantined (${blacklisted.size} manual).`}
          />
          <ChapterChip
            num="04"
            title="Interception Latency"
            value="< 4ms"
            desc="Autonomous decoy routing response speed before origin reach."
            isSuccess={true}
          />
        </div>

        {/* ── 70/30 MAIN SPLIT: TELEMETRY FEED + RIGHT PANELS ────── */}
        <div className="grid grid-cols-1 xl:grid-cols-[1.55fr_1fr] gap-6 items-start">

          {/* LEFT: Real-Time Attack Telemetry Feed Table */}
          <div className="kage-panel rounded-xl overflow-hidden flex flex-col" id="feed">

            {/* Feed Header */}
            <div className="px-5 py-3.5 border-b border-[rgba(223,231,224,0.08)] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <div className="text-[#e0231c]"><Icon name="terminal" size={14}/></div>
                <span className="text-xs font-medium uppercase tracking-[0.2em] text-[#dfe7e0]">
                  Real-Time Attack Telemetry Feed
                </span>
                <span className="font-jp text-[11px] text-[#78837c] tracking-widest hidden md:inline">探信記録</span>
                <div className="w-1.5 h-1.5 rounded-full bg-[#e0231c] threat-dot ml-1"/>
              </div>

              {/* Search & Severity Filter */}
              <div className="flex items-center gap-2.5 flex-wrap">
                <div className="relative">
                  <Icon name="search" size={11} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[#78837c]"/>
                  <input
                    type="text"
                    placeholder="Search IP or route…"
                    value={searchIP}
                    onChange={e => setSearchIP(e.target.value)}
                    className="bg-[rgba(5,7,10,0.8)] border border-[rgba(223,231,224,0.12)] rounded-lg pl-7 pr-6 py-1.5 text-xs font-mono text-[#dfe7e0] placeholder-[#78837c] focus:outline-none focus:border-[#e0231c] w-40 sm:w-48 transition-colors"
                  />
                  {searchIP && (
                    <button onClick={() => setSearchIP('')} className="absolute right-2 top-1/2 -translate-y-1/2 text-[#78837c] hover:text-[#dfe7e0]">
                      <Icon name="x" size={10}/>
                    </button>
                  )}
                </div>

                <div className="relative">
                  <select
                    value={sevFilter}
                    onChange={e => setSevFilter(e.target.value)}
                    className="appearance-none bg-[rgba(5,7,10,0.8)] border border-[rgba(223,231,224,0.12)] rounded-lg pl-3 pr-7 py-1.5 text-xs text-[#dfe7e0] focus:outline-none focus:border-[#e0231c] cursor-pointer"
                  >
                    {['All','Critical','Warning','Clean'].map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                  <Icon name="chevrondown" size={11} className="absolute right-2 top-1/2 -translate-y-1/2 text-[#78837c] pointer-events-none"/>
                </div>

                <span className="text-[11px] font-mono text-[#78837c]">{filteredEvents.length} events</span>
              </div>
            </div>

            {/* Scrollable Telemetry Terminal Table */}
            <div ref={feedRef} className="overflow-auto max-h-[520px] min-h-[380px]">
              <table className="w-full text-xs border-collapse">
                <thead className="sticky top-0 z-10 bg-[rgba(5,7,10,0.92)] backdrop-blur-md">
                  <tr className="border-b border-[rgba(223,231,224,0.08)]">
                    {['Time', 'Severity', 'Origin IP', 'Targeted Route', 'Threat Vector', 'Countermeasure'].map(h => (
                      <th key={h} className="text-left px-4 py-2.5 text-[#78837c] uppercase tracking-[0.16em] font-medium text-[10px] whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[rgba(223,231,224,0.05)]">
                  {filteredEvents.length === 0 && (
                    <tr>
                      <td colSpan={6} className="text-center py-16 text-[#78837c] font-light">
                        No telemetry events match query
                      </td>
                    </tr>
                  )}
                  {filteredEvents.map(ev => {
                    const isSelected = selected?.id === ev.id;
                    return (
                      <tr
                        key={ev.id}
                        onClick={() => setSelected(ev)}
                        className={`kage-row cursor-pointer transition-colors ${ev.isNew ? 'flash-new' : ''} ${isSelected ? 'bg-[rgba(224,35,28,0.09)]' : ''}`}
                        data-cursor
                      >
                        <td className="px-4 py-3 font-mono text-[#78837c] whitespace-nowrap text-[11px]">
                          {fmtTime(ev.timestamp)}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <SeverityBadge sev={ev.severity}/>
                        </td>
                        <td className="px-4 py-3 font-mono whitespace-nowrap text-xs">
                          <span className={blacklisted.has(ev.client_ip) ? 'line-through text-[#78837c]' : 'text-[#dfe7e0]'}>
                            {ev.client_ip}
                          </span>
                          {blacklisted.has(ev.client_ip) && (
                            <span className="ml-1.5 text-[#e0231c] text-[10px]">[BLOCKED]</span>
                          )}
                        </td>
                        <td className="px-4 py-3 font-mono max-w-[190px]">
                          <span className={`truncate block ${ev.severity === 'CRITICAL' ? 'text-rose-300' : 'text-[#aab4ad]'}`}>
                            {ev.endpoint}
                          </span>
                        </td>
                        <td className="px-4 py-3 max-w-[160px]">
                          <span className={`truncate block font-medium ${ev.severity === 'CRITICAL' ? 'text-[#e0231c]' : ev.severity === 'HIGH' ? 'text-[#c9a24a]' : 'text-[#dfe7e0]'}`}>
                            {ev.attack_type}
                          </span>
                        </td>
                        <td className="px-4 py-3 max-w-[210px]">
                          <span className="truncate block text-[#78837c] text-[11px]">
                            {ev.action_taken}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Feed Status Footer */}
            <div className="px-5 py-2.5 border-t border-[rgba(223,231,224,0.08)] bg-[rgba(5,7,10,0.6)] flex items-center justify-between text-[11px] text-[#78837c]">
              <div className="flex items-center gap-2">
                <div className={`w-1.5 h-1.5 rounded-full ${paused ? 'bg-[#78837c]' : 'bg-emerald-400 radar-dot'}`}/>
                <span>{paused ? 'STREAM PAUSED' : 'LIVE — AUTO-INGESTING THREAT TELEMETRY'}</span>
              </div>
              <span>{selected ? `Active Inspection: ${selected.id}` : 'Click any row to inspect'}</span>
            </div>
          </div>

          {/* RIGHT: Threat Deep Dive & Canary Endpoints Grid */}
          <div className="flex flex-col gap-6">
            <IntrusionInspector
              event={selected}
              onBlacklist={ip => setBlacklisted(prev => new Set([...prev, ip]))}
              blacklisted={blacklisted}
            />
            <CanaryPanel events={events}/>
          </div>
        </div>

      </main>

      {/* ══ KAGE FOOTER ════════════════════════════════════════════ */}
      <footer className="border-t border-[rgba(223,231,224,0.08)] px-4 sm:px-8 py-4 bg-[rgba(5,7,10,0.85)] mt-auto">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-4 flex-wrap text-xs text-[#78837c]">
          <div className="flex items-center gap-3">
            <span className="tracking-[0.16em] uppercase font-mono text-[#aab4ad]">VOID // SENTINEL v3.0</span>
            <span className="text-[rgba(223,231,224,0.15)]">|</span>
            <span className="font-jp text-[11px] tracking-widest text-[#aab4ad]">静けさは一つの技である</span>
          </div>

          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#e0231c] threat-dot"/>
              <span className="uppercase tracking-wider text-[10px]">Deception Core: <strong className="text-[#dfe7e0]">ARMED</strong></span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 radar-dot"/>
              <span className="uppercase tracking-wider text-[10px]">Honeypots: <strong className="text-emerald-400">ONLINE</strong></span>
            </div>
            <a
              href="/kage"
              className="hover:text-[#e0231c] transition-colors uppercase tracking-[0.2em] text-[10px] flex items-center gap-1"
            >
              <span>Full Temple Sanctuary</span>
              <span>→</span>
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
};

/* Mount */
ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
