"""Patch void.js to poll the bridge API (port 8001) for live events."""

SRC = r"x:\hackOnTrackR2\person1\void.js"
DST = r"x:\hackOnTrackR2\person1\static\js\void.js"

content = open(SRC, encoding="utf-8").read()

# ── 1. Replace the mock auto-ticker with real bridge polling ──────────────
OLD_TICKER = """  /* Live feed auto-ticker */
  useEffect(() => {
    if (!paused) {
      intervalRef.current = setInterval(() => {
        const ev = makeEvent();
        setEvents(prev => [ev, ...prev].slice(0, 250));
        setFlashTick(n => n + 1);
        if (feedRef.current) feedRef.current.scrollTop = 0;
      }, 3500);
    }
    return () => clearInterval(intervalRef.current);
  }, [paused]);"""

NEW_TICKER = """  /* Bridge API base URL — Person 3 FastAPI bridge on port 8001 */
  const BRIDGE = 'http://127.0.0.1:8001';

  /* Track seen event IDs to avoid duplicates when polling */
  const seenIds = useRef(new Set(SAMPLE_EVENTS.map(e => e.id)));

  /* Poll bridge API for live events every 3.5 s.
     Falls back to a mock event when bridge is unreachable (demo mode). */
  useEffect(() => {
    const poll = async () => {
      try {
        const res = await fetch(`${BRIDGE}/api/events?limit=100`);
        if (!res.ok) throw new Error('bridge offline');
        const liveEvents = await res.json();
        if (!liveEvents.length) return;
        const newEvts = liveEvents.filter(e => !seenIds.current.has(e.id));
        if (!newEvts.length) return;
        newEvts.forEach(e => seenIds.current.add(e.id));
        const tagged = newEvts.map(e => ({ ...e, isNew: true }));
        setEvents(prev => [...tagged, ...prev].slice(0, 500));
        setFlashTick(n => n + 1);
        if (feedRef.current) feedRef.current.scrollTop = 0;
      } catch (_) {
        /* Bridge unreachable — keep demo alive with mock events */
        if (!paused) {
          const ev = makeEvent();
          setEvents(prev => [ev, ...prev].slice(0, 250));
          setFlashTick(n => n + 1);
          if (feedRef.current) feedRef.current.scrollTop = 0;
        }
      }
    };

    if (!paused) {
      poll(); // immediate first poll on mount / resume
      intervalRef.current = setInterval(poll, 3500);
    }
    return () => clearInterval(intervalRef.current);
  }, [paused]);"""

if OLD_TICKER in content:
    content = content.replace(OLD_TICKER, NEW_TICKER)
    print("✓ Ticker replaced")
else:
    print("✗ OLD_TICKER not found — check whitespace")

# ── 2. Wire Blacklist button to also POST to bridge ───────────────────────
OLD_BL = "      onClick={() => onBlacklist(event.client_ip)}"
NEW_BL = """      onClick={() => {
          onBlacklist(event.client_ip);
          fetch('http://127.0.0.1:8001/api/blacklist', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip: event.client_ip}),
          }).catch(() => {/* bridge offline — local blacklist still applied */});
        }}"""

if OLD_BL in content:
    content = content.replace(OLD_BL, NEW_BL)
    print("✓ Blacklist onClick patched")
else:
    print("✗ OLD_BL not found")

open(DST, "w", encoding="utf-8").write(content)
print(f"✓ Written to {DST}")
