"""VOID // SENTINEL — Adversary Simulation CLI (Person 3).

Orchestrates multi-phase adversary attack simulations and baseline workloads against
the VOID Cyber Defense System (http://127.0.0.1:8000).

Attack Vectors Supported:
- Baseline Legitimate Traffic
- Decoy Canary Traps (/admin/backup.sql, /api/v1/internal/users/export, /api/debug/config)
- Reconnaissance Sweeps (/.env, /.git/config, /wp-admin, /wp-login.php, /phpinfo.php)
- SQL Injection Probes (Auth bypass, UNION extraction, stacked queries)
- Path Traversal & LFI Probes (Relative, backslash Windows, URL-encoded)
- OS Command Injection Probes (Semicolons, pipes, shell metacharacters)
- Rapid Concurrency Burst (>8 req/0.5s via ThreadPoolExecutor)
- Brute-force Login Burst
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse

# Try importing requests; fall back to standard urllib
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.error
    import urllib.request
    HAS_REQUESTS = False

# Terminal color formatting with no-color fallback
USE_COLOR = sys.stdout.isatty() and not os.getenv("NO_COLOR")


class Color:
    RESET = "\033[0m" if USE_COLOR else ""
    BOLD = "\033[1m" if USE_COLOR else ""
    DIM = "\033[2m" if USE_COLOR else ""
    RED = "\033[91m" if USE_COLOR else ""
    GREEN = "\033[92m" if USE_COLOR else ""
    YELLOW = "\033[93m" if USE_COLOR else ""
    BLUE = "\033[94m" if USE_COLOR else ""
    MAGENTA = "\033[95m" if USE_COLOR else ""
    CYAN = "\033[96m" if USE_COLOR else ""
    WHITE = "\033[97m" if USE_COLOR else ""


def is_safe_target(target_url: str) -> bool:
    """Validate that the target is localhost or a private RFC1918 address."""
    try:
        parsed = urllib.parse.urlparse(target_url)
        host = parsed.hostname or "127.0.0.1"
        if host in ("localhost", "127.0.0.1", "::1", "testserver"):
            return True
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private
    except Exception:
        return False


class AttackSimulator:
    """Adversary Attack Simulation Engine."""

    def __init__(
        self,
        target: str = "http://127.0.0.1:8000",
        delay: float = 0.3,
        burst_count: int = 10,
        quiet: bool = False,
    ) -> None:
        self.target = target.rstrip("/")
        self.delay = delay
        self.burst_count = max(8, burst_count)
        self.quiet = quiet

        # Telemetry metrics tracked across phases
        self.metrics = {
            "requests_sent": 0,
            "decoys_triggered": 0,
            "blocked_or_throttled": 0,
            "successful_200": 0,
            "errors": 0,
        }

        # Initialize requests session if available
        self.session = requests.Session() if HAS_REQUESTS else None
        if self.session:
            self.session.headers.update({"User-Agent": "VOID-Sentinel-AdversarySim/2.0"})

    def log(self, msg: str) -> None:
        """Print log line if not in quiet mode."""
        if not self.quiet:
            print(msg)

    def send_request(
        self,
        path: str,
        method: str = "GET",
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 5.0,
    ) -> Dict[str, Any]:
        """Send HTTP request via requests or urllib fallback."""
        url = f"{self.target}{path}"
        req_headers = {"User-Agent": "VOID-Sentinel-AdversarySim/2.0"}
        if headers:
            req_headers.update(headers)

        self.metrics["requests_sent"] += 1
        start_time = time.time()

        if HAS_REQUESTS and self.session:
            try:
                resp = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=data if data else None,
                    headers=req_headers,
                    timeout=timeout,
                )
                duration_ms = round((time.time() - start_time) * 1000, 1)

                is_decoy = (
                    resp.headers.get("x-void-interception") == "DECOY_TRIGGERED"
                    or "x-synthetic-artifact" in resp.headers
                )
                is_blocked = resp.status_code in (429, 403, 418)

                if is_decoy:
                    self.metrics["decoys_triggered"] += 1
                if is_blocked:
                    self.metrics["blocked_or_throttled"] += 1
                if resp.status_code == 200:
                    self.metrics["successful_200"] += 1

                return {
                    "status": resp.status_code,
                    "duration_ms": duration_ms,
                    "headers": dict(resp.headers),
                    "body": resp.text,
                    "url": resp.url,
                    "is_decoy": is_decoy,
                    "is_blocked": is_blocked,
                }
            except Exception as e:
                self.metrics["errors"] += 1
                return {"status": 0, "error": str(e), "url": url, "is_decoy": False, "is_blocked": False}

        # Fallback to urllib
        query_str = f"?{urllib.parse.urlencode(params)}" if params else ""
        full_url = f"{url}{query_str}"
        body_bytes = json.dumps(data).encode("utf-8") if data else None
        if data:
            req_headers["Content-Type"] = "application/json"

        req = urllib.request.Request(full_url, data=body_bytes, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                duration_ms = round((time.time() - start_time) * 1000, 1)
                body = resp.read().decode("utf-8", errors="replace")
                resp_headers = dict(resp.headers)
                is_decoy = (
                    resp_headers.get("x-void-interception") == "DECOY_TRIGGERED"
                    or "x-synthetic-artifact" in resp_headers
                )
                if is_decoy:
                    self.metrics["decoys_triggered"] += 1
                if resp.status == 200:
                    self.metrics["successful_200"] += 1

                return {
                    "status": resp.status,
                    "duration_ms": duration_ms,
                    "headers": resp_headers,
                    "body": body,
                    "url": full_url,
                    "is_decoy": is_decoy,
                    "is_blocked": False,
                }
        except urllib.error.HTTPError as he:
            duration_ms = round((time.time() - start_time) * 1000, 1)
            body = he.read().decode("utf-8", errors="replace")
            resp_headers = dict(he.headers)
            is_decoy = (
                resp_headers.get("x-void-interception") == "DECOY_TRIGGERED"
                or "x-synthetic-artifact" in resp_headers
            )
            is_blocked = he.code in (429, 403, 418)
            if is_decoy:
                self.metrics["decoys_triggered"] += 1
            if is_blocked:
                self.metrics["blocked_or_throttled"] += 1
            return {
                "status": he.code,
                "duration_ms": duration_ms,
                "headers": resp_headers,
                "body": body,
                "url": full_url,
                "is_decoy": is_decoy,
                "is_blocked": is_blocked,
            }
        except Exception as exc:
            self.metrics["errors"] += 1
            return {"status": 0, "error": str(exc), "url": full_url, "is_decoy": False, "is_blocked": False}

    def run_healthcheck(self) -> bool:
        """Verify backend connectivity. Exits non-zero if unreachable."""
        self.log(f"{Color.CYAN}[*] Verifying backend availability at {self.target}/health...{Color.RESET}")
        res = self.send_request("/health")
        if res.get("status") == 200:
            self.log(
                f"    {Color.GREEN}[PASS] Backend is ONLINE! (HTTP 200, {res.get('duration_ms', 0)}ms){Color.RESET}"
            )
            return True
        self.log(
            f"    {Color.RED}[FAIL] Backend unreachable at {self.target}. Status: {res.get('status')}, Error: {res.get('error', 'None')}{Color.RESET}"
        )
        return False

    def run_baseline(self) -> None:
        """Phase 1: Legitimate baseline traffic that should NOT trigger deception or alarms."""
        self.log(f"\n{Color.BOLD}{Color.WHITE}─── Phase 1: Baseline Legitimate Traffic ───{Color.RESET}")
        endpoints = ["/api/products", "/api/profile"]
        all_passed = True
        for ep in endpoints:
            res = self.send_request(ep)
            status = res.get("status")
            decoy = res.get("is_decoy", False)
            if status == 200 and not decoy:
                self.log(f"  {Color.GREEN}[PASS]{Color.RESET} GET {ep:<18} -> HTTP {status} (Clean normal traffic)")
            else:
                all_passed = False
                self.log(f"  {Color.RED}[FAIL]{Color.RESET} GET {ep:<18} -> HTTP {status} (Unexpected decoy={decoy})")
            time.sleep(self.delay)

        if all_passed:
            self.log(f"  {Color.GREEN}--> Baseline traffic verified clean.{Color.RESET}")
        else:
            self.log(f"  {Color.YELLOW}--> Notice: Baseline traffic showed unexpected status.{Color.RESET}")

    def run_decoys(self) -> None:
        """Phase 2: Decoy canary traps to entice attackers and emit DECOY_ACCESS."""
        self.log(f"\n{Color.BOLD}{Color.WHITE}─── Phase 2: Cyber-Deception Decoy Traps ───{Color.RESET}")
        decoys = [
            ("/admin/backup.sql", "Database Backup Archive Decoy"),
            ("/api/v1/internal/users/export", "Privileged User Export Decoy"),
            ("/api/debug/config", "Runtime Debug Configuration Decoy"),
        ]
        for path, name in decoys:
            res = self.send_request(path)
            is_decoy = res.get("is_decoy", False)
            canary_flag = res.get("headers", {}).get("x-synthetic-artifact", "Not Set")
            self.log(
                f"  {Color.MAGENTA}[TRIPWIRE]{Color.RESET} {name} ({path})\n"
                f"    -> HTTP {res.get('status')} | Deception Intercept: {Color.GREEN if is_decoy else Color.RED}{is_decoy}{Color.RESET} | Canary: {canary_flag}"
            )
            time.sleep(self.delay)

    def run_recon(self) -> None:
        """Phase 3: Reconnaissance probes targeting high-value files."""
        self.log(f"\n{Color.BOLD}{Color.WHITE}─── Phase 3: Reconnaissance Sweeps ───{Color.RESET}")
        targets = ["/.env", "/.git/config", "/wp-admin", "/wp-login.php", "/phpinfo.php"]
        for target in targets:
            res = self.send_request(target)
            self.log(
                f"  {Color.YELLOW}[RECON]{Color.RESET} GET {target:<18} -> HTTP {res.get('status')} "
                f"({'Decoy Canary' if res.get('is_decoy') else 'Intercepted'})"
            )
            time.sleep(self.delay)

    def run_sqli(self) -> None:
        """Phase 4: SQL Injection attack payloads."""
        self.log(f"\n{Color.BOLD}{Color.WHITE}─── Phase 4: SQL Injection Exploits ───{Color.RESET}")
        sqli_tests = [
            {"q": "' OR 1=1 --"},
            {"q": "1 UNION SELECT username, password FROM users"},
            {"category": "hardware'; DROP TABLE logs; --"},
            {"id": "1' AND SLEEP(5) --"},
        ]
        for params in sqli_tests:
            res = self.send_request("/api/products", params=params)
            self.log(
                f"  {Color.RED}[SQLi]{Color.RESET} Payload: {urllib.parse.urlencode(params):<42} -> HTTP {res.get('status')}"
            )
            time.sleep(self.delay)

    def run_traversal(self) -> None:
        """Phase 5: Directory traversal and LFI probes."""
        self.log(f"\n{Color.BOLD}{Color.WHITE}─── Phase 5: Path Traversal & LFI Exploits ───{Color.RESET}")
        traversal_tests = [
            {"file": "../../etc/passwd"},
            {"doc": "..\\..\\windows\\system32\\win.ini"},
            {"download": "%2e%2e%2f%2e%2e%2fetc%2fshadow"},
            {"path": "....//....//etc/hosts"},
        ]
        for params in traversal_tests:
            res = self.send_request("/api/products", params=params)
            self.log(
                f"  {Color.RED}[TRAVERSAL]{Color.RESET} Payload: {urllib.parse.urlencode(params):<38} -> HTTP {res.get('status')}"
            )
            time.sleep(self.delay)

    def run_cmdi(self) -> None:
        """Phase 6: OS Command injection exploits."""
        self.log(f"\n{Color.BOLD}{Color.WHITE}─── Phase 6: Command Injection (RCE) ───{Color.RESET}")
        cmd_tests = [
            {"target": "127.0.0.1; cat /etc/passwd"},
            {"host": "localhost | whoami"},
            {"ip": "`id`"},
            {"ping": "$(uname -a)"},
        ]
        for params in cmd_tests:
            res = self.send_request("/api/profile", params=params)
            self.log(
                f"  {Color.RED}[CMDi]{Color.RESET} Payload: {urllib.parse.urlencode(params):<38} -> HTTP {res.get('status')}"
            )
            time.sleep(self.delay)

    def run_burst(self) -> None:
        """Phase 7: High-concurrency rapid request burst to trigger REQUEST_BURST (BURST-001)."""
        self.log(f"\n{Color.BOLD}{Color.WHITE}─── Phase 7: Multi-Threaded Request Burst Anomaly ───{Color.RESET}")
        self.log(
            f"  {Color.YELLOW}[>] Firing {self.burst_count} concurrent requests across threads in < 0.5s...{Color.RESET}"
        )

        burst_results: List[int] = []
        burst_start = time.time()

        def worker(idx: int) -> int:
            resp = self.send_request(f"/api/products?burst={idx}")
            return resp.get("status", 0)

        with ThreadPoolExecutor(max_workers=min(12, self.burst_count)) as executor:
            futures = [executor.submit(worker, i) for i in range(self.burst_count)]
            for fut in as_completed(futures):
                burst_results.append(fut.result())

        elapsed = time.time() - burst_start
        self.log(
            f"  {Color.GREEN}[+] Sent {len(burst_results)} requests in {elapsed:.3f}s. "
            f"Statuses: {dict((s, burst_results.count(s)) for s in set(burst_results))}{Color.RESET}"
        )

    def run_brute(self) -> None:
        """Phase 8: Brute-force credential stuffing burst."""
        self.log(f"\n{Color.BOLD}{Color.WHITE}─── Phase 8: Credential Stuffing / Auth Burst ───{Color.RESET}")
        passwords = ["admin123", "password", "123456", "root", "secret", "VOID2026!"]
        for pwd in passwords:
            payload = {"username": "admin", "password": pwd}
            res = self.send_request("/api/v1/auth/tokens", method="POST", data=payload)
            self.log(
                f"  {Color.YELLOW}[BRUTE]{Color.RESET} POST /api/v1/auth/tokens (pwd={pwd:<10}) -> HTTP {res.get('status')} "
                f"{'(Quarantined/Decoy)' if res.get('is_decoy') or res.get('is_blocked') else ''}"
            )
            time.sleep(0.1)

    def fetch_backend_stats(self) -> Optional[Dict[str, Any]]:
        """Fetch live telemetry stats from Person 1's GET /stats."""
        res = self.send_request("/stats", timeout=3.0)
        if res.get("status") == 200:
            try:
                return json.loads(res["body"])
            except Exception:
                return None
        return None

    def print_summary(self) -> None:
        """Display ANSI summary table comparing client activity with backend telemetry."""
        backend_stats = self.fetch_backend_stats()

        print("\n" + "=" * 65)
        print(f" {Color.BOLD}{Color.CYAN}VOID // SENTINEL — ADVERSARY SIMULATION RESULTS{Color.RESET}")
        print("=" * 65)
        print(f"  Target Host                 : {self.target}")
        print(f"  Total Requests Fired        : {self.metrics['requests_sent']}")
        print(f"  Decoy Traps Triggered       : {Color.MAGENTA}{self.metrics['decoys_triggered']}{Color.RESET}")
        print(f"  Blocked / Throttled (4xx)   : {Color.RED}{self.metrics['blocked_or_throttled']}{Color.RESET}")
        print(f"  Successful Normal (200 OK)  : {Color.GREEN}{self.metrics['successful_200']}{Color.RESET}")
        print(f"  Network / Connection Errors : {self.metrics['errors']}")

        if backend_stats:
            print("-" * 65)
            print(f" {Color.BOLD}Live Backend Telemetry Metrics (/stats):{Color.RESET}")
            print(f"  Backend Total Events Logged : {backend_stats.get('total_events', 'N/A')}")
            print(f"  Backend Decoy Interactions  : {backend_stats.get('decoy_interactions', 'N/A')}")
            print(f"  Aggregate System Threat     : {backend_stats.get('aggregate_system_risk', 'N/A')}/100")
            print(f"  Highest Threat Attacker IP  : {backend_stats.get('highest_risk_ip', 'N/A')}")
            print(f"  Active Recommendations      : {backend_stats.get('active_recommendations_count', 'N/A')}")
            sev = backend_stats.get("severity_counts", {})
            print(f"  Severity Breakdown          : CRITICAL={sev.get('CRITICAL', 0)} HIGH={sev.get('HIGH', 0)} MED={sev.get('MEDIUM', 0)} LOW={sev.get('LOW', 0)}")

        print("=" * 65)
        print(f"{Color.GREEN}Simulation finished. Verify your database and webhooks now!{Color.RESET}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="VOID // SENTINEL — Adversary Simulation Workload CLI",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--target",
        default="http://127.0.0.1:8000",
        help="Target backend URL",
    )
    parser.add_argument(
        "--mode",
        choices=["all", "baseline", "recon", "sqli", "traversal", "cmdi", "burst", "brute", "decoy"],
        default="all",
        help="Attack simulation mode",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.25,
        help="Inter-request delay in seconds",
    )
    parser.add_argument(
        "--burst-count",
        type=int,
        default=10,
        help="Number of concurrent requests in burst phase",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress verbose output and show only final summary",
    )
    parser.add_argument(
        "--i-own-this",
        action="store_true",
        help="Safety override: allow targeting non-localhost / non-private IPs",
    )

    args = parser.parse_args()

    # Safety Guard: enforce localhost / private target unless explicitly overridden
    if not is_safe_target(args.target) and not args.i_own_this:
        print(
            f"{Color.RED}[ERROR] Safety Guard: Target '{args.target}' is not a local or private address.\n"
            f"To test external servers, you must explicitly pass --i-own-this.{Color.RESET}",
            file=sys.stderr,
        )
        sys.exit(2)

    sim = AttackSimulator(
        target=args.target,
        delay=args.delay,
        burst_count=args.burst_count,
        quiet=args.quiet,
    )

    # Health check: must be reachable
    if not sim.run_healthcheck():
        print(
            f"{Color.RED}[FATAL] Could not connect to target backend at {args.target}.\n"
            f"Please verify Person 1's backend is running on port 8000.{Color.RESET}",
            file=sys.stderr,
        )
        sys.exit(1)

    mode = args.mode
    if mode in ("all", "baseline"):
        sim.run_baseline()
    if mode in ("all", "decoy"):
        sim.run_decoys()
    if mode in ("all", "recon"):
        sim.run_recon()
    if mode in ("all", "sqli"):
        sim.run_sqli()
    if mode in ("all", "traversal"):
        sim.run_traversal()
    if mode in ("all", "cmdi"):
        sim.run_cmdi()
    if mode in ("all", "burst"):
        sim.run_burst()
    if mode in ("all", "brute"):
        sim.run_brute()

    sim.print_summary()


if __name__ == "__main__":
    main()
