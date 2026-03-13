import { useState, useEffect, useRef } from "react";

// ── Mock scan simulation data ──────────────────────────────────────────────
const MOCK_PORTS = [
  { port: 22, service: "SSH", risk: "INFO", banner: "OpenSSH_8.9p1 Ubuntu-3ubuntu0.4" },
  { port: 80, service: "HTTP", risk: "LOW", banner: "Apache/2.4.52 (Ubuntu)" },
  { port: 443, service: "HTTPS", risk: "INFO", banner: "TLSv1.3 — nginx/1.22.0" },
  { port: 3306, service: "MySQL", risk: "MEDIUM", banner: "5.5.5-10.6.12-MariaDB-0ubuntu0.22.04.1" },
  { port: 6379, service: "Redis", risk: "HIGH", banner: "Redis 7.0.5 — No AUTH required" },
  { port: 8080, service: "HTTP-Alt", risk: "MEDIUM", banner: "Jetty/9.4 — Dev server exposed" },
  { port: 23, service: "Telnet", risk: "CRITICAL", banner: "Ubuntu 22.04 LTS telnetd" },
];

const MOCK_SUBS = [
  { subdomain: "www.target.com", ip: "203.0.113.10" },
  { subdomain: "api.target.com", ip: "203.0.113.11" },
  { subdomain: "admin.target.com", ip: "203.0.113.12" },
  { subdomain: "dev.target.com", ip: "203.0.113.13" },
  { subdomain: "mail.target.com", ip: "203.0.113.14" },
];

const MOCK_HTTP = [
  { check: "Missing: Strict-Transport-Security", detail: "HSTS missing — MITM risk elevated", severity: "HIGH" },
  { check: "Missing: Content-Security-Policy", detail: "No CSP — XSS attacks unmitigated", severity: "HIGH" },
  { check: "Missing: X-Frame-Options", detail: "Clickjacking protection absent", severity: "MEDIUM" },
  { check: "Server Banner Leak", detail: "Apache/2.4.52 (Ubuntu) — version exposed", severity: "LOW" },
  { check: "Tech Stack Leak", detail: "X-Powered-By: PHP/8.1.12", severity: "LOW" },
];

const MOCK_DNS = [
  { type: "A", value: "203.0.113.10" },
  { type: "MX", value: "10 mail.target.com." },
  { type: "NS", value: "ns1.target.com." },
  { type: "TXT", value: "v=spf1 include:sendgrid.net ~all" },
];

const TERMINAL_SCRIPT = [
  { t: "› Initializing NetReconX v1.0.0...", c: "#0af" },
  { t: "› Loading OWASP ruleset & CVE database...", c: "#0af" },
  { t: "› Resolving DNS: target.com → 203.0.113.10", c: "#30d158" },
  { t: "  [A]   203.0.113.10", c: "#ffd60a" },
  { t: "  [MX]  10 mail.target.com.", c: "#ffd60a" },
  { t: "  [NS]  ns1.target.com.", c: "#ffd60a" },
  { t: "› Brute-forcing 24 common subdomains...", c: "#30d158" },
  { t: "  [+] www.target.com      → 203.0.113.10", c: "#30d158" },
  { t: "  [+] api.target.com      → 203.0.113.11", c: "#30d158" },
  { t: "  [+] admin.target.com    → 203.0.113.12", c: "#ff6b00" },
  { t: "  [+] dev.target.com      → 203.0.113.13", c: "#ff6b00" },
  { t: "› Launching port scan [1–10000] · 200 threads...", c: "#30d158" },
  { t: "  [OPEN] 22/tcp    SSH       [INFO]", c: "#0af" },
  { t: "  [OPEN] 23/tcp    Telnet    [CRITICAL] ← unencrypted protocol!", c: "#ff2d55" },
  { t: "  [OPEN] 80/tcp    HTTP      [LOW]", c: "#30d158" },
  { t: "  [OPEN] 443/tcp   HTTPS     [INFO]", c: "#0af" },
  { t: "  [OPEN] 3306/tcp  MySQL     [MEDIUM]", c: "#ffd60a" },
  { t: "  [OPEN] 6379/tcp  Redis     [HIGH] ← unauthenticated!", c: "#ff6b00" },
  { t: "  [OPEN] 8080/tcp  HTTP-Alt  [MEDIUM]", c: "#ffd60a" },
  { t: "› Auditing HTTP security headers...", c: "#30d158" },
  { t: "  [-] HSTS missing — MITM risk", c: "#ff6b00" },
  { t: "  [-] CSP not set — XSS unmitigated", c: "#ff6b00" },
  { t: "  [-] X-Frame-Options absent", c: "#ffd60a" },
  { t: "  [!] Server leaks: Apache/2.4.52", c: "#ffd60a" },
  { t: "› Scan complete. Risk Score: 8.7/10 [CRITICAL]", c: "#ff2d55" },
  { t: "› Reports saved: report.json / report.html", c: "#0af" },
];

// ── Severity config ────────────────────────────────────────────────────────
const SEV = {
  CRITICAL: { color: "#ff2d55", bg: "rgba(255,45,85,0.12)", border: "rgba(255,45,85,0.3)" },
  HIGH:     { color: "#ff6b00", bg: "rgba(255,107,0,0.12)", border: "rgba(255,107,0,0.3)" },
  MEDIUM:   { color: "#ffd60a", bg: "rgba(255,214,10,0.12)", border: "rgba(255,214,10,0.3)" },
  LOW:      { color: "#30d158", bg: "rgba(48,209,88,0.12)", border: "rgba(48,209,88,0.3)" },
  INFO:     { color: "#0a84ff", bg: "rgba(10,132,255,0.12)", border: "rgba(10,132,255,0.3)" },
};

const Badge = ({ sev }) => {
  const s = SEV[sev] || SEV.INFO;
  return (
    <span style={{ fontSize: 9, padding: "2px 8px", letterSpacing: 1, fontWeight: 700,
      background: s.bg, color: s.color, border: `1px solid ${s.border}`, borderRadius: 3 }}>
      {sev}
    </span>
  );
};

// ── Mini bar chart ─────────────────────────────────────────────────────────
const MiniChart = ({ data }) => {
  const max = Math.max(...data.map(d => d.v), 1);
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
      {data.map(d => (
        <div key={d.label} style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 60, fontSize: 9, color: SEV[d.label]?.color || "#aaa", letterSpacing: 1 }}>{d.label}</div>
          <div style={{ flex: 1, height: 12, background: "rgba(255,255,255,0.04)", borderRadius: 2, overflow: "hidden" }}>
            <div style={{ width: `${(d.v / max) * 100}%`, height: "100%",
              background: SEV[d.label]?.color || "#aaa", opacity: 0.75,
              transition: "width 1.4s cubic-bezier(0.16,1,0.3,1)", borderRadius: 2 }} />
          </div>
          <div style={{ width: 16, fontSize: 11, color: SEV[d.label]?.color, fontWeight: 700, textAlign: "right" }}>{d.v}</div>
        </div>
      ))}
    </div>
  );
};

// ── Pulsing dot ────────────────────────────────────────────────────────────
const Pulse = ({ color = "#30d158", size = 8 }) => (
  <>
    <style>{`@keyframes pulseRing{0%{transform:scale(1);opacity:0.8}100%{transform:scale(2.2);opacity:0}}`}</style>
    <div style={{ position: "relative", width: size, height: size }}>
      <div style={{ position: "absolute", inset: 0, borderRadius: "50%", background: color,
        animation: "pulseRing 1.4s ease-out infinite", opacity: 0 }} />
      <div style={{ width: size, height: size, borderRadius: "50%", background: color }} />
    </div>
  </>
);

// ══════════════════════════════════════════════════════════════════════════
// MAIN COMPONENT
// ══════════════════════════════════════════════════════════════════════════
export default function NetReconX() {
  const [target, setTarget] = useState("");
  const [portRange, setPortRange] = useState("1-10000");
  const [mode, setMode] = useState("standard");
  const [scanning, setScanning] = useState(false);
  const [done, setDone] = useState(false);
  const [progress, setProgress] = useState(0);
  const [phase, setPhase] = useState("");
  const [lines, setLines] = useState([]);
  const [ports, setPorts] = useState([]);
  const [http, setHttp] = useState([]);
  const [subs, setSubs] = useState([]);
  const [dns, setDns] = useState([]);
  const [tab, setTab] = useState("ports");
  const termRef = useRef(null);
  const ivRef = useRef(null);

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [lines]);

  const launchScan = () => {
    if (!target.trim()) return;
    setScanning(true); setDone(false); setProgress(0);
    setLines([]); setPorts([]); setHttp([]); setSubs([]); setDns([]);
    setPhase("Initializing");

    const phases = ["DNS Resolve","DNS Enum","Port Scan","Banner Grab","HTTP Audit","Finalizing"];
    let i = 0;
    ivRef.current = setInterval(() => {
      if (i < TERMINAL_SCRIPT.length) {
        setLines(prev => [...prev, TERMINAL_SCRIPT[i]]);
        const pct = Math.round(((i + 1) / TERMINAL_SCRIPT.length) * 100);
        setProgress(pct);
        setPhase(phases[Math.floor((pct / 100) * phases.length)] || "Scanning");
        i++;
      } else {
        clearInterval(ivRef.current);
        setScanning(false); setDone(true);
        setPorts(MOCK_PORTS); setHttp(MOCK_HTTP);
        setSubs(MOCK_SUBS); setDns(MOCK_DNS);
      }
    }, 180);
  };

  const sevCounts = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].map(s => ({
    label: s, v: ports.filter(p => p.risk === s).length + http.filter(h => h.severity === s).length
  }));

  const riskScore = 8.7;
  const totalFindings = ports.length + http.length;

  return (
    <div style={{ minHeight: "100vh", background: "#05080d", color: "#dde4ec",
      fontFamily: "'Courier New', monospace", fontSize: 13 }}>

      {/* Scanlines */}
      <div style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 100,
        backgroundImage: "repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,0,0,0.04) 3px,rgba(0,0,0,0.04) 4px)" }} />

      {/* ── Top Bar ──────────────────────────────────────────────────────── */}
      <header style={{ background: "rgba(0,170,255,0.04)", borderBottom: "1px solid rgba(0,170,255,0.15)",
        padding: "14px 28px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{ width: 38, height: 38, border: "2px solid #0af", borderRadius: 4,
            display: "flex", alignItems: "center", justifyContent: "center" }}>
            <span style={{ fontSize: 18 }}>⬡</span>
          </div>
          <div>
            <div style={{ fontSize: 17, fontWeight: 900, letterSpacing: 4, color: "#0af" }}>NETRECONX</div>
            <div style={{ fontSize: 9, color: "rgba(255,255,255,0.25)", letterSpacing: 2 }}>
              NETWORK RECONNAISSANCE ENGINE v1.0 · ETHICAL USE ONLY
            </div>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          {["OWASP","CVE-DB","NMAP"].map(b => (
            <div key={b} style={{ fontSize: 9, letterSpacing: 2, padding: "3px 10px",
              border: "1px solid rgba(0,170,255,0.2)", color: "rgba(0,170,255,0.5)", borderRadius: 2 }}>{b}</div>
          ))}
          <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 9,
            letterSpacing: 2, padding: "3px 10px", border: "1px solid rgba(48,209,88,0.4)",
            color: "#30d158", borderRadius: 2 }}>
            <Pulse size={6} /> READY
          </div>
        </div>
      </header>

      <div style={{ padding: "22px 28px", display: "grid", gap: 18 }}>

        {/* ── Input Bar ──────────────────────────────────────────────────── */}
        <div style={{ background: "rgba(0,170,255,0.03)", border: "1px solid rgba(0,170,255,0.12)",
          borderRadius: 6, padding: 18 }}>
          <div style={{ fontSize: 9, letterSpacing: 3, color: "rgba(255,255,255,0.25)", marginBottom: 12 }}>
            TARGET CONFIGURATION
          </div>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <input value={target} onChange={e => setTarget(e.target.value)}
              onKeyDown={e => e.key === "Enter" && !scanning && launchScan()}
              placeholder="hostname or IP (e.g. 192.168.1.1)"
              style={{ flex: "2 1 260px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(0,170,255,0.2)",
                borderRadius: 4, padding: "11px 14px", color: "#dde4ec", fontSize: 13,
                outline: "none", fontFamily: "'Courier New',monospace" }} />
            <input value={portRange} onChange={e => setPortRange(e.target.value)}
              placeholder="Ports (1-10000)"
              style={{ flex: "1 1 130px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(0,170,255,0.15)",
                borderRadius: 4, padding: "11px 14px", color: "#dde4ec", fontSize: 13,
                outline: "none", fontFamily: "'Courier New',monospace" }} />
            <select value={mode} onChange={e => setMode(e.target.value)}
              style={{ flex: "1 1 120px", background: "rgba(0,0,0,0.7)", border: "1px solid rgba(0,170,255,0.15)",
                borderRadius: 4, padding: "11px 14px", color: "#dde4ec", fontSize: 12,
                fontFamily: "'Courier New',monospace", cursor: "pointer" }}>
              <option value="quick">QUICK</option>
              <option value="standard">STANDARD</option>
              <option value="full">FULL</option>
            </select>
            <button onClick={launchScan} disabled={scanning}
              style={{ flex: "0 0 auto", padding: "11px 26px",
                background: scanning ? "rgba(0,170,255,0.1)" : "rgba(0,170,255,0.9)",
                border: "none", borderRadius: 4, color: scanning ? "#0af" : "#000",
                fontFamily: "'Courier New',monospace", fontSize: 12, fontWeight: 900,
                letterSpacing: 2, cursor: scanning ? "not-allowed" : "pointer", transition: "all 0.2s" }}>
              {scanning ? "SCANNING..." : "▶ LAUNCH"}
            </button>
          </div>

          {(scanning || done) && (
            <div style={{ marginTop: 14 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10,
                color: "rgba(255,255,255,0.3)", marginBottom: 5 }}>
                <span>{scanning ? `◈ ${phase}` : "✓ SCAN COMPLETE"}</span>
                <span>{progress}%</span>
              </div>
              <div style={{ height: 3, background: "rgba(255,255,255,0.06)", borderRadius: 2, overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${progress}%`,
                  background: done ? "#30d158" : "#0af",
                  transition: "width 0.25s ease-out", borderRadius: 2,
                  boxShadow: `0 0 10px ${done ? "#30d158" : "#0af"}` }} />
              </div>
            </div>
          )}
        </div>

        {/* ── Main Grid ──────────────────────────────────────────────────── */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 300px", gap: 18 }}>

          {/* Terminal */}
          <div style={{ background: "#000", border: "1px solid rgba(255,255,255,0.06)",
            borderRadius: 6, overflow: "hidden" }}>
            <div style={{ background: "rgba(255,255,255,0.03)", padding: "9px 16px",
              borderBottom: "1px solid rgba(255,255,255,0.05)",
              display: "flex", alignItems: "center", gap: 6 }}>
              {["#ff5f57","#febc2e","#28c840"].map(c => (
                <div key={c} style={{ width: 10, height: 10, borderRadius: "50%", background: c }} />
              ))}
              <span style={{ marginLeft: 8, fontSize: 10, color: "rgba(255,255,255,0.2)", letterSpacing: 1 }}>
                netreconx — scan.log
              </span>
              {scanning && <div style={{ marginLeft: "auto" }}><Pulse color="#0af" size={6} /></div>}
            </div>
            <div ref={termRef} style={{ padding: 16, height: 300, overflowY: "auto" }}>
              {lines.length === 0
                ? <span style={{ color: "rgba(255,255,255,0.15)", fontSize: 12 }}>$ netreconx --target &lt;host&gt; --mode {mode}_</span>
                : lines.map((l, i) => (
                    <div key={i} style={{ color: l.c, fontSize: 11, lineHeight: 1.9,
                      fontFamily: "'Courier New',monospace" }}>{l.t}</div>
                  ))}
              {scanning && <span style={{ color: "#0af" }}>█</span>}
            </div>
          </div>

          {/* Stats panel */}
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            {/* Risk gauge */}
            <div style={{ background: "rgba(255,45,85,0.05)", border: "1px solid rgba(255,45,85,0.2)",
              borderRadius: 6, padding: 18, textAlign: "center" }}>
              <div style={{ fontSize: 9, letterSpacing: 3, color: "rgba(255,255,255,0.25)", marginBottom: 8 }}>RISK SCORE</div>
              <div style={{ fontSize: 56, fontWeight: 900, color: done ? "#ff2d55" : "rgba(255,255,255,0.1)",
                lineHeight: 1, transition: "color 0.5s" }}>{done ? riskScore : "—"}</div>
              <div style={{ fontSize: 10, color: done ? "#ff2d55" : "rgba(255,255,255,0.2)", letterSpacing: 2 }}>
                / 10 · {done ? "CRITICAL RISK" : "AWAITING SCAN"}
              </div>
              <div style={{ marginTop: 14, display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8 }}>
                {[
                  { l: "PORTS", v: ports.length },
                  { l: "FINDINGS", v: totalFindings },
                  { l: "SUBS", v: subs.length },
                ].map(s => (
                  <div key={s.l} style={{ textAlign: "center" }}>
                    <div style={{ fontSize: 20, fontWeight: 700, color: "#0af" }}>{done ? s.v : "—"}</div>
                    <div style={{ fontSize: 8, color: "rgba(255,255,255,0.2)", letterSpacing: 1 }}>{s.l}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Breakdown */}
            {done && (
              <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
                borderRadius: 6, padding: 16 }}>
                <div style={{ fontSize: 9, letterSpacing: 3, color: "rgba(255,255,255,0.25)", marginBottom: 12 }}>
                  FINDINGS BREAKDOWN
                </div>
                <MiniChart data={sevCounts} />
              </div>
            )}

            {/* DNS records */}
            {done && dns.length > 0 && (
              <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
                borderRadius: 6, padding: 16, flex: 1 }}>
                <div style={{ fontSize: 9, letterSpacing: 3, color: "rgba(255,255,255,0.25)", marginBottom: 10 }}>
                  DNS RECORDS
                </div>
                {dns.map((r, i) => (
                  <div key={i} style={{ display: "flex", gap: 8, padding: "5px 0",
                    borderBottom: "1px solid rgba(255,255,255,0.04)", fontSize: 11 }}>
                    <span style={{ color: "#0af", width: 34, flexShrink: 0 }}>{r.type}</span>
                    <span style={{ color: "rgba(255,255,255,0.5)", wordBreak: "break-all" }}>{r.value}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* ── Results Tabs ──────────────────────────────────────────────── */}
        {done && (
          <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
            borderRadius: 6, overflow: "hidden" }}>
            {/* Tab bar */}
            <div style={{ display: "flex", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
              {[
                { id: "ports", label: `OPEN PORTS (${ports.length})` },
                { id: "http", label: `HTTP AUDIT (${http.length})` },
                { id: "subs", label: `SUBDOMAINS (${subs.length})` },
              ].map(t => (
                <button key={t.id} onClick={() => setTab(t.id)}
                  style={{ padding: "12px 22px", fontSize: 10, letterSpacing: 2, border: "none",
                    borderBottom: tab === t.id ? "2px solid #0af" : "2px solid transparent",
                    background: tab === t.id ? "rgba(0,170,255,0.06)" : "transparent",
                    color: tab === t.id ? "#0af" : "rgba(255,255,255,0.3)",
                    cursor: "pointer", fontFamily: "'Courier New',monospace", transition: "all 0.15s" }}>
                  {t.label}
                </button>
              ))}
            </div>

            {/* Ports tab */}
            {tab === "ports" && (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ background: "rgba(255,255,255,0.03)" }}>
                    {["PORT","SERVICE","RISK","BANNER"].map(h => (
                      <th key={h} style={{ padding: "10px 16px", textAlign: "left", fontSize: 9,
                        letterSpacing: 2, color: "rgba(255,255,255,0.25)", fontWeight: 400 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {ports.map((p, i) => (
                    <tr key={i} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                      <td style={{ padding: "11px 16px", color: "#0af", fontWeight: 700 }}>{p.port}/tcp</td>
                      <td style={{ padding: "11px 16px" }}>{p.service}</td>
                      <td style={{ padding: "11px 16px" }}><Badge sev={p.risk} /></td>
                      <td style={{ padding: "11px 16px", fontSize: 11, color: "rgba(255,255,255,0.35)" }}>
                        {p.banner || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {/* HTTP tab */}
            {tab === "http" && (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ background: "rgba(255,255,255,0.03)" }}>
                    {["SEVERITY","CHECK","DETAIL"].map(h => (
                      <th key={h} style={{ padding: "10px 16px", textAlign: "left", fontSize: 9,
                        letterSpacing: 2, color: "rgba(255,255,255,0.25)", fontWeight: 400 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {http.map((f, i) => (
                    <tr key={i} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                      <td style={{ padding: "11px 16px" }}><Badge sev={f.severity} /></td>
                      <td style={{ padding: "11px 16px", fontWeight: 600 }}>{f.check}</td>
                      <td style={{ padding: "11px 16px", fontSize: 11, color: "rgba(255,255,255,0.45)" }}>{f.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {/* Subdomains tab */}
            {tab === "subs" && (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ background: "rgba(255,255,255,0.03)" }}>
                    {["SUBDOMAIN","IP ADDRESS","STATUS"].map(h => (
                      <th key={h} style={{ padding: "10px 16px", textAlign: "left", fontSize: 9,
                        letterSpacing: 2, color: "rgba(255,255,255,0.25)", fontWeight: 400 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {subs.map((s, i) => (
                    <tr key={i} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                      <td style={{ padding: "11px 16px", color: "#0af" }}>{s.subdomain}</td>
                      <td style={{ padding: "11px 16px", color: "rgba(255,255,255,0.5)" }}>{s.ip}</td>
                      <td style={{ padding: "11px 16px" }}>
                        <span style={{ fontSize: 9, padding: "2px 8px", background: "rgba(48,209,88,0.12)",
                          color: "#30d158", border: "1px solid rgba(48,209,88,0.3)", borderRadius: 3, letterSpacing: 1 }}>
                          LIVE
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {/* ── Footer ──────────────────────────────────────────────────────── */}
        <div style={{ borderTop: "1px solid rgba(255,255,255,0.04)", paddingTop: 14,
          display: "flex", justifyContent: "space-between", fontSize: 9,
          color: "rgba(255,255,255,0.18)", letterSpacing: 1 }}>
          <span>⚠ FOR AUTHORIZED PENETRATION TESTING ONLY</span>
          <span>NetReconX v1.0.0 · Python Backend + React Dashboard</span>
        </div>
      </div>
    </div>
  );
}
