'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import {
  Target, ShieldAlert, ActivitySquare, Terminal, AlertCircle,
  Cpu, Radio, Fingerprint, Lock, EyeOff, ShieldCheck,
  HardDrive, CreditCard, Ghost, Skull, Monitor, CheckCircle, Calculator,
  Image as ImageIcon, Globe, MousePointerClick, ClipboardCopy, Eye
} from 'lucide-react';
import { saveThreatLog } from './actions';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

const isSuspiciousPayload = (url: string) =>
  /\.(exe|apk|php|zip|bin|sh|bat)$/i.test(url) || /login|auth|credential/i.test(url);

const SCAN_PHASES = [
  { icon: <Cpu className="w-5 h-5 text-accent" />, text: "Setting up a secure, fake smartphone..." },
  { icon: <Fingerprint className="w-5 h-5 text-accent" />, text: "Opening the link inside the safe zone..." },
  { icon: <MousePointerClick className="w-5 h-5 text-accent" />, text: "Tapping buttons and typing fake passwords..." },
  { icon: <Radio className="w-5 h-5 text-accent animate-pulse-fast" />, text: "Watching what the website tries to steal..." },
  { icon: <Terminal className="w-5 h-5 text-accent" />, text: "Writing the final threat report..." }
];

export default function ThreatTrailer() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [phaseIndex, setPhaseIndex] = useState(0);
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const autoRan = useRef(false);

  // Scan-phase ticker (scans are longer now because of interaction, so 5 phases @ 3s)
  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (loading) {
      interval = setInterval(() => {
        setPhaseIndex((prev) => (prev < SCAN_PHASES.length - 1 ? prev + 1 : prev));
      }, 3000);
    } else {
      setPhaseIndex(0);
    }
    return () => clearInterval(interval);
  }, [loading]);

  const runScan = useCallback(async (target: string) => {
    if (!target) return;
    setLoading(true);
    setData(null);
    setError(null);
    try {
      const res = await fetch(`${API_URL}/api/detonate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target }),
      });
      if (!res.ok) {
        const detail = await res.json().catch(() => ({}));
        throw new Error(detail?.detail || `Scan failed (${res.status})`);
      }
      const result = await res.json();
      setData(result);

      // Don't persist base64 screenshots; keep the log light. Failure here must not break the UI.
      try {
        const light = {
          ...result,
          visual_frames: (result.visual_frames || []).map(({ image, ...rest }: any) => rest),
        };
        await saveThreatLog(light);
      } catch (e) {
        console.warn('saveThreatLog failed:', e);
      }
    } catch (err: any) {
      console.error('Detonation failed:', err);
      setError(err?.message || 'Could not reach the Threat Trailer engine.');
    } finally {
      setLoading(false);
    }
  }, []);

  // Chrome-extension auto-fetch: ?url=... (runs once, even under React strict mode)
  useEffect(() => {
    if (autoRan.current) return;
    const incomingUrl = new URLSearchParams(window.location.search).get('url');
    if (incomingUrl) {
      autoRan.current = true;
      setUrl(incomingUrl);
      runScan(incomingUrl);
    }
  }, [runScan]);

  const handleDetonate = (e: React.FormEvent) => {
    e.preventDefault();
    runScan(url);
  };

  // ---------- Derived state: backend is the single source of truth ----------
  const level: string | undefined = data?.risk_level ?? data?.analysis?.exfiltration_level;
  const isCritical = level === 'CRITICAL';
  const isSuspicious = level === 'SUSPICIOUS';
  const isSafe = level === 'SAFE';

  const riskColor = isCritical ? 'text-red-500 border-red-500/30 bg-red-500/5' :
                    isSuspicious ? 'text-orange-400 border-orange-400/30 bg-orange-400/5' :
                    isSafe ? 'text-green-500 border-green-500/30 bg-green-500/5' :
                    'text-accent border-accent/30 bg-accent/5';

  // Use the backend score as-is. (Summing the breakdown breaks when the whitelist
  // override or the 9.9 cap kicks in, so the two could disagree.)
  const rawScore = Math.min(Number(data?.threat_score ?? 0), 9.9);
  const displayScore = rawScore.toFixed(1);

  const getRuleColorClasses = (color: string) => {
    switch (color) {
      case 'red': return 'border-red-500/30 bg-red-500/10 text-red-400';
      case 'orange': return 'border-orange-500/30 bg-orange-500/10 text-orange-400';
      case 'green': return 'border-green-500/30 bg-green-500/10 text-green-400';
      default: return 'border-accent/30 bg-accent/10 text-accent';
    }
  };

  const getImpactIcon = (text: string) => {
    if (!text) return <AlertCircle className="w-6 h-6 text-accent" />;
    const lower = text.toLowerCase();
    if (lower.includes('clipboard')) return <ClipboardCopy className="w-6 h-6 text-red-400" />;
    if (lower.includes('ransomware') || lower.includes('file') || lower.includes('binary') || lower.includes('drop') || lower.includes('malware')) return <HardDrive className="w-6 h-6 text-red-400" />;
    if (lower.includes('password') || lower.includes('financial') || lower.includes('credential') || lower.includes('intercept')) return <CreditCard className="w-6 h-6 text-orange-400" />;
    if (lower.includes('stealth') || lower.includes('background') || lower.includes('monitor') || lower.includes('telemetry') || lower.includes('fingerprint')) return <Ghost className="w-6 h-6 text-purple-400" />;
    if (isSafe) return <CheckCircle className="w-6 h-6 text-green-500" />;
    return <AlertCircle className="w-6 h-6 text-accent" />;
  };

  const triggers = data?.honeypot_triggers || {};
  const headline = (data?.analysis?.headline || '').toLowerCase();
  const brand: string | null = data?.analysis?.impersonated_brand || null;

  const isRansomware = !!triggers.tried_download || headline.includes('drive-by') || headline.includes('ransomware');
  const isClipboard = !!triggers.clipboard_hijack;
  const isPhishing = !!triggers.credentials_exfiltrated || !!brand || headline.includes('credential') || headline.includes('phishing');

  const maxThirdParty = Math.max(1, ...((data?.third_party_domains || []) as [string, number][]).map(([, n]) => n));

  // =======================================================
  // TRAILER FRAMES
  // =======================================================

  // Frame: REAL captured events (no more scripted fake output)
  const renderTerminal = () => {
    const events: { level: string; text: string }[] = data?.runtime_events || [];
    return (
      <div className="w-full h-[420px] bg-[#0a0a0a] border border-border-subtle p-5 font-mono text-[11px] shadow-inner overflow-y-auto flex flex-col gap-1 rounded-lg">
        <div className="mb-2 text-text-secondary/50">root@sandbox:~# live_capture --mobile</div>
        {events.length === 0 && <div className="text-text-secondary/50">&gt;&gt; No notable runtime activity captured.</div>}
        {events.map((e, i) => (
          <div
            key={i}
            className={
              e.level === 'danger' ? 'text-red-500 font-bold' :
              e.level === 'warn' ? 'text-yellow-400' : 'text-green-400/80'
            }
          >
            &gt;&gt; {e.text}
          </div>
        ))}
        <div className={`mt-auto pt-3 font-bold tracking-widest ${isCritical ? 'text-red-500 animate-pulse' : isSuspicious ? 'text-orange-400 animate-pulse' : 'text-green-500'}`}>
          {isCritical ? 'SYSTEM COMPROMISED _' : isSuspicious ? 'SILENT TRACKING ACTIVE _' : 'SYSTEM SECURE _'}
        </div>
      </div>
    );
  };

  const renderBlastRadius = () => {
    const box = 'absolute inset-0 flex flex-col items-center justify-center text-center p-4 border';
    return (
      <div className="w-full h-[420px] border border-border-subtle overflow-hidden shadow-inner flex items-center justify-center p-6 relative rounded-lg">
        {isRansomware ? (
          <div className={`${box} bg-red-900/10 border-red-500/20`}>
            <Lock className="w-16 h-16 text-red-500 mb-4 drop-shadow-[0_0_8px_#ef4444] animate-bounce" />
            <div className="font-heading text-red-500 text-xl mb-2 leading-tight tracking-widest">FILE DROPPED</div>
            <div className="text-xs text-text-primary/70 mb-4 max-w-[220px] leading-relaxed">
              {triggers.files_dropped?.[0] || 'A file'} was pushed to the device. If opened, ransomware could lock your personal data.
            </div>
            <div className="bg-red-500 text-black text-[10px] font-bold px-4 py-2 uppercase tracking-wider">Worst case: ransom demand</div>
          </div>
        ) : isClipboard ? (
          <div className={`${box} bg-red-900/10 border-red-500/20`}>
            <ClipboardCopy className="w-16 h-16 text-red-500 mb-4 drop-shadow-[0_0_8px_#ef4444] animate-pulse" />
            <div className="font-heading text-red-500 text-xl mb-2 leading-tight tracking-widest">CLIPBOARD HIJACKED</div>
            <div className="text-xs text-text-primary/70 max-w-[220px] leading-relaxed">
              The page silently copied a command to your clipboard and will ask you to paste it. Never paste it.
            </div>
          </div>
        ) : isPhishing ? (
          <div className={`${box} bg-orange-900/10 border-orange-500/20`}>
            <CreditCard className="w-16 h-16 text-orange-500 mb-4 drop-shadow-[0_0_8px_#f97316] animate-pulse" />
            <div className="font-heading text-orange-500 text-xl mb-2 leading-tight tracking-widest">
              {brand ? `FAKE ${brand.toUpperCase()}` : 'DATA BREACH'}
            </div>
            <div className="text-xs text-text-primary/70 mb-4 font-mono space-y-1">
              {brand && <div>pretends to be : <span className="text-red-400">{brand}</span></div>}
              <div>typed_password : <span className="text-red-400">{triggers.credentials_exfiltrated ? 'SENT TO 3RD PARTY' : 'AT RISK'}</span></div>
            </div>
            <div className="bg-orange-500 text-black text-[10px] font-bold px-4 py-2 uppercase tracking-wider animate-pulse">Identity at risk</div>
          </div>
        ) : isSafe ? (
          <div className={`${box} bg-green-900/10 border-green-500/20`}>
            <CheckCircle className="w-16 h-16 text-green-500 mb-4 drop-shadow-[0_0_8px_currentColor]" />
            <div className="font-heading text-green-500 text-xl mb-2 leading-tight tracking-widest">LOOKS SAFE</div>
            <div className="text-xs text-text-primary/70 max-w-[220px] leading-relaxed">
              We clicked around and nothing malicious happened. Stay alert anyway.
            </div>
          </div>
        ) : (
          <div className={`${box} bg-accent/10 border-accent/20`}>
            <Ghost className="w-16 h-16 text-accent mb-4 drop-shadow-[0_0_8px_currentColor]" />
            <div className="font-heading text-accent text-xl mb-2 leading-tight tracking-widest">SILENT TRACKING</div>
            <div className="text-xs text-text-primary/70 max-w-[220px] leading-relaxed">
              Your device details and browsing habits are shared with {data?.third_party_domains?.length || 'several'} outside companies.
            </div>
          </div>
        )}
      </div>
    );
  };

  const frameCount = data?.visual_frames?.length || 0;

  return (
    <div className="max-w-[1200px] mx-auto px-8 py-12 lg:py-20">

      {/* LANDING PAGE */}
      {!loading && !data && (
        <div className="flex flex-col items-center text-center animate-in fade-in duration-700 max-w-4xl mx-auto mb-16">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-accent/10 text-accent text-xs font-heading uppercase tracking-widest mb-8 border border-accent/20">
            <span className="w-2 h-2 rounded-full bg-accent animate-pulse" /> Live Sandbox
          </div>
          <h1 className="text-4xl md:text-6xl font-heading text-text-primary mb-6 tracking-tight leading-tight">
            Don't guess if a link is safe. <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-accent to-text-primary">Watch it detonate.</span>
          </h1>
          <p className="text-text-secondary text-base md:text-lg max-w-2xl mb-12 leading-relaxed">
            Threat Trailer opens suspicious links in a secure, isolated cloud device, taps the buttons a victim would tap, and records exactly what the website tries to download, steal, or track, before it ever reaches your personal computer.
          </p>

          {error && (
            <div className="w-full max-w-2xl mb-6 border border-red-500/30 bg-red-500/10 text-red-400 text-sm px-4 py-3 text-left flex items-start gap-2">
              <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" /> {error}
            </div>
          )}

          <form id="detonate-form" onSubmit={handleDetonate} className="flex flex-col sm:flex-row gap-4 w-full max-w-2xl relative shadow-2xl">
            <div className="relative flex-1">
              <Target className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-text-secondary" />
              <input
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Paste a suspicious link here..."
                required
                className="w-full bg-surface-subtle border border-border-subtle pl-12 pr-4 py-4 text-base text-text-primary placeholder:text-text-secondary/50 focus:outline-none focus:border-accent transition-colors"
              />
            </div>
            <button type="submit" className="bg-text-primary hover:bg-white text-canvas text-base px-8 py-4 font-heading font-semibold uppercase transition-colors whitespace-nowrap">
              Inspect Link
            </button>
          </form>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mt-24 text-left">
            <div>
              <EyeOff className="w-8 h-8 text-accent mb-4" />
              <h3 className="font-heading text-lg text-text-primary mb-2">100% Invisible to Hackers</h3>
              <p className="text-sm text-text-secondary">We visit the link from our secure servers, not your browser. The attacker never sees you.</p>
            </div>
            <div>
              <MousePointerClick className="w-8 h-8 text-accent mb-4" />
              <h3 className="font-heading text-lg text-text-primary mb-2">We Click So You Don't Have To</h3>
              <p className="text-sm text-text-secondary">Download buttons, fake logins, hidden popups: we trigger them in the sandbox and show you the result.</p>
            </div>
            <div>
              <ShieldCheck className="w-8 h-8 text-accent mb-4" />
              <h3 className="font-heading text-lg text-text-primary mb-2">Plain English Reports</h3>
              <p className="text-sm text-text-secondary">No cyber-jargon. We tell you exactly what would happen to your phone or laptop.</p>
            </div>
          </div>
        </div>
      )}

      {/* SCANNING TERMINAL */}
      {loading && (
        <div className="max-w-2xl mx-auto mt-20">
          <div className="w-full bg-surface-subtle border border-accent/30 p-8 rounded-sm relative overflow-hidden flex items-center shadow-[0_0_40px_-10px_rgba(94,116,139,0.3)]">
            <div className="absolute top-0 left-0 w-full h-1 bg-accent/50 animate-scan blur-sm"></div>
            <div className="flex flex-col gap-4 z-10 w-full">
              <div className="flex items-center justify-between text-xs font-mono text-accent/80">
                <span>[THREAT_TRAILER_OS]</span>
                <span className="animate-pulse-fast">ALLOCATING_RESOURCES</span>
              </div>
              <div className="flex items-center gap-4 text-text-primary text-base font-mono animate-in slide-in-from-bottom-2 duration-300" key={phaseIndex}>
                {SCAN_PHASES[phaseIndex].icon}
                {SCAN_PHASES[phaseIndex].text}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* THE VERDICT */}
      {data && !loading && (
        <div className="flex flex-col gap-12">

          <div className="flex flex-col gap-2">
            <button className="flex items-center gap-3 hover:text-accent transition-colors w-fit" onClick={() => setData(null)}>
              <span className="text-sm font-heading uppercase tracking-wider">&larr; Scan Another Link</span>
            </button>
            {data.final_url && data.final_url !== data.url && (
              <div className="text-xs font-mono text-text-secondary break-all">
                Redirected to: <span className="text-orange-400">{data.final_url}</span>
              </div>
            )}
          </div>

          {/* SECTION 1: VERDICT */}
          <section className={`border p-8 md:p-12 text-center flex flex-col items-center shadow-2xl relative overflow-hidden animate-in zoom-in-95 fade-in duration-500 ${riskColor}`}>
            {isCritical && <Skull className="absolute -right-10 -top-10 w-64 h-64 opacity-5 text-red-500 pointer-events-none" />}
            {isSafe ? <ShieldCheck className="w-20 h-20 mb-6 drop-shadow-[0_0_15px_currentColor]" /> : <ShieldAlert className="w-20 h-20 mb-6 drop-shadow-[0_0_15px_currentColor]" />}

            <h2 className="text-3xl md:text-5xl font-heading text-text-primary mb-6 max-w-3xl leading-tight relative z-10">
              {data.analysis?.headline || 'Scan Complete'}
            </h2>

            {brand && (
              <div className="relative z-10 mb-6 inline-flex items-center gap-2 px-4 py-2 border border-red-500/40 bg-red-500/10 text-red-400 text-xs font-heading uppercase tracking-widest">
                <Eye className="w-4 h-4" /> Impersonating {brand}
              </div>
            )}

            <div className="flex flex-col md:flex-row items-stretch justify-center gap-6 mb-12 relative z-10 w-full max-w-2xl">
              <div className="flex flex-col flex-1 p-6 bg-background/80 backdrop-blur-sm border border-current/20 text-left">
                <div className="flex justify-between items-end mb-2">
                  <span className="text-xs font-heading tracking-widest uppercase text-text-secondary">Threat Score</span>
                  <span className="text-4xl font-mono font-bold leading-none">{displayScore} <span className="text-xl text-text-secondary/50">/ 10</span></span>
                </div>
                <div className="w-full bg-black/60 h-2 mt-2 rounded-full overflow-hidden border border-current/10 relative">
                  <div
                    className={`absolute top-0 left-0 h-full transition-all duration-1000 ease-out ${isCritical ? 'bg-red-500 shadow-[0_0_10px_#ef4444]' : isSuspicious ? 'bg-orange-500 shadow-[0_0_10px_#f97316]' : 'bg-green-500 shadow-[0_0_10px_#22c55e]'}`}
                    style={{ width: `${(rawScore / 10) * 100}%` }}
                  />
                </div>
              </div>

              <div className="flex flex-col items-center justify-center p-6 bg-background/80 backdrop-blur-sm border border-current/20 min-w-[200px]">
                <span className="text-xs font-heading tracking-widest uppercase text-text-secondary mb-2">Verdict</span>
                <span className="text-3xl font-heading tracking-widest uppercase">{level}</span>
              </div>
            </div>

            <div className="w-full max-w-4xl text-left mb-4 relative z-10">
              <h3 className="text-sm font-heading uppercase tracking-widest text-text-secondary mb-4 border-b border-current/20 pb-2">
                {isSafe ? 'Security Analysis Summary:' : 'If you clicked this link, this would happen:'}
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {data.analysis?.device_impact?.map((impact: string, i: number) => (
                  <div key={i} className="bg-canvas/95 border border-current/30 p-6 flex flex-col gap-4 shadow-lg hover:-translate-y-1 transition-transform">
                    <div className="p-3 bg-background/50 rounded-sm w-fit border border-current/10">
                      {getImpactIcon(impact)}
                    </div>
                    <span className="text-sm text-text-primary/95 leading-relaxed">{impact}</span>
                  </div>
                ))}
              </div>
            </div>
          </section>

          {/* SECTION 2: SCORE BREAKDOWN */}
          {data.score_breakdown?.length > 0 && (
            <section className="bg-surface-subtle border border-border-subtle p-8 shadow-lg animate-in fade-in slide-in-from-bottom-8 duration-700 delay-200 fill-mode-both">
              <div className="text-xs font-heading tracking-wider uppercase text-text-secondary mb-6 border-b border-border-subtle pb-4 flex items-center gap-2">
                <Calculator className="w-4 h-4" /> Threat Score Breakdown
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                {data.score_breakdown.map((rule: any, i: number) => (
                  <div key={i} className={`p-4 border rounded-lg flex flex-col gap-2 justify-between h-full ${getRuleColorClasses(rule.color)}`}>
                    <span className="text-xs uppercase tracking-widest font-bold font-mono">{rule.points} PTS</span>
                    <span className="text-sm text-text-primary/90 leading-snug">{rule.rule}</span>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* SECTION 3: CINEMATIC TRAILER */}
          <section className="bg-surface-subtle border border-border-subtle p-8 shadow-lg animate-in fade-in slide-in-from-bottom-8 duration-700 delay-300 fill-mode-both">
            <div className="text-xs font-heading tracking-wider uppercase text-text-secondary mb-8 border-b border-border-subtle pb-4 flex items-center gap-2">
              <Monitor className="w-4 h-4" /> Cinematic Threat Trailer
            </div>

            <div className="flex overflow-x-auto pb-6 gap-6 snap-x custom-scrollbar">

              {data.visual_frames?.map((frame: any, i: number) => (
                <div key={i} className="flex-none w-[320px] flex flex-col gap-3 snap-center">
                  <span className="text-xs font-heading uppercase text-text-secondary tracking-widest text-center">
                    {i + 1}. {frame.phase || `Frame ${i + 1}`}
                  </span>
                  <div className="w-full h-[420px] bg-canvas/30 border border-border-subtle rounded-lg flex items-center justify-center p-4 relative overflow-hidden">
                    <div className="w-full max-w-[200px] h-full bg-black border-[6px] border-[#2A2A2A] rounded-[2rem] relative shadow-[0_10px_40px_-10px_rgba(0,0,0,0.8)] overflow-hidden flex flex-col">
                      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-20 h-5 bg-[#2A2A2A] rounded-b-xl z-20"></div>
                      {frame.image ? (
                        <img src={`data:image/jpeg;base64,${frame.image}`} alt={`Threat Frame ${i + 1}`} className="w-full h-full object-cover object-top opacity-90" />
                      ) : (
                        <div className="flex flex-col h-full items-center justify-center text-xs text-text-secondary/50 p-6 text-center mt-4">
                          <ImageIcon className="w-6 h-6 mb-2 opacity-30" /> UI Render Failed
                        </div>
                      )}
                    </div>
                  </div>
                  {frame.caption && (
                    <p className="text-xs text-text-primary/80 text-center leading-snug px-2">{frame.caption}</p>
                  )}
                </div>
              ))}

              <div className="flex-none w-[320px] md:w-[400px] flex flex-col gap-3 snap-center">
                <span className="text-xs font-heading uppercase text-text-secondary tracking-widest text-center">{frameCount + 1}. Live Capture</span>
                {renderTerminal()}
              </div>

              <div className="flex-none w-[320px] md:w-[400px] flex flex-col gap-3 snap-center">
                <span className="text-xs font-heading uppercase text-text-secondary tracking-widest text-center">{frameCount + 2}. Ultimate Result</span>
                {renderBlastRadius()}
              </div>

            </div>
          </section>

          {/* SECTION 3.5: WHAT WE DID + WHO GOT YOUR DATA */}
          {(data.interactions?.length > 0 || data.third_party_domains?.length > 0) && (
            <section className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              {data.interactions?.length > 0 && (
                <div className="bg-surface-subtle border border-border-subtle p-8">
                  <div className="flex items-center gap-2 text-xs font-heading tracking-wider uppercase text-text-secondary mb-6 border-b border-border-subtle pb-4">
                    <MousePointerClick className="w-4 h-4" /> What We Did To The Page
                  </div>
                  <ul className="space-y-3">
                    {data.interactions.map((it: any, i: number) => (
                      <li key={i} className="text-sm text-text-primary/90 flex flex-col gap-1">
                        <span className="font-mono text-xs text-text-secondary">
                          {it.action === 'click' ? `Tapped "${it.target}"` : 'Typed fake credentials & submitted'}
                        </span>
                        <span className="flex flex-wrap gap-2">
                          {it.caused_download && <span className="text-[10px] px-2 py-0.5 border border-red-500/40 text-red-400 uppercase">download</span>}
                          {it.caused_popup && <span className="text-[10px] px-2 py-0.5 border border-red-500/40 text-red-400 uppercase">popup</span>}
                          {it.caused_dialog && <span className="text-[10px] px-2 py-0.5 border border-orange-500/40 text-orange-400 uppercase">alert</span>}
                          {it.navigated_to && <span className="text-[10px] px-2 py-0.5 border border-orange-500/40 text-orange-400 uppercase">redirect</span>}
                          {!it.caused_download && !it.caused_popup && !it.caused_dialog && !it.navigated_to && it.action === 'click' &&
                            <span className="text-[10px] px-2 py-0.5 border border-border-subtle text-text-secondary uppercase">nothing happened</span>}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {data.third_party_domains?.length > 0 && (
                <div className="bg-surface-subtle border border-border-subtle p-8">
                  <div className="flex items-center gap-2 text-xs font-heading tracking-wider uppercase text-text-secondary mb-6 border-b border-border-subtle pb-4">
                    <Globe className="w-4 h-4" /> Who Else Got Your Data
                  </div>
                  <div className="space-y-3">
                    {(data.third_party_domains as [string, number][]).map(([domain, count]) => (
                      <div key={domain} className="flex flex-col gap-1">
                        <div className="flex justify-between text-xs font-mono">
                          <span className="text-text-primary/90 break-all">{domain}</span>
                          <span className="text-text-secondary">{count} req</span>
                        </div>
                        <div className="w-full h-1.5 bg-black/50 rounded-full overflow-hidden">
                          <div className="h-full bg-accent" style={{ width: `${(count / maxThirdParty) * 100}%` }} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </section>
          )}

          {/* SECTION 4: NETWORK LOGS & TIMELINE */}
          <section className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <div className="bg-surface-subtle border border-border-subtle p-8 animate-in fade-in slide-in-from-left-4 duration-700 delay-500 fill-mode-both">
              <div className="flex items-center gap-2 text-xs font-heading tracking-wider uppercase text-text-secondary mb-4">
                <ActivitySquare className="w-4 h-4" /> Behind-the-Scenes Traffic
              </div>
              <p className="text-xs text-text-secondary mb-4">Everything the website tried to download or send in the background without asking you.</p>
              <div className="bg-canvas border border-border-subtle h-[300px] overflow-y-auto p-5 font-mono text-[11px] leading-relaxed space-y-3 shadow-inner">
                {data.network_logs?.length > 0 ? (
                  data.network_logs.map((log: string, idx: number) => {
                    const isDanger = isSuspiciousPayload(log);
                    return (
                      <div key={idx} className={`break-all ${isDanger ? 'text-red-400 font-bold' : 'text-text-secondary/60'}`}>
                        {isDanger ? '⚠️ [DANGER]' : '↳ [NORMAL]'} {log}
                      </div>
                    );
                  })
                ) : (
                  <div className="text-text-secondary/40">No hidden background activity detected.</div>
                )}
              </div>
            </div>

            <div className="bg-surface-subtle border border-border-subtle p-8 animate-in fade-in slide-in-from-right-4 duration-700 delay-500 fill-mode-both">
              <div className="text-xs font-heading tracking-wider uppercase text-text-secondary mb-8 border-b border-border-subtle pb-4">
                Step-by-Step Incident Timeline
              </div>
              <div className="space-y-8 border-l-2 border-border-subtle pl-6 ml-3 h-[300px] overflow-y-auto pr-4 custom-scrollbar">
                {(data.dynamic_timeline || data.analysis?.trailer_timeline)?.map((step: any, idx: number) => (
                  <div key={idx} className="relative">
                    <span className={`absolute -left-[33px] top-1 w-3 h-3 rounded-full ${step.type === 'danger' || (isCritical && !step.type) ? 'bg-red-500 shadow-[0_0_10px_#ef4444]' : step.type === 'success' || (isSafe && !step.type) ? 'bg-green-500 shadow-[0_0_10px_rgba(34,197,94,0.5)]' : step.type === 'warning' ? 'bg-orange-500 shadow-[0_0_10px_#f97316]' : 'bg-text-primary'}`} />
                    <span className="font-heading text-xs text-text-secondary block mb-1 uppercase tracking-wider">{step.phase}</span>
                    <p className="text-sm text-text-primary/90 leading-relaxed">{step.action}</p>
                  </div>
                ))}
              </div>
            </div>
          </section>

          {/* SECTION 5: DEFENSE PROTOCOL */}
          {(isCritical || isSuspicious) && (isRansomware || isPhishing || isClipboard) && (
            <section className="bg-green-900/10 border border-green-500/30 p-8 shadow-lg relative overflow-hidden animate-in fade-in slide-in-from-bottom-4 duration-700 delay-700 fill-mode-both">
              <div className="absolute top-0 left-0 w-1 h-full bg-green-500"></div>
              <div className="text-xs font-heading tracking-wider uppercase text-green-500 mb-6 flex items-center gap-2">
                <ShieldCheck className="w-5 h-5" /> Recommended Defense Protocol
              </div>
              <p className="text-sm text-text-primary/90 leading-relaxed mb-4 max-w-3xl">
                Threat Trailer ran this link in a cloud sandbox, so your personal device is safe. If you or someone else already opened it on a real device, do this right away:
              </p>
              <ul className="space-y-3 max-w-3xl">
                {isRansomware && (
                  <>
                    <li className="flex items-start gap-2 text-sm"><span className="text-green-500 font-bold">1.</span> Disconnect from Wi-Fi so any malware can't reach its command server.</li>
                    <li className="flex items-start gap-2 text-sm"><span className="text-green-500 font-bold">2.</span> Do NOT open any downloaded file (.exe, .apk, .zip, .msi). Delete it permanently.</li>
                    <li className="flex items-start gap-2 text-sm"><span className="text-green-500 font-bold">3.</span> Run a full scan with Microsoft Defender or Malwarebytes.</li>
                  </>
                )}
                {isPhishing && (
                  <>
                    <li className="flex items-start gap-2 text-sm"><span className="text-green-500 font-bold">1.</span> Go to the real website manually (do NOT use this link) and change your password.</li>
                    <li className="flex items-start gap-2 text-sm"><span className="text-green-500 font-bold">2.</span> Turn on two-factor authentication if it isn't active.</li>
                    <li className="flex items-start gap-2 text-sm"><span className="text-green-500 font-bold">3.</span> Watch your email and bank statements for unrecognised logins.</li>
                  </>
                )}
                {isClipboard && (
                  <>
                    <li className="flex items-start gap-2 text-sm"><span className="text-green-500 font-bold">1.</span> Do NOT paste anything into Run, PowerShell, Terminal or a command prompt.</li>
                    <li className="flex items-start gap-2 text-sm"><span className="text-green-500 font-bold">2.</span> Clear your clipboard by copying any harmless word, then close the page.</li>
                  </>
                )}
              </ul>
            </section>
          )}

        </div>
      )}
    </div>
  );
}