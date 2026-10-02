import Link from 'next/link';
import { notFound } from 'next/navigation';
import {
  ShieldAlert, AlertCircle, ArrowLeft, HardDrive, CreditCard, Ghost, Skull,
  FileJson, Terminal, Server, Lock, Monitor, ShieldCheck, CheckCircle,
  ClipboardCopy, Calculator, Eye
} from 'lucide-react';
import { getThreatLogById } from '../../actions';
import ShareButton from './ShareButton';
import PdfButton from './PdfButton';
import CopyJsonButton from './CopyJsonButton';

type RuntimeEvent = { level: string; text: string };
type Rule = { rule: string; points: string; color: string };
type Frame = { phase?: string; caption?: string };

const ruleClasses = (color: string) =>
  color === 'red' ? 'border-red-500/30 bg-red-500/10 text-red-400' :
  color === 'orange' ? 'border-orange-500/30 bg-orange-500/10 text-orange-400' :
  color === 'green' ? 'border-green-500/30 bg-green-500/10 text-green-400' :
  'border-accent/30 bg-accent/10 text-accent';

export default async function PastScanPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const log = await getThreatLogById(id);

  if (!log) {
    notFound();
  }

  const analysis = (log.analysis ?? {}) as any;

  // ---- Verdict: prefer the column, fall back to the JSON (older rows) ----
  const level: string = log.riskLevel || analysis.exfiltration_level || 'UNKNOWN';
  const isCritical = level === 'CRITICAL';
  const isSuspicious = level === 'SUSPICIOUS';
  const isSafe = level === 'SAFE';

  const riskColor = isCritical ? 'text-red-500 border-red-500/30 bg-red-500/5' :
                    isSuspicious ? 'text-orange-400 border-orange-400/30 bg-orange-400/5' :
                    isSafe ? 'text-green-500 border-green-500/30 bg-green-500/5' :
                    'text-accent border-accent/30 bg-accent/5';

  // ---- Real score. Old rows saved before this change have no score. ----
  const hasScore = typeof analysis.threat_score === 'number';
  const scoreText = hasScore ? `${analysis.threat_score.toFixed(1)} / 10` : 'N/A';

  // ---- Saved scan evidence (all optional, so old rows still render) ----
  const breakdown: Rule[] = Array.isArray(analysis.score_breakdown) ? analysis.score_breakdown : [];
  const events: RuntimeEvent[] = Array.isArray(analysis.runtime_events) ? analysis.runtime_events : [];
  const frames: Frame[] = Array.isArray(analysis.visual_frames) ? analysis.visual_frames : [];
  const triggers = analysis.honeypot_triggers ?? {};
  const brand: string | null = analysis.impersonated_brand ?? null;
  const impacts: string[] = Array.isArray(analysis.device_impact) ? analysis.device_impact : [];
  const timeline: { phase: string; action: string }[] = Array.isArray(analysis.trailer_timeline) ? analysis.trailer_timeline : [];

  // VirusTotal count lives inside the breakdown rule text ("Flagged by N ...")
  const vtRule = breakdown.find((r) => /^Flagged by (\d+)/.test(r.rule));
  const vtFlags = vtRule ? Number(vtRule.rule.match(/^Flagged by (\d+)/)![1]) : 0;

  const headline = String(analysis.headline ?? '').toLowerCase();
  const isRansomware = !!triggers.tried_download || headline.includes('drive-by') || headline.includes('ransomware');
  const isClipboard = !!triggers.clipboard_hijack;
  const isPhishing = !!triggers.credentials_exfiltrated || !!brand || headline.includes('credential') || headline.includes('phishing');

  const getImpactIcon = (text: string) => {
    const lower = text.toLowerCase();
    if (lower.includes('clipboard')) return <ClipboardCopy className="w-6 h-6 text-red-400" />;
    if (lower.includes('ransomware') || lower.includes('file') || lower.includes('binary') || lower.includes('malware')) return <HardDrive className="w-6 h-6 text-red-400" />;
    if (lower.includes('password') || lower.includes('financial') || lower.includes('credential')) return <CreditCard className="w-6 h-6 text-orange-400" />;
    if (lower.includes('stealth') || lower.includes('background') || lower.includes('monitor') || lower.includes('fingerprint')) return <Ghost className="w-6 h-6 text-purple-400" />;
    if (isSafe) return <CheckCircle className="w-6 h-6 text-green-500" />;
    return <AlertCircle className="w-6 h-6 text-accent" />;
  };

  // JSON shown in the console: everything except the bulky frame list
  const { visual_frames: _omit, ...jsonForDisplay } = analysis;

  return (
    <div className="max-w-[1200px] mx-auto px-8 py-12">

      {/* Header */}
      <div className="flex items-center justify-between mb-8 print:hidden">
        <Link href="/history" className="inline-flex items-center gap-2 text-sm font-heading uppercase tracking-wider text-text-secondary hover:text-text-primary transition-colors">
          <ArrowLeft className="w-4 h-4" /> Back to History
        </Link>
        <div className="flex items-center gap-4">
          <PdfButton />
          <ShareButton title={analysis.headline || 'Threat Report'} id={id} />
        </div>
      </div>

      <div className="flex flex-col gap-12">

        {/* SECTION 1: VERDICT */}
        <section className={`border p-8 md:p-12 text-center flex flex-col items-center shadow-2xl relative overflow-hidden ${riskColor}`}>
          {isCritical && <Skull className="absolute -right-10 -top-10 w-64 h-64 opacity-5 text-red-500 pointer-events-none" />}
          {isSafe ? <ShieldCheck className="w-20 h-20 mb-6 drop-shadow-[0_0_15px_currentColor]" /> : <ShieldAlert className="w-20 h-20 mb-6 drop-shadow-[0_0_15px_currentColor]" />}

          <h2 className="text-3xl md:text-5xl font-heading text-text-primary mb-6 max-w-3xl leading-tight relative z-10">
            {analysis.headline || 'Archived Scan Report'}
          </h2>

          {brand && (
            <div className="relative z-10 mb-6 inline-flex items-center gap-2 px-4 py-2 border border-red-500/40 bg-red-500/10 text-red-400 text-xs font-heading uppercase tracking-widest">
              <Eye className="w-4 h-4" /> Impersonating {brand}
            </div>
          )}

          {analysis.final_url && analysis.final_url !== log.url && (
            <div className="relative z-10 mb-6 text-xs font-mono text-text-secondary break-all">
              Redirected to: <span className="text-orange-400">{analysis.final_url}</span>
            </div>
          )}

          <div className="flex flex-col md:flex-row items-center gap-6 mb-12 relative z-10">
            <div className="flex flex-col items-center p-4 bg-background/80 backdrop-blur-sm border border-current/20 min-w-[160px]">
              <span className="text-xs font-heading tracking-widest uppercase text-text-secondary mb-1">Threat Score</span>
              <span className="text-3xl font-mono font-bold">{scoreText}</span>
            </div>
            <div className="flex flex-col items-center p-4 bg-background/80 backdrop-blur-sm border border-current/20 min-w-[160px]">
              <span className="text-xs font-heading tracking-widest uppercase text-text-secondary mb-1">Verdict</span>
              <span className="text-2xl font-heading tracking-widest uppercase">{level}</span>
            </div>
          </div>

          {impacts.length > 0 && (
            <div className="w-full max-w-4xl text-left mb-4 relative z-10">
              <h3 className="text-sm font-heading uppercase tracking-widest text-text-secondary mb-4 border-b border-current/20 pb-2">
                {isSafe ? 'Security Analysis Summary:' : 'If you clicked this link, this would happen:'}
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {impacts.map((impact, i) => (
                  <div key={i} className="bg-canvas/95 border border-current/30 p-6 flex flex-col gap-4 shadow-lg hover:-translate-y-1 transition-transform">
                    <div className="p-3 bg-background/50 rounded-sm w-fit border border-current/10">
                      {getImpactIcon(impact)}
                    </div>
                    <span className="text-sm text-text-primary/95 leading-relaxed">{impact}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>

        {/* SECTION 2: SCORE BREAKDOWN */}
        {breakdown.length > 0 && (
          <section className="bg-surface-subtle border border-border-subtle p-8 shadow-lg">
            <div className="text-xs font-heading tracking-wider uppercase text-text-secondary mb-6 border-b border-border-subtle pb-4 flex items-center gap-2">
              <Calculator className="w-4 h-4" /> Threat Score Breakdown
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {breakdown.map((rule, i) => (
                <div key={i} className={`p-4 border rounded-lg flex flex-col gap-2 justify-between h-full ${ruleClasses(rule.color)}`}>
                  <span className="text-xs uppercase tracking-widest font-bold font-mono">{rule.points} PTS</span>
                  <span className="text-sm text-text-primary/90 leading-snug">{rule.rule}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* SECTION 3: WHAT HAPPENED (real data, no scripted output) */}
        <section className="bg-surface-subtle border border-border-subtle p-8 shadow-lg">
          <div className="text-xs font-heading tracking-wider uppercase text-text-secondary mb-8 border-b border-border-subtle pb-4 flex items-center gap-2">
            <Monitor className="w-4 h-4" /> Scan Trailer
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">

            {/* Steps the scanner took (screenshots are not stored, captions are) */}
            <div className="flex flex-col gap-3">
              <span className="text-xs font-heading uppercase text-text-secondary tracking-widest">1. Steps Captured</span>
              <div className="w-full h-[420px] bg-canvas/30 border border-border-subtle rounded-lg p-5 overflow-y-auto">
                {frames.length > 0 ? (
                  <ol className="space-y-4">
                    {frames.map((f, i) => (
                      <li key={i} className="text-sm">
                        <span className="block font-heading text-xs uppercase tracking-wider text-text-secondary">{f.phase || `Step ${i + 1}`}</span>
                        <span className="text-text-primary/90 leading-snug">{f.caption}</span>
                      </li>
                    ))}
                  </ol>
                ) : (
                  <div className="h-full flex flex-col items-center justify-center text-xs text-text-secondary/50 text-center">
                    <ShieldAlert className="w-6 h-6 mb-2 opacity-30" />
                    No step details saved for this scan.
                  </div>
                )}
              </div>
            </div>

            {/* Real captured events */}
            <div className="flex flex-col gap-3">
              <span className="text-xs font-heading uppercase text-text-secondary tracking-widest">2. Live Capture</span>
              <div className="w-full h-[420px] bg-[#0a0a0a] border border-border-subtle p-5 font-mono text-[11px] shadow-inner overflow-y-auto flex flex-col gap-1 rounded-lg">
                <div className="mb-2 text-text-secondary/50">root@sandbox:~# live_capture --mobile</div>
                {events.length === 0 && <div className="text-text-secondary/50">&gt;&gt; No runtime activity saved for this scan.</div>}
                {events.map((e, i) => (
                  <div key={i} className={e.level === 'danger' ? 'text-red-500 font-bold' : e.level === 'warn' ? 'text-yellow-400' : 'text-green-400/80'}>
                    &gt;&gt; {e.text}
                  </div>
                ))}
                <div className={`mt-auto pt-3 font-bold tracking-widest ${isCritical ? 'text-red-500' : isSuspicious ? 'text-orange-400' : 'text-green-500'}`}>
                  {isCritical ? 'SYSTEM COMPROMISED _' : isSuspicious ? 'SILENT TRACKING ACTIVE _' : 'SYSTEM SECURE _'}
                </div>
              </div>
            </div>

            {/* Result */}
            <div className="flex flex-col gap-3">
              <span className="text-xs font-heading uppercase text-text-secondary tracking-widest">3. Ultimate Result</span>
              <div className="w-full h-[420px] border border-border-subtle overflow-hidden shadow-inner flex items-center justify-center p-6 relative rounded-lg">
                {isRansomware ? (
                  <div className="absolute inset-0 bg-red-900/10 flex flex-col items-center justify-center text-center p-4 border border-red-500/20">
                    <Lock className="w-16 h-16 text-red-500 mb-4 drop-shadow-[0_0_8px_#ef4444]" />
                    <div className="font-heading text-red-500 text-xl mb-2 leading-tight tracking-widest">FILE DROPPED</div>
                    <div className="text-xs text-text-primary/70 mb-4 max-w-[220px] leading-relaxed">
                      {triggers.files_dropped?.[0] || 'A file'} was pushed to the device. If opened, ransomware could lock your personal data.
                    </div>
                    <div className="bg-red-500 text-black text-[10px] font-bold px-4 py-2 uppercase tracking-wider">Worst case: ransom demand</div>
                  </div>
                ) : isClipboard ? (
                  <div className="absolute inset-0 bg-red-900/10 flex flex-col items-center justify-center text-center p-4 border border-red-500/20">
                    <ClipboardCopy className="w-16 h-16 text-red-500 mb-4 drop-shadow-[0_0_8px_#ef4444]" />
                    <div className="font-heading text-red-500 text-xl mb-2 leading-tight tracking-widest">CLIPBOARD HIJACKED</div>
                    <div className="text-xs text-text-primary/70 max-w-[220px] leading-relaxed">The page silently copied a command to the clipboard. Never paste it.</div>
                  </div>
                ) : isPhishing ? (
                  <div className="absolute inset-0 bg-orange-900/10 flex flex-col items-center justify-center text-center p-4 border border-orange-500/20">
                    <CreditCard className="w-16 h-16 text-orange-500 mb-4 drop-shadow-[0_0_8px_#f97316]" />
                    <div className="font-heading text-orange-500 text-xl mb-2 leading-tight tracking-widest">
                      {brand ? `FAKE ${brand.toUpperCase()}` : 'DATA BREACH'}
                    </div>
                    <div className="text-xs text-text-primary/70 mb-4 font-mono space-y-1">
                      {brand && <div>pretends to be : <span className="text-red-400">{brand}</span></div>}
                      <div>typed_password : <span className="text-red-400">{triggers.credentials_exfiltrated ? 'SENT TO 3RD PARTY' : 'AT RISK'}</span></div>
                    </div>
                    <div className="bg-orange-500 text-black text-[10px] font-bold px-4 py-2 uppercase tracking-wider">Identity at risk</div>
                  </div>
                ) : isSafe ? (
                  <div className="absolute inset-0 bg-green-900/10 flex flex-col items-center justify-center text-center p-4 border border-green-500/20">
                    <CheckCircle className="w-16 h-16 text-green-500 mb-4 drop-shadow-[0_0_8px_currentColor]" />
                    <div className="font-heading text-green-500 text-xl mb-2 leading-tight tracking-widest">LOOKS SAFE</div>
                    <div className="text-xs text-text-primary/70 max-w-[220px] leading-relaxed">Nothing malicious happened during the scan. Stay alert anyway.</div>
                  </div>
                ) : (
                  <div className="absolute inset-0 bg-accent/10 flex flex-col items-center justify-center text-center p-4 border border-accent/20">
                    <Ghost className="w-16 h-16 text-accent mb-4 drop-shadow-[0_0_8px_currentColor]" />
                    <div className="font-heading text-accent text-xl mb-2 leading-tight tracking-widest">SILENT TRACKING</div>
                    <div className="text-xs text-text-primary/70 max-w-[220px] leading-relaxed">
                      Device details and browsing habits are shared with {analysis.third_party_domains?.length || 'several'} outside companies.
                    </div>
                  </div>
                )}
              </div>
            </div>

          </div>
        </section>

        {/* SECTION 4: TIMELINE */}
        {timeline.length > 0 && (
          <section className="bg-surface-subtle border border-border-subtle p-8 shadow-lg">
            <div className="text-xs font-heading tracking-wider uppercase text-text-secondary mb-8 border-b border-border-subtle pb-4">
              Step-by-Step Incident Timeline
            </div>
            <div className="space-y-8 border-l-2 border-border-subtle pl-6 ml-3">
              {timeline.map((step, idx) => (
                <div key={idx} className="relative">
                  <span className={`absolute -left-[33px] top-1 w-3 h-3 rounded-full ${isCritical ? 'bg-red-500 shadow-[0_0_10px_#ef4444]' : isSafe ? 'bg-green-500' : 'bg-text-primary'}`} />
                  <span className="font-heading text-xs text-text-secondary block mb-2 uppercase tracking-wider">{step.phase}</span>
                  <p className="text-base text-text-primary/90 leading-relaxed">{step.action}</p>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* SECTION 5: DEFENSE PROTOCOL */}
        {(isCritical || isSuspicious) && (isRansomware || isPhishing || isClipboard) && (
          <section className="bg-green-900/10 border border-green-500/30 p-8 shadow-lg relative overflow-hidden">
            <div className="absolute top-0 left-0 w-1 h-full bg-green-500"></div>
            <div className="text-xs font-heading tracking-wider uppercase text-green-500 mb-6 flex items-center gap-2">
              <ShieldCheck className="w-5 h-5" /> Recommended Defense Protocol
            </div>
            <p className="text-sm text-text-primary/90 leading-relaxed mb-4 max-w-3xl">
              Threat Trailer ran this link in a sandbox, so your personal device is safe. If you or someone else already opened it on a real device, do this right away:
            </p>
            <ul className="space-y-3 max-w-3xl">
              {isRansomware && (
                <>
                  <li className="flex items-start gap-2 text-sm"><span className="text-green-500 font-bold">1.</span> Disconnect from Wi-Fi so any malware can&apos;t reach its command server.</li>
                  <li className="flex items-start gap-2 text-sm"><span className="text-green-500 font-bold">2.</span> Do NOT open any downloaded file (.exe, .apk, .zip, .msi). Delete it permanently.</li>
                  <li className="flex items-start gap-2 text-sm"><span className="text-green-500 font-bold">3.</span> Run a full scan with Microsoft Defender or Malwarebytes.</li>
                </>
              )}
              {isPhishing && (
                <>
                  <li className="flex items-start gap-2 text-sm"><span className="text-green-500 font-bold">1.</span> Go to the real website manually (do NOT use this link) and change your password.</li>
                  <li className="flex items-start gap-2 text-sm"><span className="text-green-500 font-bold">2.</span> Turn on two-factor authentication if it isn&apos;t active.</li>
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

        {/* SECTION 6: FORENSIC CONSOLE */}
        <section className="mt-4 border border-border-subtle bg-[#0a0a0a] rounded-sm overflow-hidden shadow-2xl print:hidden">
          <div className="bg-[#141414] border-b border-border-subtle px-6 py-3 flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-mono text-accent">
              <Terminal className="w-4 h-4" />
              <span>FORENSIC_ENGINEER_CONSOLE</span>
            </div>
            <div className="flex gap-2">
              <span className="w-3 h-3 rounded-full bg-red-500/80"></span>
              <span className="w-3 h-3 rounded-full bg-yellow-500/80"></span>
              <span className="w-3 h-3 rounded-full bg-green-500/80"></span>
            </div>
          </div>

          <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-8 font-mono text-xs">
            <div className="flex flex-col gap-4">
              <div className="flex items-center gap-2 text-text-secondary/80 border-b border-border-subtle/50 pb-2">
                <Server className="w-4 h-4" /> Raw OSINT & Telemetry
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-[#1a1a1a] p-4 border border-border-subtle/30">
                  <span className="block text-text-secondary/60 mb-1">Target URL</span>
                  <span className="text-accent break-all">{log.url}</span>
                </div>
                <div className="bg-[#1a1a1a] p-4 border border-border-subtle/30">
                  <span className="block text-text-secondary/60 mb-1">Scan Timestamp</span>
                  <span className="text-text-primary">{log.createdAt.toLocaleString()}</span>
                </div>
                <div className="bg-[#1a1a1a] p-4 border border-border-subtle/30">
                  <span className="block text-text-secondary/60 mb-1">VT Malicious Flags</span>
                  <span className={vtFlags > 0 ? 'text-red-400 font-bold' : 'text-green-400'}>{vtFlags} detected</span>
                </div>
                <div className="bg-[#1a1a1a] p-4 border border-border-subtle/30">
                  <span className="block text-text-secondary/60 mb-1">Background Reqs</span>
                  <span className="text-yellow-400">{log.networkReqs} intercepted</span>
                </div>
              </div>
            </div>

            <div className="flex flex-col gap-4 h-full relative">
              <div className="flex items-center justify-between text-text-secondary/80 border-b border-border-subtle/50 pb-2">
                <div className="flex items-center gap-2">
                  <FileJson className="w-4 h-4" /> Scan JSON Dump
                </div>
                <CopyJsonButton data={jsonForDisplay} />
              </div>
              <div className="bg-[#1a1a1a] p-4 border border-border-subtle/30 h-[250px] overflow-auto">
                <pre className="text-text-primary/70 leading-relaxed whitespace-pre-wrap break-words">
                  {JSON.stringify(jsonForDisplay, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        </section>

      </div>
    </div>
  );
}