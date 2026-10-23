import { useEffect, useState, type CSSProperties } from 'react';
import { AlertTriangle, ArrowRight, Check, ChevronRight, CircleHelp, Clock3, FileSearch, Fingerprint, History, LockKeyhole, RotateCcw, ShieldCheck, Trash2, X } from 'lucide-react';
import { analyzeMessage, type AnalysisRecord, type RiskLevel } from '@/lib/analyzer';

const HISTORY_KEY = 'scamsathi.analysis-history.v1';
const HISTORY_LIMIT = 8;

const samples = [
  { id: 'bank-threat', title: 'Bank account warning', level: 'High' as RiskLevel, text: 'URGENT: Your SBI account will be blocked today. Verify your account immediately at http://sbi-kyc-update.help/login and share the OTP with our support team.' },
  { id: 'refund-fee', title: 'Refund fee request', level: 'High' as RiskLevel, text: 'Your parcel refund is ready. Pay a ₹29 processing fee via UPI now to release your refund. This offer expires in 30 minutes.' },
  { id: 'delivery-update', title: 'Delivery update', level: 'Low' as RiskLevel, text: 'Your delivery could not be completed. Please review the address details using this link: https://bit.ly/parcel-review-24' },
  { id: 'appointment', title: 'Appointment reminder', level: 'Low' as RiskLevel, text: 'Reminder: Your clinic appointment is scheduled for Thursday at 4:30 pm. Call the clinic using the number on your appointment card if you need to reschedule.' },
];

function readHistory(): AnalysisRecord[] {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? '[]');
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item): item is AnalysisRecord =>
      !!item && typeof item === 'object' &&
      typeof item.id === 'string' && typeof item.message === 'string' &&
      typeof item.riskScore === 'number' &&
      ['Low', 'Medium', 'High'].includes(item.riskLevel) &&
      Array.isArray(item.warnings) && Array.isArray(item.recommendations) &&
      typeof item.analyzedAt === 'string',
    ).slice(0, HISTORY_LIMIT);
  } catch {
    return [];
  }
}

function levelColor(level: RiskLevel) {
  return level.toLowerCase();
}

function prettyTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Saved analysis';
  return new Intl.DateTimeFormat('en-IN', { day: 'numeric', month: 'short', hour: 'numeric', minute: '2-digit' }).format(date);
}

function App() {
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [result, setResult] = useState<AnalysisRecord | null>(null);
  const [history, setHistory] = useState<AnalysisRecord[]>([]);
  const [confirmClear, setConfirmClear] = useState(false);
  const [storageNotice, setStorageNotice] = useState('');

  useEffect(() => {
    setHistory(readHistory());
  }, []);

  function saveHistory(next: AnalysisRecord[]) {
    setHistory(next);
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(next.slice(0, HISTORY_LIMIT)));
      setStorageNotice('');
    } catch {
      setStorageNotice('This browser could not save history. Your current analysis is still available until you leave this page.');
    }
  }

  function runAnalysis(source = message) {
    if (!source.trim()) {
      setError('Paste a message to analyse. Empty input is not saved.');
      return;
    }
    const analysis = analyzeMessage(source.trim());
    setMessage(source.trim());
    setError('');
    setResult(analysis);
    saveHistory([analysis, ...history.filter((item) => item.id !== analysis.id)].slice(0, HISTORY_LIMIT));
  }

  function loadSample(text: string) {
    setMessage(text);
    setError('');
  }

  function clearHistory() {
    saveHistory([]);
    setResult(null);
    setConfirmClear(false);
  }

  const scoreStyle = result
    ? { '--score': `${result.riskScore * 3.6}deg`, '--score-color': result.riskLevel === 'High' ? '#ed897e' : result.riskLevel === 'Medium' ? '#e2b96e' : '#77d2ad' } as CSSProperties
    : undefined;

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-inner">
          <div className="brand" aria-label="ScamSathi">
            <span className="brand-mark"><ShieldCheck size={20} strokeWidth={2.2} /></span>
            <span>ScamSathi<small>Personal message check</small></span>
          </div>
          <div className="privacy-chip"><LockKeyhole size={14} /> Runs on this device</div>
        </div>
      </header>

      <main className="page-wrap">
        <section className="intro">
          <div className="intro-copy">
            <div className="eyebrow"><span className="brand-mark" style={{ width: 20, height: 20, borderRadius: 6 }}><Fingerprint size={13} /></span> A calmer second opinion</div>
            <h1>Pause. Check. Then decide.</h1>
            <p>Paste a suspicious message for a clear, local check of common pressure tactics and link patterns. Your message stays in this browser.</p>
          </div>
          <div className="local-note"><ShieldCheck size={15} /> No account. No message uploads.</div>
        </section>

        <div className="layout">
          <section aria-label="Message analyser">
            <div className="panel composer">
              <div className="panel-heading">
                <div><h2>Check a message</h2><p>SMS, WhatsApp, email or payment request</p></div>
                <span className="step-tag">01 / ANALYSE</span>
              </div>
              <label htmlFor="message-input" className="sr-only">Message to analyse</label>
              <textarea
                id="message-input"
                className="text-input"
                data-testid="input-message"
                value={message}
                onChange={(event) => { setMessage(event.target.value); if (error) setError(''); }}
                placeholder="Paste the full message here. You can remove names or personal details first."
                maxLength={5000}
                aria-invalid={!!error}
                aria-describedby={error ? 'message-error' : 'message-count'}
              />
              <div className="input-meta">
                <span id={error ? 'message-error' : 'message-count'} className={error ? 'inline-error' : ''} role={error ? 'alert' : undefined}>
                  {error || 'Your text is analysed locally and is never sent anywhere.'}
                </span>
                <span>{message.length.toLocaleString()} / 5,000</span>
              </div>
              <div className="button-row">
                <button type="button" className="primary-btn" data-testid="button-analyze" onClick={() => runAnalysis()}>
                  <FileSearch size={17} /> Analyse message <ArrowRight size={16} />
                </button>
                <button type="button" className="secondary-btn" data-testid="button-clear-input" onClick={() => { setMessage(''); setError(''); }}>
                  <RotateCcw size={15} /> Clear text
                </button>
              </div>
            </div>

            <section className="panel samples" aria-labelledby="samples-heading">
              <div className="section-heading">
                <h2 id="samples-heading">Try a sample</h2><span>Four examples · select to load</span>
              </div>
              <div className="sample-list">
                {samples.map((sample) => (
                  <button key={sample.id} type="button" className="sample-item" data-testid={`button-sample-${sample.id}`} onClick={() => loadSample(sample.text)} aria-label={`Load sample: ${sample.title}`}>
                    <span className="sample-top"><span className="sample-name">{sample.title}</span><span className={`risk-pill ${levelColor(sample.level)}`}>{sample.level} example</span></span>
                    <span className="sample-preview">{sample.text}</span>
                  </button>
                ))}
              </div>
            </section>
          </section>

          <aside className="side-stack" aria-label="Analysis results and privacy">
            <div className="panel privacy-card">
              <div className="privacy-icon"><LockKeyhole size={17} /></div>
              <div><h3>Private by design</h3><p>Checks run in this tab. Recent analyses are stored only in this browser’s local storage and can be cleared any time.</p></div>
            </div>
            <section className="panel result-card" aria-labelledby="result-heading" aria-live="polite">
              <div className="section-heading"><h2 id="result-heading">Your check</h2>{result && <span>Just now</span>}</div>
              {!result ? (
                <div className="result-empty">
                  <div className="result-empty-icon"><CircleHelp size={22} /></div>
                  <h3>A second opinion, not a verdict</h3>
                  <p>Your score and the reasons behind it will appear here. Nothing is checked against a live threat database.</p>
                </div>
              ) : (
                <>
                  <div className="result-banner">
                    <div className="score-ring" style={scoreStyle}><span className="score-number">{result.riskScore}</span></div>
                    <div><div className="result-label">Heuristic risk score</div><div className="result-level" style={{ color: 'var(--score-color)' }}>{result.riskLevel} risk</div><div className="result-sub">out of 100 · {result.warnings.length} sign{result.warnings.length === 1 ? '' : 's'} matched</div></div>
                  </div>
                  <div className="result-section-label"><AlertTriangle size={14} /> What stood out</div>
                  {result.warnings.length ? (
                    <div className="warning-list">
                      {result.warnings.map((warning) => (
                        <article className={`warning-item ${warning.severity >= 28 ? 'high-warning' : warning.severity >= 20 ? 'medium-warning' : 'low-warning'}`} key={warning.id} data-testid={`warning-${warning.id}`}>
                          <div className="warning-title-row"><span className="warning-title">{warning.title}</span><span className="warning-weight">{warning.category} · +{warning.severity}</span></div>
                          <p>{warning.explanation}</p>
                        </article>
                      ))}
                    </div>
                  ) : <div className="no-signals">No listed warning patterns matched. That does not confirm the message is genuine.</div>}
                  <div className="result-section-label"><Check size={14} /> Safer next steps</div>
                  <ul className="recommendation-list">{result.recommendations.map((recommendation) => <li key={recommendation}><ChevronRight size={14} />{recommendation}</li>)}</ul>
                </>
              )}
            </section>
          </aside>
        </div>

        <section className="panel history" aria-labelledby="history-heading">
          <div className="section-heading">
            <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}><History size={17} color="#83d6b4" /><h2 id="history-heading">Recent checks</h2><span>{history.length} of {HISTORY_LIMIT}</span></div>
            {history.length > 0 && <button type="button" className="ghost-btn" data-testid="button-clear-history" onClick={() => setConfirmClear(true)}><Trash2 size={13} /> Clear history</button>}
          </div>
          {storageNotice && <p className="inline-error" role="status">{storageNotice}</p>}
          {history.length === 0 ? (
            <div className="history-empty">Your recent analyses will stay on this device and appear here.</div>
          ) : (
            <div className="history-list">
              {history.map((item) => (
                <article className="history-entry" key={item.id} data-testid={`history-item-${item.id}`}>
                  <div className="history-entry-head"><span className={`risk-pill ${levelColor(item.riskLevel)}`}>{item.riskLevel} · {item.riskScore}</span><span className="history-date"><Clock3 size={10} style={{ display: 'inline', verticalAlign: '-1px' }} /> {prettyTime(item.analyzedAt)}</span></div>
                  <div className="history-message">{item.message}</div>
                  <button type="button" className="ghost-btn history-open" data-testid={`button-revisit-${item.id}`} onClick={() => { setMessage(item.message); setResult(item); setError(''); }}>
                    Revisit analysis <ChevronRight size={13} />
                  </button>
                </article>
              ))}
            </div>
          )}
        </section>

        <div className="disclaimer" role="note"><AlertTriangle size={15} /><span><strong>Important:</strong> Results are heuristic estimates based on visible message patterns, not proof of fraud or safety. Scams change quickly. Do not share OTPs, PINs or passwords, and independently verify requests using a trusted official channel.</span></div>
        <div className="footer-note">ScamSathi · A private, on-device message check</div>
      </main>

      {confirmClear && (
        <div className="confirm-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setConfirmClear(false); }}>
          <section className="confirm-box" role="alertdialog" aria-modal="true" aria-labelledby="clear-title" aria-describedby="clear-description">
            <h2 id="clear-title">Clear recent checks?</h2>
            <p id="clear-description">This removes the saved analysis history from this browser. This cannot be undone.</p>
            <div className="confirm-actions">
              <button type="button" className="secondary-btn" data-testid="button-cancel-clear" onClick={() => setConfirmClear(false)}><X size={14} /> Keep history</button>
              <button type="button" className="primary-btn" data-testid="button-confirm-clear" onClick={clearHistory}><Trash2 size={14} /> Clear history</button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}

export default App;
