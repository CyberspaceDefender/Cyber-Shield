"""
Cyber-Shield MVP — Main Application Server
A Python HTTP server that serves a full-featured GUI for scam detection.
No external dependencies beyond the standard library.

Usage:
    python3 app.py
    Then open http://localhost:8888 in your browser.
"""

import sys
import os
import json
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# Add parent directory to path for module imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.threat_engine import scan_message, ThreatStats
from modules.language_module import get_warning, get_available_languages


# ── Global state ──────────────────────────────────────────────────────────

stats = ThreatStats()
scan_history = []

# ── Sample messages for the demo panel ────────────────────────────────────

DEMO_MESSAGES = [
    {
        "label": "Bank Phishing SMS",
        "text": "URGENT: Your GTBank account has been flagged for suspicious activity. Verify your BVN and OTP immediately to avoid account suspension. Click: gtb-secure-verify.tk/login"
    },
    {
        "label": "Fake CBN Grant",
        "text": "Congratulations! You have been selected to receive N500,000 from the CBN COVID-19 Palliative Fund. Send your BVN, account number and 'processing fee' of N2,500 to 0801234567 to claim."
    },
    {
        "label": "MTN Lottery Scam",
        "text": "Dear MTN subscriber, you have WON N1,000,000 in our 30th anniversary promo! Claim your prize within 24 hours. Send your name, bank details and N5,000 activation fee to Agent Mike: 0901234567"
    },
    {
        "label": "Crypto Investment Fraud",
        "text": "Earn 150% guaranteed returns in 7 days! Join our Bitcoin/USDT trading group. Invest as little as 50k and earn 75k weekly. Trusted by 5000+ Nigerians. DM now, limited slots!"
    },
    {
        "label": "Legitimate Bank Alert",
        "text": "Access Bank: Your account ending 4521 was debited N15,000.00 on 18/03/2026 at 10:45. If this was not you, call 01-2712005 or visit accessbankplc.com immediately."
    },
    {
        "label": "Romance Scam",
        "text": "Hello dear, I am Dr. James Williams, US Army doctor deployed in Syria. I saw your profile and fell in love instantly. I have a package worth $500,000 I need to transfer to Nigeria. Please help me, I will share with you."
    },
]


# ── HTML GUI ──────────────────────────────────────────────────────────────

def build_html(demo_json_str: str):
    demo_options = "".join(
        f'<option value="{i}">{m["label"]}</option>'
        for i, m in enumerate(DEMO_MESSAGES)
    )

    # JavaScript is a plain string — NO f-string escaping needed at all.
    # Only two values are injected via .replace() after the fact.
    js_code = """
let selectedLang = 'pidgin';
let currentResult = null;
const DEMOS = __DEMO_JSON__;

function selectLang(btn) {
  document.querySelectorAll('.lang-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  selectedLang = btn.dataset.lang;
  if (currentResult) renderResult(currentResult);
}

function loadDemo(idx) {
  if (idx === '') return;
  document.getElementById('msg-input').value = DEMOS[parseInt(idx)].text;
}

function clearAll() {
  document.getElementById('msg-input').value = '';
  document.getElementById('demo-select').value = '';
  document.getElementById('result-panel').style.display = 'none';
  currentResult = null;
}

function showTab(btn, panelId) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById(panelId).classList.add('active');
}

async function doScan() {
  const text = document.getElementById('msg-input').value.trim();
  if (!text) { alert('Please enter a message to scan.'); return; }

  const btn = document.getElementById('scan-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Scanning...';

  try {
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ text, language: selectedLang })
    });
    const data = await resp.json();
    if (data.error) throw new Error(data.error);
    currentResult = data;
    renderResult(data);
    updateStats(data.stats);
    updateHistory(data.result, text);
  } catch (e) {
    alert('Scan error: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = 'Scan Message';
  }
}

function renderResult(data) {
  const result  = data.result;
  const warning = data.warning;
  const panel = document.getElementById('result-panel');
  panel.style.display = 'block';
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  // Reset to first tab
  document.querySelectorAll('.tab').forEach((t, i) => t.classList.toggle('active', i === 0));
  document.querySelectorAll('.tab-panel').forEach((p, i) => p.classList.toggle('active', i === 0));

  const v = result.verdict;
  const icons = { SCAM: '[SCAM]', SUSPICIOUS: '[WARN]', CAUTION: '[CAUTION]', SAFE: '[SAFE]' };

  // ── Verdict banner ──
  document.getElementById('verdict-banner').innerHTML =
    '<div class="verdict-banner verdict-' + v + '">' +
      '<div class="verdict-icon">' + (icons[v] || '?') + '</div>' +
      '<div>' +
        '<div class="verdict-title">' + escHtml(warning.headline) + '</div>' +
        '<div class="verdict-summary">' + escHtml(warning.summary) + '</div>' +
      '</div>' +
    '</div>';

  // ── Risk meter ──
  const score = result.risk_score;
  const rColor = score >= 70 ? 'var(--red)' : score >= 40 ? 'var(--amber)' : score >= 20 ? '#f5c56a' : 'var(--green)';
  document.getElementById('risk-meter-container').innerHTML =
    '<div class="risk-meter">' +
      '<div class="risk-label"><span>Risk Score</span>' +
        '<span style="color:' + rColor + '; font-weight:600">' + score + '/100</span></div>' +
      '<div class="risk-bar"><div class="risk-fill" style="width:' + score + '%; background:' + rColor + '"></div></div>' +
    '</div>';

  // ── Threat category badges ──
  let badgesHtml = '';
  if (result.categories && result.categories.length) {
    badgesHtml = result.categories.map(function(c) {
      return '<span class="badge badge-amber">' + escHtml(c) + '</span>';
    }).join('');
  }
  if (result.verdict !== 'SAFE') {
    var confCls = result.confidence === 'HIGH' ? 'badge-red' : 'badge-amber';
    badgesHtml += '<span class="badge ' + confCls + '">' + escHtml(result.confidence) + ' CONFIDENCE</span>';
  }
  document.getElementById('threat-badges').innerHTML =
    badgesHtml ? '<div class="threat-badges">' + badgesHtml + '</div>' : '';

  // ── Category explanation ──
  var catEl = document.getElementById('cat-explanation');
  if (warning.category_explanation) {
    catEl.innerHTML =
      '<div class="cat-explain">' +
        '<div class="cat-explain-title">Threat Pattern: ' +
          escHtml(result.primary_category || 'General') + '</div>' +
        escHtml(warning.category_explanation) +
      '</div>';
  } else {
    catEl.innerHTML = '';
  }

  // ── Actions tab ──
  document.getElementById('actions-header').textContent = warning.headline;
  var stepItems = warning.what_to_do.map(function(step) {
    var cls = (step.indexOf('No ') === 0 || step.indexOf('Do not') === 0 || step.startsWith('Never')) ? 'action-no'
            : (step.indexOf('Yes') >= 0 || step.startsWith('Delete') || step.startsWith('Report') || step.startsWith('Call') || step.startsWith('Access')) ? 'action-yes'
            : step.indexOf('Warning') >= 0 ? 'action-warn'
            : 'action-info';
    // Detect step type by emoji codepoint
    var cp = step.codePointAt(0);
    if (cp === 0x1F6AB) cls = 'action-no';
    if (cp === 0x2705)  cls = 'action-yes';
    if (cp === 0x26A0)  cls = 'action-warn';
    if (cp === 0x1F50D || cp === 0x1F4A1) cls = 'action-info';
    return '<li class="' + cls + '">' + escHtml(step) + '</li>';
  }).join('');
  document.getElementById('steps-list').innerHTML = stepItems;

  // ── Technical tab ──
  var urlHtml = '';
  if (result.urls_found && result.urls_found.length) {
    urlHtml = '<div style="font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px;font-weight:500;">URLs Detected</div>';
    result.url_analysis.forEach(function(u) {
      var rc = u.risk_score >= 60 ? 'url-risk-high' : u.risk_score >= 30 ? 'url-risk-med' : 'url-risk-low';
      var uc = u.risk_score >= 60 ? 'var(--red)' : u.risk_score >= 30 ? 'var(--amber)' : 'var(--green)';
      var findings = u.findings.map(function(f) {
        return '<li style="color:var(--text2);margin-top:4px;line-height:1.4">' + escHtml(f) + '</li>';
      }).join('');
      urlHtml +=
        '<div class="url-item ' + rc + '">' +
          '<div class="url-text">' + escHtml(u.url) + '</div>' +
          '<div style="font-size:11px;color:var(--text2)">Risk: ' +
            '<strong style="color:' + uc + '">' + u.risk_score + '/100</strong></div>' +
          (findings ? '<ul style="padding-left:14px;margin-top:6px;font-size:11px">' + findings + '</ul>' : '') +
        '</div>';
    });
  } else {
    urlHtml = '<div style="color:var(--text2);font-size:12px;">No URLs detected in message.</div>';
  }

  var patternsHtml = '';
  if (result.patterns_matched && result.patterns_matched.length) {
    var pItems = result.patterns_matched.map(function(p) {
      var pr = p.severity === 'CRITICAL' ? 'url-risk-high' : p.severity === 'HIGH' ? 'url-risk-high' : 'url-risk-med';
      var bc = p.severity === 'CRITICAL' ? 'badge-red' : 'badge-amber';
      return '<div class="url-item ' + pr + '" style="margin-top:6px">' +
               '<div style="font-weight:600;font-size:12px">' + escHtml(p.category) +
                 ' <span class="badge ' + bc + '" style="font-size:10px">' + escHtml(p.severity) + '</span>' +
               '</div>' +
             '</div>';
    }).join('');
    patternsHtml =
      '<div style="margin-top:14px">' +
        '<div style="font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px;font-weight:500;">Pattern Matches</div>' +
        pItems +
      '</div>';
  }

  var scanTime = '';
  try { scanTime = new Date(result.timestamp).toLocaleTimeString(); } catch(e) { scanTime = '—'; }

  document.getElementById('tech-content').innerHTML =
    '<div style="font-family:monospace;font-size:12px;color:var(--text2);background:var(--bg3);padding:10px;border-radius:6px;margin-bottom:12px;">' +
      'MSG-ID: ' + escHtml(result.message_hash) +
      ' &nbsp;|&nbsp; SCANNED: ' + scanTime +
      ' &nbsp;|&nbsp; PATTERNS: ' + (result.patterns_matched ? result.patterns_matched.length : 0) +
    '</div>' + urlHtml + patternsHtml;

  // ── Learn tab ──
  document.getElementById('learn-content').innerHTML =
    '<div class="learn-label">Learn From This Scan</div>' +
    '<div class="learn-text">' + escHtml(warning.learn) + '</div>';
}

function escHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function updateStats(s) {
  document.getElementById('stat-total').textContent      = s.total      || 0;
  document.getElementById('stat-scams').textContent      = s.scams      || 0;
  document.getElementById('stat-suspicious').textContent = s.suspicious || 0;
  document.getElementById('stat-safe').textContent       = s.safe       || 0;
}

function updateHistory(result, text) {
  var list = document.getElementById('history-list');
  var placeholder = list.querySelector('div');
  if (placeholder && list.children.length === 1) list.innerHTML = '';

  var preview = text.substring(0, 42) + (text.length > 42 ? '\u2026' : '');
  var item = document.createElement('div');
  item.className = 'history-item';
  item.innerHTML =
    '<span class="h-verdict h-' + result.verdict + '">' + result.verdict + '</span>' +
    '<span class="h-text">' + escHtml(preview) + '</span>' +
    '<span class="h-score">' + result.risk_score + '</span>';
  list.insertBefore(item, list.firstChild);
  while (list.children.length > 8) list.removeChild(list.lastChild);
}

function clearHistory() {
  document.getElementById('history-list').innerHTML =
    '<div style="padding:16px 0;color:var(--text2);font-size:12px;text-align:center;">No scans yet</div>';
  fetch('/api/reset', { method: 'POST' });
  ['stat-total','stat-scams','stat-suspicious','stat-safe'].forEach(function(id) {
    document.getElementById(id).textContent = '0';
  });
}
""".replace("__DEMO_JSON__", demo_json_str)

    # HTML and CSS — only static values here, no JS expressions
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cyber-Shield — AI Scam Detector in Local Languages</title>
<style>
  :root {{
    --bg: #0d1117;
    --bg2: #161b22;
    --bg3: #21262d;
    --border: #30363d;
    --text: #e6edf3;
    --text2: #8b949e;
    --green: #3fb950;
    --green-bg: #0d2014;
    --red: #f85149;
    --red-bg: #2d1117;
    --amber: #d29922;
    --amber-bg: #272115;
    --blue: #58a6ff;
    --blue-bg: #0c1f3a;
    --teal: #39d0a0;
    --radius: 8px;
    --radius-lg: 12px;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    font-size: 14px;
    line-height: 1.6;
    min-height: 100vh;
  }}

  /* ── Header ── */
  header {{
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 0 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 56px;
    position: sticky;
    top: 0;
    z-index: 100;
  }}

  .logo {{
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: 600;
    font-size: 16px;
  }}

  .logo-icon {{
    width: 32px; height: 32px;
    background: linear-gradient(135deg, #1a4731, #0d2e1f);
    border: 1px solid #3fb95033;
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 16px;
  }}

  .logo span {{ color: var(--teal); }}

  .header-right {{
    display: flex;
    align-items: center;
    gap: 16px;
    font-size: 12px;
    color: var(--text2);
  }}

  .status-dot {{
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--green);
    animation: pulse 2s ease-in-out infinite;
  }}

  @keyframes pulse {{
    0%, 100% {{ opacity: 1; }}
    50% {{ opacity: 0.5; }}
  }}

  /* ── Layout ── */
  .container {{
    max-width: 1100px;
    margin: 0 auto;
    padding: 24px 20px;
    display: grid;
    grid-template-columns: 1fr 340px;
    gap: 20px;
  }}

  /* ── Cards ── */
  .card {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }}

  .card-header {{
    padding: 14px 18px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }}

  .card-title {{
    font-weight: 600;
    font-size: 13px;
    display: flex;
    align-items: center;
    gap: 8px;
  }}

  .card-body {{ padding: 18px; }}

  /* ── Language selector ── */
  .lang-grid {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 6px;
    margin-bottom: 16px;
  }}

  .lang-btn {{
    padding: 8px 4px;
    border-radius: 6px;
    border: 1px solid var(--border);
    background: var(--bg3);
    color: var(--text2);
    cursor: pointer;
    font-size: 11px;
    font-weight: 500;
    text-align: center;
    transition: all 0.15s;
  }}

  .lang-btn:hover {{ border-color: var(--teal); color: var(--teal); }}
  .lang-btn.active {{
    background: #0d2e24;
    border-color: var(--teal);
    color: var(--teal);
  }}

  /* ── Input area ── */
  .input-row {{
    display: flex;
    gap: 8px;
    margin-bottom: 10px;
  }}

  select {{
    flex: 1;
    padding: 8px 12px;
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text);
    font-size: 13px;
    cursor: pointer;
  }}

  textarea {{
    width: 100%;
    min-height: 120px;
    padding: 12px;
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text);
    font-size: 13px;
    resize: vertical;
    font-family: inherit;
    transition: border-color 0.15s;
  }}

  textarea:focus, select:focus {{
    outline: none;
    border-color: var(--teal);
  }}

  .btn {{
    padding: 10px 20px;
    border-radius: var(--radius);
    border: none;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s;
    font-family: inherit;
  }}

  .btn-scan {{
    background: var(--teal);
    color: #0d1117;
    width: 100%;
    margin-top: 12px;
    font-size: 14px;
    padding: 12px;
  }}

  .btn-scan:hover {{ background: #5ae8b8; transform: translateY(-1px); }}
  .btn-scan:active {{ transform: translateY(0); }}
  .btn-scan:disabled {{ opacity: 0.5; cursor: not-allowed; transform: none; }}

  .btn-clear {{
    background: var(--bg3);
    color: var(--text2);
    border: 1px solid var(--border);
    padding: 6px 12px;
    font-size: 12px;
  }}

  /* ── Result panel ── */
  #result-panel {{ display: none; }}

  .verdict-banner {{
    border-radius: var(--radius);
    padding: 16px;
    margin-bottom: 16px;
    display: flex;
    align-items: flex-start;
    gap: 12px;
  }}

  .verdict-SCAM      {{ background: var(--red-bg);   border: 1px solid #f8514944; }}
  .verdict-SUSPICIOUS{{ background: var(--amber-bg); border: 1px solid #d2992244; }}
  .verdict-CAUTION   {{ background: #1e1a0d;         border: 1px solid #d2992222; }}
  .verdict-SAFE      {{ background: var(--green-bg); border: 1px solid #3fb95044; }}

  .verdict-icon {{
    font-size: 28px;
    line-height: 1;
    flex-shrink: 0;
  }}

  .verdict-title {{
    font-weight: 700;
    font-size: 16px;
    margin-bottom: 4px;
  }}

  .verdict-SCAM .verdict-title      {{ color: var(--red); }}
  .verdict-SUSPICIOUS .verdict-title{{ color: var(--amber); }}
  .verdict-CAUTION .verdict-title   {{ color: #f5c56a; }}
  .verdict-SAFE .verdict-title      {{ color: var(--green); }}

  .verdict-summary {{ font-size: 13px; color: var(--text2); line-height: 1.5; }}

  /* ── Risk meter ── */
  .risk-meter {{
    margin: 14px 0;
  }}

  .risk-label {{
    display: flex;
    justify-content: space-between;
    font-size: 12px;
    color: var(--text2);
    margin-bottom: 6px;
  }}

  .risk-bar {{
    height: 6px;
    background: var(--bg3);
    border-radius: 3px;
    overflow: hidden;
  }}

  .risk-fill {{
    height: 100%;
    border-radius: 3px;
    transition: width 0.6s ease;
  }}

  /* ── Warning steps ── */
  .steps-list {{
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin: 12px 0;
  }}

  .steps-list li {{
    font-size: 13px;
    padding: 8px 10px;
    background: var(--bg3);
    border-radius: 6px;
    border-left: 3px solid transparent;
    line-height: 1.5;
  }}

  .steps-list li.action-no   {{ border-color: var(--red); }}
  .steps-list li.action-yes  {{ border-color: var(--green); }}
  .steps-list li.action-warn {{ border-color: var(--amber); }}
  .steps-list li.action-info {{ border-color: var(--blue); }}

  /* ── Learn section ── */
  .learn-box {{
    background: var(--blue-bg);
    border: 1px solid #58a6ff22;
    border-radius: var(--radius);
    padding: 12px;
    margin-top: 14px;
  }}

  .learn-label {{
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--blue);
    margin-bottom: 6px;
  }}

  .learn-text {{
    font-size: 13px;
    color: var(--text2);
    line-height: 1.6;
  }}

  /* ── Threat badges ── */
  .threat-badges {{
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin: 10px 0;
  }}

  .badge {{
    padding: 3px 10px;
    border-radius: 99px;
    font-size: 11px;
    font-weight: 500;
  }}

  .badge-red    {{ background: #2d1117; color: var(--red);   border: 1px solid #f8514933; }}
  .badge-amber  {{ background: #272115; color: var(--amber); border: 1px solid #d2992233; }}
  .badge-blue   {{ background: #0c1f3a; color: var(--blue);  border: 1px solid #58a6ff33; }}
  .badge-green  {{ background: #0d2014; color: var(--green); border: 1px solid #3fb95033; }}

  /* ── URL list ── */
  .url-item {{
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 12px;
    margin-top: 8px;
  }}

  .url-text {{
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 11px;
    color: var(--text2);
    word-break: break-all;
    margin-bottom: 4px;
  }}

  .url-risk-high {{ border-left: 3px solid var(--red); }}
  .url-risk-med  {{ border-left: 3px solid var(--amber); }}
  .url-risk-low  {{ border-left: 3px solid var(--green); }}

  /* ── Stats sidebar ── */
  .sidebar {{ display: flex; flex-direction: column; gap: 16px; }}

  .stat-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
  }}

  .stat-cell {{
    background: var(--bg3);
    border-radius: var(--radius);
    padding: 12px;
    text-align: center;
  }}

  .stat-num {{
    font-size: 24px;
    font-weight: 700;
    line-height: 1.1;
  }}

  .stat-label {{
    font-size: 11px;
    color: var(--text2);
    margin-top: 2px;
  }}

  /* ── History ── */
  .history-item {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 0;
    border-bottom: 1px solid var(--border);
    font-size: 12px;
  }}

  .history-item:last-child {{ border-bottom: none; }}

  .h-verdict {{
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 600;
    flex-shrink: 0;
  }}

  .h-SCAM       {{ background: var(--red-bg);   color: var(--red); }}
  .h-SUSPICIOUS {{ background: var(--amber-bg); color: var(--amber); }}
  .h-CAUTION    {{ background: #272115;          color: #f5c56a; }}
  .h-SAFE       {{ background: var(--green-bg);  color: var(--green); }}

  .h-text {{ color: var(--text2); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .h-score {{ color: var(--text2); flex-shrink: 0; }}

  /* ── Category tips ── */
  .tips-list {{ display: flex; flex-direction: column; gap: 6px; }}

  .tip-item {{
    background: var(--bg3);
    border-radius: 6px;
    padding: 10px;
    font-size: 12px;
    cursor: pointer;
    transition: background 0.1s;
    border-left: 3px solid var(--teal);
  }}

  .tip-item:hover {{ background: #1c2330; }}
  .tip-title {{ font-weight: 600; margin-bottom: 2px; }}
  .tip-desc  {{ color: var(--text2); line-height: 1.4; }}

  /* ── Loading spinner ── */
  .spinner {{
    display: inline-block;
    width: 14px; height: 14px;
    border: 2px solid transparent;
    border-top-color: #0d1117;
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
    vertical-align: middle;
  }}

  @keyframes spin {{ to {{ transform: rotate(360deg); }} }}

  /* ── Category explanation ── */
  .cat-explain {{
    background: #1e1a0d;
    border: 1px solid #d2992222;
    border-radius: var(--radius);
    padding: 12px;
    margin-top: 10px;
    font-size: 12px;
    color: var(--text2);
    line-height: 1.6;
  }}

  .cat-explain-title {{ font-weight: 600; color: var(--amber); margin-bottom: 4px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; }}

  /* ── Tabs ── */
  .tab-row {{
    display: flex;
    border-bottom: 1px solid var(--border);
    padding: 0 18px;
  }}

  .tab {{
    padding: 10px 14px;
    font-size: 12px;
    font-weight: 500;
    color: var(--text2);
    cursor: pointer;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
    transition: all 0.15s;
    background: none;
    border-top: none;
    border-left: none;
    border-right: none;
    font-family: inherit;
  }}

  .tab.active {{ color: var(--teal); border-bottom-color: var(--teal); }}
  .tab:hover:not(.active) {{ color: var(--text); }}

  .tab-panel {{ display: none; padding: 18px; }}
  .tab-panel.active {{ display: block; }}

  /* ── Footer ── */
  footer {{
    text-align: center;
    padding: 20px;
    color: var(--text2);
    font-size: 12px;
    border-top: 1px solid var(--border);
    margin-top: 20px;
  }}

  @media (max-width: 760px) {{
    .container {{ grid-template-columns: 1fr; }}
    .sidebar {{ order: -1; }}
    .lang-grid {{ grid-template-columns: repeat(3, 1fr); }}
  }}
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">🛡️</div>
    Cyber-<span>Shield</span>
  </div>
  <div class="header-right">
    <span class="status-dot"></span>
    Engine Active
    <span>v1.0 MVP</span>
  </div>
</header>

<div class="container">

  <!-- ── MAIN PANEL ── -->
  <main>

    <!-- Scanner Card -->
    <div class="card" style="margin-bottom: 20px;">
      <div class="card-header">
        <div class="card-title">
          🔍 Scan a Message
        </div>
        <button class="btn btn-clear" onclick="clearAll()">Clear</button>
      </div>
      <div class="card-body">

        <!-- Language selector -->
        <div style="margin-bottom: 12px;">
          <div style="font-size: 11px; color: var(--text2); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; font-weight: 500;">⚙️ Alert Language</div>
          <div class="lang-grid" id="lang-grid">
            <button class="lang-btn active" data-lang="pidgin" onclick="selectLang(this)">🇳🇬<br>Pidgin</button>
            <button class="lang-btn" data-lang="yoruba" onclick="selectLang(this)">🟢<br>Yorùbá</button>
            <button class="lang-btn" data-lang="hausa" onclick="selectLang(this)">🟡<br>Hausa</button>
            <button class="lang-btn" data-lang="igbo" onclick="selectLang(this)">🔵<br>Igbo</button>
            <button class="lang-btn" data-lang="english" onclick="selectLang(this)">🇬🇧<br>English</button>
          </div>
        </div>

        <!-- Demo picker -->
        <div class="input-row">
          <select id="demo-select" onchange="loadDemo(this.value)">
            <option value="">— Load a demo message —</option>
            {demo_options}
          </select>
        </div>

        <!-- Text input -->
        <textarea id="msg-input" placeholder="Paste or type an SMS, WhatsApp message, or any suspicious text here…"></textarea>

        <button class="btn btn-scan" id="scan-btn" onclick="doScan()">
          🛡️ Scan Message
        </button>
      </div>
    </div>

    <!-- Result Panel -->
    <div class="card" id="result-panel">
      <div class="tab-row">
        <button class="tab active" onclick="showTab(this, 'tab-verdict')">Verdict</button>
        <button class="tab" onclick="showTab(this, 'tab-actions')">What To Do</button>
        <button class="tab" onclick="showTab(this, 'tab-technical')">Technical</button>
        <button class="tab" onclick="showTab(this, 'tab-learn')">Learn</button>
      </div>

      <!-- Verdict Tab -->
      <div class="tab-panel active" id="tab-verdict">
        <div id="verdict-banner"></div>
        <div id="risk-meter-container"></div>
        <div id="threat-badges"></div>
        <div id="cat-explanation"></div>
      </div>

      <!-- Actions Tab -->
      <div class="tab-panel" id="tab-actions">
        <div style="font-size: 13px; color: var(--text2); margin-bottom: 10px;" id="actions-header"></div>
        <ul class="steps-list" id="steps-list"></ul>
      </div>

      <!-- Technical Tab -->
      <div class="tab-panel" id="tab-technical">
        <div id="tech-content"></div>
      </div>

      <!-- Learn Tab -->
      <div class="tab-panel" id="tab-learn">
        <div class="learn-box" id="learn-content"></div>
      </div>
    </div>

  </main>

  <!-- ── SIDEBAR ── -->
  <aside class="sidebar">

    <!-- Stats -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">📊 Session Stats</div>
      </div>
      <div class="card-body" style="padding: 14px;">
        <div class="stat-grid" id="stat-grid">
          <div class="stat-cell"><div class="stat-num" id="stat-total" style="color: var(--text)">0</div><div class="stat-label">Total Scans</div></div>
          <div class="stat-cell"><div class="stat-num" id="stat-scams" style="color: var(--red)">0</div><div class="stat-label">Scams Found</div></div>
          <div class="stat-cell"><div class="stat-num" id="stat-suspicious" style="color: var(--amber)">0</div><div class="stat-label">Suspicious</div></div>
          <div class="stat-cell"><div class="stat-num" id="stat-safe" style="color: var(--green)">0</div><div class="stat-label">Safe</div></div>
        </div>
      </div>
    </div>

    <!-- History -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">🕐 Recent Scans</div>
        <button class="btn btn-clear" onclick="clearHistory()" style="font-size:11px; padding:4px 8px;">Clear</button>
      </div>
      <div class="card-body" style="padding: 0 16px;" id="history-list">
        <div style="padding: 16px 0; color: var(--text2); font-size: 12px; text-align: center;">No scans yet</div>
      </div>
    </div>

    <!-- Security Tips -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">💡 Security Tips</div>
      </div>
      <div class="card-body" style="padding: 14px;">
        <div class="tips-list">
          <div class="tip-item">
            <div class="tip-title">Never share your OTP</div>
            <div class="tip-desc">Banks will NEVER ask for your one-time password via SMS or call</div>
          </div>
          <div class="tip-item">
            <div class="tip-title">Verify domain names</div>
            <div class="tip-desc">Real Nigerian banks use .com.ng or .com — not .tk, .ml, or .xyz</div>
          </div>
          <div class="tip-item">
            <div class="tip-title">Urgency = Red flag</div>
            <div class="tip-desc">Real organisations give you time. Pressure to act NOW is a scam tactic</div>
          </div>
          <div class="tip-item">
            <div class="tip-title">Call to verify</div>
            <div class="tip-desc">Call your bank on the number printed on your card — not numbers in SMS</div>
          </div>
        </div>
      </div>
    </div>

  </aside>
</div>

<footer>
  Cyber-Shield MVP | Built for Nigeria's Digital Inclusion &nbsp;·&nbsp;
  Report scams: <strong>efccnigeria.org</strong> &nbsp;·&nbsp; 
  CBN Consumer Protection: <strong>01-2798330</strong>
</footer>

<script>
{js_code}
</script>
</body>
</html>"""


# ── HTTP Request Handler ──────────────────────────────────────────────────

class CyberShieldHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        # Suppress default request logs — use our own
        pass

    def send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html: str):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            demo_json_str = json.dumps(DEMO_MESSAGES, ensure_ascii=False)
            html = build_html(demo_json_str)
            self.send_html(html)

        elif path == "/api/stats":
            self.send_json(stats.summary())

        elif path == "/api/languages":
            self.send_json(get_available_languages())

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len else b"{}"

        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            self.send_json({"error": "Invalid JSON"}, 400)
            return

        if path == "/api/scan":
            text = payload.get("text", "").strip()
            language = payload.get("language", "english")

            if not text:
                self.send_json({"error": "No text provided"}, 400)
                return

            # Run threat analysis
            result = scan_message(text)
            stats.record(result)
            scan_history.append(result)

            # Get localised warning
            warning = get_warning(
                verdict=result["verdict"],
                language=language,
                category=result.get("primary_category"),
            )

            print(f"[{datetime.now().strftime('%H:%M:%S')}] SCAN | "
                  f"Verdict: {result['verdict']:10s} | "
                  f"Risk: {result['risk_score']:3d} | "
                  f"Lang: {language}")

            self.send_json({
                "result": result,
                "warning": warning,
                "stats": stats.summary(),
            })

        elif path == "/api/reset":
            stats.scans.clear()
            stats.category_counts.clear()
            scan_history.clear()
            self.send_json({"ok": True})

        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


# ── Entry point ────────────────────────────────────────────────────────────

def main():
    PORT = 8888
    HOST = "localhost"

    print("=" * 58)
    print("   🛡️  CYBER-SHIELD — AI Scam Detector")
    print("   Digital Inclusion for Nigeria")
    print("=" * 58)
    print(f"   Server starting on http://{HOST}:{PORT}")
    print(f"   Languages: Pidgin | Yorùbá | Hausa | Igbo | English")
    print(f"   Press Ctrl+C to stop")
    print("=" * 58)

    server = HTTPServer((HOST, PORT), CyberShieldHandler)

    # Auto-open browser after short delay
    def open_browser():
        import time
        time.sleep(1.2)
        webbrowser.open(f"http://{HOST}:{PORT}")

    threading.Thread(target=open_browser, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Cyber-Shield] Server stopped. Stay safe! 🛡️")
        server.server_close()


if __name__ == "__main__":
    main()
