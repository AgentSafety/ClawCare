"""Dashboard — generate a self-contained HTML report combining scan + guard data."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import clawcare
from clawcare.config import DEFAULT_LOG_PATH

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def _load_scan_json(path: str | Path | None) -> dict[str, Any] | None:
    """Load a scan JSON report file."""
    if path is None:
        return None
    p = Path(path)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _load_guard_events(
    log_path: str | Path | None = None,
    max_events: int = 500,
) -> list[dict[str, Any]]:
    """Load guard audit events from JSONL log."""
    dest = Path(log_path).expanduser() if log_path else DEFAULT_LOG_PATH
    if not dest.is_file():
        return []
    events: list[dict[str, Any]] = []
    try:
        with open(dest, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    # Return newest first, capped
    events.reverse()
    return events[:max_events]


# ---------------------------------------------------------------------------
# HTML generation helpers
# ---------------------------------------------------------------------------

_e = html.escape

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _sev_class(sev: str) -> str:
    return f"sev-{sev.lower()}"


def _status_badge(status: str) -> str:
    css = f"badge-{status}"
    return f'<span class="badge {css}">{_e(status)}</span>'


def _severity_cards(counts: dict[str, int]) -> str:
    cards = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        n = counts.get(sev.lower(), counts.get(sev, 0))
        cards.append(
            f'<div class="card"><div class="value {_sev_class(sev)}">{n}</div>'
            f'<div class="label">{sev}</div></div>'
        )
    total = sum(counts.get(k, 0) for k in ("critical", "high", "medium", "low", "CRITICAL", "HIGH", "MEDIUM", "LOW"))
    cards.insert(
        0,
        f'<div class="card"><div class="value">{total}</div>'
        f'<div class="label">Total</div></div>',
    )
    return f'<div class="cards">{"".join(cards)}</div>'


def _time_filter_html(filter_id: str, onchange: str) -> str:
    return (
        f'<div class="filter-bar">'
        f'<label>Time range:</label>'
        f'<select id="{filter_id}-preset" onchange="{onchange}()">'
        f'<option value="24" selected>Past 24 hours</option>'
        f'<option value="72">Past 3 days</option>'
        f'<option value="168">Past 7 days</option>'
        f'<option value="720">Past 30 days</option>'
        f'<option value="0">All time</option>'
        f'<option value="custom">Custom range</option>'
        f'</select>'
        f'<span id="{filter_id}-custom" class="custom-range" style="display:none">'
        f'<input type="datetime-local" id="{filter_id}-from" onchange="{onchange}()">'
        f'<span style="color:#8b949e;margin:0 4px">to</span>'
        f'<input type="datetime-local" id="{filter_id}-to" onchange="{onchange}()">'
        f'</span>'
        f'</div>'
    )


def _scan_section(scan: dict[str, Any] | None) -> str:
    if scan is None:
        return '<div id="tab-scan" class="tab-panel active"><div class="empty">No scan data. Run: clawcare scan &lt;path&gt; --format json --json-out scan.json</div></div>'

    parts: list[str] = ['<div id="tab-scan" class="tab-panel active">']

    # Metadata
    run_id = _e(scan.get("run_id", "-"))
    scanned = _e(scan.get("scanned_path", "-"))
    adapter = _e(scan.get("adapter_used", {}).get("name", "-"))
    mode = _e(scan.get("summary", {}).get("mode", "-"))
    fail_on = _e(scan.get("summary", {}).get("fail_on", "-"))
    scan_ts = _e(scan.get("timestamp", "-"))
    parts.append(
        f'<p style="font-size:0.82rem;color:#8b949e;margin-bottom:4px;">'
        f'Run ID: <code>{run_id}</code> &middot; Path: <code>{scanned}</code> '
        f'&middot; Adapter: {adapter} &middot; Mode: {mode} &middot; Fail on: {fail_on}</p>'
    )
    parts.append(
        f'<div class="scan-time">'
        f'<span class="scan-time-label">Last scanned</span>'
        f'<span class="scan-time-value utc-ts" data-utc="{scan_ts}">{scan_ts}</span>'
        f'</div>'
    )

    # Severity cards
    summary = scan.get("summary", {})
    parts.append(_severity_cards(summary))

    # Findings table (sortable columns, click for modal)
    findings = scan.get("findings", []) + scan.get("manifest_violations", [])
    # Pre-sort: severity then timestamp (scan timestamp used for all)
    findings.sort(key=lambda f: _SEV_ORDER.get(f.get("severity", ""), 99))

    if findings:
        parts.append(
            '<table id="scan-table"><thead><tr>'
            '<th class="sortable" data-col="0" data-type="sev">Severity</th>'
            '<th class="sortable" data-col="1" data-type="str">Rule</th>'
            '<th class="sortable" data-col="2" data-type="str">File</th>'
            '<th class="sortable" data-col="3" data-type="num">Line</th>'
            '<th class="sortable" data-col="4" data-type="str">Excerpt</th>'
            '</tr></thead><tbody>'
        )
        for f in findings:
            sev = f.get("severity", "")
            detail_json = _e(json.dumps(f, ensure_ascii=False))
            parts.append(
                f'<tr class="clickable-row" data-detail="{detail_json}">'
                f'<td class="{_sev_class(sev)}">{_e(sev)}</td>'
                f'<td>{_e(f.get("rule_id", ""))}</td>'
                f'<td class="truncate">{_e(f.get("file", ""))}</td>'
                f'<td>{f.get("line", "")}</td>'
                f'<td class="truncate">{_e(f.get("excerpt", ""))}</td>'
                f'</tr>'
            )
        parts.append("</tbody></table>")
        parts.append('<div id="scan-pager" class="pager"></div>')
    else:
        parts.append('<div class="empty">✅ No findings.</div>')

    parts.append("</div>")
    return "\n".join(parts)


def _guard_section(events: list[dict[str, Any]]) -> str:
    parts: list[str] = ['<div id="tab-guard" class="tab-panel">']

    if not events:
        parts.append('<div class="empty">No guard events. Activate guard: clawcare guard activate --platform claude</div></div>')
        return "\n".join(parts)

    # Status summary cards
    status_counts: dict[str, int] = {}
    for ev in events:
        s = ev.get("status", "unknown")
        status_counts[s] = status_counts.get(s, 0) + 1

    cards = [f'<div class="card"><div class="value">{len(events)}</div><div class="label">Total Events</div></div>']
    for status in ("blocked", "warned", "allowed", "executed", "failed"):
        n = status_counts.get(status, 0)
        if n > 0:
            cards.append(
                f'<div class="card"><div class="value">{n}</div>'
                f'<div class="label">{_status_badge(status)}</div></div>'
            )
    parts.append(f'<div id="guard-summary-cards"><div class="cards">{"".join(cards)}</div></div>')

    # Hourly activity chart (last 24h)
    now = datetime.now(timezone.utc)
    hourly: dict[int, dict[str, int]] = {}
    for ev in events:
        ts_str = ev.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            continue
        diff_hours = (now - ts).total_seconds() / 3600
        if diff_hours <= 24:
            hour = int(diff_hours)
            bucket = hourly.setdefault(hour, {"blocked": 0, "warned": 0, "allowed": 0, "executed": 0, "failed": 0})
            s = ev.get("status", "allowed")
            if s in bucket:
                bucket[s] += 1

    parts.append('<div id="guard-chart">')
    if hourly:
        max_val = max(sum(v.values()) for v in hourly.values()) or 1
        parts.append('<h2 style="border:none;margin-top:8px;">Activity</h2>')
        parts.append('<div class="bar-chart">')
        for h in range(23, -1, -1):
            bucket = hourly.get(h, {})
            total = sum(bucket.values())
            height = max(4, int(70 * total / max_val)) if total else 4
            color = "#f85149" if bucket.get("blocked", 0) else ("#d29922" if bucket.get("warned", 0) else "#3fb950")
            label = f"{h}h ago: {total} events"
            parts.append(f'<div class="bar" style="height:{height}px;background:{color};" data-tip="{label}"></div>')
        parts.append("</div>")
    parts.append('</div>')

    # Time range filter
    parts.append(_time_filter_html("guard-filter", "filterGuardByTime"))

    # Pre-sort events: severity asc then timestamp desc
    def _guard_sort_key(ev: dict[str, Any]) -> tuple[int, list[int]]:
        findings = ev.get("findings", [])
        min_sev = 99
        for f in findings:
            if isinstance(f, dict):
                s = _SEV_ORDER.get(f.get("severity", ""), 99)
                if s < min_sev:
                    min_sev = s
        # Negate each char's ordinal so lexicographic ascending = timestamp descending
        ts = ev.get("timestamp", "")
        return (min_sev, [-ord(c) for c in ts])

    events_sorted = sorted(events, key=_guard_sort_key)

    # Events table
    parts.append(
        '<table id="guard-table"><thead><tr>'
        '<th class="sortable" data-col="0" data-type="ts">Time</th>'
        '<th class="sortable" data-col="1" data-type="str">Run ID</th>'
        '<th class="sortable" data-col="2" data-type="str">Platform</th>'
        '<th class="sortable" data-col="3" data-type="str">Status</th>'
        '<th class="sortable" data-col="4" data-type="sev">Severity</th>'
        '<th class="sortable" data-col="5" data-type="str">Command</th>'
        '<th class="sortable" data-col="6" data-type="str">Findings</th>'
        '</tr></thead><tbody>'
    )
    for ev in events_sorted:
        ts_raw = ev.get("timestamp", "-")
        ts = _e(ts_raw)
        run_id = _e(ev.get("run_id", "-"))
        platform = _e(ev.get("platform", "-"))
        status = ev.get("status", "-")
        cmd = _e(ev.get("command", ""))
        findings = ev.get("findings", [])
        finding_text_parts: list[str] = []
        for f in findings:
            if isinstance(f, dict):
                sev = f.get("severity", "")
                rid = f.get("rule_id", "")
                finding_text_parts.append(f'<span class="{_sev_class(sev)}">{_e(rid)}</span>')
            else:
                finding_text_parts.append(_e(str(f)))
        finding_html = ", ".join(finding_text_parts) if finding_text_parts else '<span style="color:#484f58">\u2014</span>'

        # Compute highest severity from findings
        max_sev = ""
        for f in findings:
            if isinstance(f, dict):
                s = f.get("severity", "")
                sn = _SEV_ORDER.get(s, 99)
                if not max_sev or sn < _SEV_ORDER.get(max_sev, 99):
                    max_sev = s

        detail_json = _e(json.dumps(ev, ensure_ascii=False))
        parts.append(
            f'<tr class="clickable-row" data-ts="{_e(ts_raw)}" data-status="{_e(status)}"'
            f' data-detail="{detail_json}">'
            f'<td class="utc-ts" data-utc="{_e(ts_raw)}" style="white-space:nowrap;font-size:0.78rem">{ts}</td>'
            f'<td><code style="font-size:0.75rem">{run_id}</code></td>'
            f"<td>{platform}</td>"
            f"<td>{_status_badge(status)}</td>"
            f'<td class="{_sev_class(max_sev)}">{_e(max_sev) if max_sev else "—"}</td>'
            f'<td class="truncate">{cmd}</td>'
            f"<td>{finding_html}</td></tr>"
        )
    parts.append("</tbody></table>")
    parts.append('<div id="guard-pager" class="pager"></div>')

    parts.append("</div>")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """\
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       background: #0d1117; color: #c9d1d9; line-height: 1.5; padding: 24px; }
h1 { color: #58a6ff; margin-bottom: 4px; font-size: 1.6rem; }
h2 { color: #8b949e; margin: 28px 0 12px; font-size: 1.15rem; border-bottom: 1px solid #21262d; padding-bottom: 6px; }
.subtitle { color: #8b949e; font-size: 0.85rem; margin-bottom: 20px; }
/* Tabs */
.tab-bar { display: flex; gap: 0; margin-bottom: 0; border-bottom: 2px solid #21262d; }
.tab-btn { background: none; border: none; color: #8b949e; padding: 10px 20px; font-size: 0.9rem;
           cursor: pointer; border-bottom: 2px solid transparent; margin-bottom: -2px; font-weight: 600; }
.tab-btn:hover { color: #c9d1d9; }
.tab-btn.active { color: #58a6ff; border-bottom-color: #58a6ff; }
.tab-panel { display: none; padding-top: 20px; }
.tab-panel.active { display: block; }
/* Cards */
.cards { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; }
.card { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 16px 20px;
        min-width: 130px; text-align: center; }
.card .value { font-size: 2rem; font-weight: 700; }
.card .label { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px; }
.sev-critical { color: #f85149; }
.sev-high { color: #d29922; }
.sev-medium { color: #58a6ff; }
.sev-low { color: #8b949e; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.7rem;
         font-weight: 600; text-transform: uppercase; }
.badge-blocked { background: #f8514933; color: #f85149; }
.badge-warned { background: #d2992233; color: #d29922; }
.badge-allowed { background: #3fb95033; color: #3fb950; }
.badge-executed { background: #8b949e22; color: #8b949e; }
.badge-failed { background: #f8514922; color: #da3633; }
/* Tables */
table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px;
        overflow: hidden; margin-bottom: 8px; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #21262d; font-size: 0.85rem; }
th { background: #1c2128; color: #8b949e; font-weight: 600; text-transform: uppercase;
     font-size: 0.72rem; letter-spacing: 0.5px; }
th.sortable { cursor: pointer; user-select: none; }
th.sortable:hover { color: #c9d1d9; }
th.sortable::after { content: ' ⇅'; font-size: 0.65rem; opacity: 0.5; }
th.sort-asc::after { content: ' ↑'; opacity: 1; }
th.sort-desc::after { content: ' ↓'; opacity: 1; }
tr:hover { background: #1c2128; }
tr.clickable-row { cursor: pointer; }
tr.clickable-row:hover { background: #1f2937; }
/* Bar chart */
.bar-chart { display: flex; gap: 3px; align-items: flex-end; height: 80px; margin: 12px 0; }
.bar { min-width: 18px; border-radius: 3px 3px 0 0; position: relative; cursor: default; }
.bar:hover::after { content: attr(data-tip); position: absolute; bottom: 100%; left: 50%;
                    transform: translateX(-50%); background: #30363d; padding: 2px 8px;
                    border-radius: 4px; font-size: 0.7rem; white-space: nowrap; }
/* Pagination */
.pager { display: flex; align-items: center; gap: 6px; margin: 8px 0 20px; font-size: 0.82rem; }
.pager button { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 4px 12px;
                border-radius: 6px; cursor: pointer; font-size: 0.78rem; }
.pager button:hover:not(:disabled) { background: #30363d; }
.pager button:disabled { opacity: 0.4; cursor: default; }
.pager .page-info { color: #8b949e; }
/* Filter bar */
.filter-bar { display: flex; align-items: center; gap: 10px; margin: 12px 0; flex-wrap: wrap; }
.filter-bar label { color: #8b949e; font-size: 0.82rem; }
.filter-bar select, .filter-bar input { background: #161b22; border: 1px solid #30363d; color: #c9d1d9;
                     padding: 5px 10px; border-radius: 6px; font-size: 0.82rem; }
.custom-range input { background: #161b22; border: 1px solid #30363d; color: #c9d1d9;
                      padding: 5px 8px; border-radius: 6px; font-size: 0.82rem; }
/* Modal */
.modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                 background: rgba(0,0,0,0.7); z-index: 1000; justify-content: center; align-items: center; }
.modal-overlay.open { display: flex; }
.modal { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 24px;
         max-width: 700px; width: 90%; max-height: 80vh; overflow-y: auto; position: relative; }
.modal h3 { color: #58a6ff; margin-bottom: 16px; font-size: 1.1rem; }
.modal-close { position: absolute; top: 12px; right: 16px; background: none; border: none;
               color: #8b949e; font-size: 1.4rem; cursor: pointer; }
.modal-close:hover { color: #c9d1d9; }
.detail-grid { display: grid; grid-template-columns: 120px 1fr; gap: 8px 12px; font-size: 0.85rem; }
.detail-grid .detail-label { color: #8b949e; font-weight: 600; text-transform: uppercase; font-size: 0.72rem; }
.detail-grid .detail-value { color: #c9d1d9; word-break: break-word; }
.detail-grid .detail-value code { background: #0d1117; padding: 2px 6px; border-radius: 4px; font-size: 0.82rem; }
.detail-grid .detail-value pre { background: #0d1117; padding: 10px; border-radius: 6px;
                                  font-size: 0.78rem; overflow-x: auto; white-space: pre-wrap;
                                  margin-top: 4px; }
/* Misc */
.empty { text-align: center; padding: 32px; color: #484f58; }
.truncate { max-width: 340px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
/* Scan time highlight */
.scan-time { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
             padding: 12px 16px; margin-bottom: 16px; display: inline-block; }
.scan-time-label { color: #8b949e; font-size: 0.78rem; text-transform: uppercase;
                   letter-spacing: 0.5px; display: block; margin-bottom: 2px; }
.scan-time-value { color: #58a6ff; font-size: 1.1rem; font-weight: 600; }
/* Timezone toggle */
.tz-toggle { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 5px 14px;
             border-radius: 6px; cursor: pointer; font-size: 0.78rem; margin-bottom: 12px; }
.tz-toggle:hover { background: #30363d; }
.footer { margin-top: 40px; color: #484f58; font-size: 0.75rem; text-align: center; }
"""

# ---------------------------------------------------------------------------
# JavaScript (tabs, pagination, time filter, sorting, modal)
# ---------------------------------------------------------------------------

_JS = """\
(function() {
  var PAGE_SIZE = 25;
  var SEV_ORDER = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3};

  /* ── Tabs ─────────────────────────────────────── */
  document.querySelectorAll('.tab-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
      document.querySelectorAll('.tab-panel').forEach(function(p) { p.classList.remove('active'); });
      btn.classList.add('active');
      document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    });
  });

  /* ── Pagination ───────────────────────────────── */
  var pageState = {};
  function paginate(tableId, pagerId, rows, page) {
    if (!rows || rows.length === 0) {
      var pager = document.getElementById(pagerId);
      if (pager) pager.innerHTML = '<span class="page-info">0 rows</span>';
      return;
    }
    var totalPages = Math.ceil(rows.length / PAGE_SIZE);
    if (page < 1) page = 1;
    if (page > totalPages) page = totalPages;
    pageState[tableId] = page;
    var start = (page - 1) * PAGE_SIZE;
    var end = start + PAGE_SIZE;
    rows.forEach(function(r, i) {
      r.style.display = (i >= start && i < end) ? '' : 'none';
    });
    var pager = document.getElementById(pagerId);
    if (!pager) return;
    pager.innerHTML =
      '<button ' + (page <= 1 ? 'disabled' : '') +
      ' onclick="window._pageTo(\\'' + tableId + '\\',\\'' + pagerId + '\\',' + (page-1) + ')">\\u2190 Prev</button>' +
      '<span class="page-info">Page ' + page + ' of ' + totalPages + ' (' + rows.length + ' rows)</span>' +
      '<button ' + (page >= totalPages ? 'disabled' : '') +
      ' onclick="window._pageTo(\\'' + tableId + '\\',\\'' + pagerId + '\\',' + (page+1) + ')">Next \\u2192</button>';
  }

  function getVisibleRows(tableId) {
    var tbody = document.querySelector('#' + tableId + ' tbody');
    if (!tbody) return [];
    return Array.from(tbody.querySelectorAll('tr')).filter(function(r) {
      return r.dataset._visible === '1';
    });
  }

  window._pageTo = function(tableId, pagerId, page) {
    paginate(tableId, pagerId, getVisibleRows(tableId), page);
  };

  /* ── Time filter (shared logic) ───────────────── */
  function applyTimeFilter(prefixId, tableId, pagerId) {
    var sel = document.getElementById(prefixId + '-preset');
    var customSpan = document.getElementById(prefixId + '-custom');
    var preset = sel ? sel.value : '24';

    if (preset === 'custom') {
      customSpan.style.display = '';
      var fromEl = document.getElementById(prefixId + '-from');
      var toEl = document.getElementById(prefixId + '-to');
      var fromMs = fromEl && fromEl.value ? new Date(fromEl.value).getTime() : 0;
      var toMs = toEl && toEl.value ? new Date(toEl.value).getTime() : Date.now() + 86400000;

      var tbody = document.querySelector('#' + tableId + ' tbody');
      if (!tbody) return;
      var rows = Array.from(tbody.querySelectorAll('tr'));
      rows.forEach(function(r) {
        var ts = r.getAttribute('data-ts');
        if (!ts || ts === '-') { r.dataset._visible = '0'; r.style.display = 'none'; return; }
        try {
          var d = new Date(ts);
          var t = d.getTime();
          r.dataset._visible = (t >= fromMs && t <= toMs) ? '1' : '0';
        } catch(e) { r.dataset._visible = '0'; }
      });
    } else {
      customSpan.style.display = 'none';
      var hours = parseInt(preset, 10);
      var tbody = document.querySelector('#' + tableId + ' tbody');
      if (!tbody) return;
      var now = Date.now();
      var rows = Array.from(tbody.querySelectorAll('tr'));
      rows.forEach(function(r) {
        if (hours === 0) {
          r.dataset._visible = '1';
        } else {
          var ts = r.getAttribute('data-ts');
          if (!ts || ts === '-') { r.dataset._visible = '0'; r.style.display = 'none'; return; }
          try {
            var d = new Date(ts);
            var diffH = (now - d.getTime()) / 3600000;
            r.dataset._visible = diffH <= hours ? '1' : '0';
          } catch(e) { r.dataset._visible = '0'; }
        }
      });
    }
    rows.forEach(function(r) { r.style.display = 'none'; });
    paginate(tableId, pagerId, getVisibleRows(tableId), 1);
  }

  window.filterGuardByTime = function() {
    applyTimeFilter('guard-filter', 'guard-table', 'guard-pager');
    updateGuardSummary();
  };

  /* ── Dynamic guard summary ─────────────────────── */
  function updateGuardSummary() {
    var visRows = getVisibleRows('guard-table');
    var statusCounts = {};
    var total = visRows.length;
    visRows.forEach(function(r) {
      var st = r.getAttribute('data-status') || 'unknown';
      statusCounts[st] = (statusCounts[st] || 0) + 1;
    });
    var cardsDiv = document.getElementById('guard-summary-cards');
    if (cardsDiv) {
      var html = '<div class="cards">';
      html += '<div class="card"><div class="value">' + total + '</div><div class="label">Total Events</div></div>';
      ['blocked','warned','allowed','executed','failed'].forEach(function(s) {
        var n = statusCounts[s] || 0;
        if (n > 0) {
          html += '<div class="card"><div class="value">' + n + '</div>'
                + '<div class="label"><span class="badge badge-' + s + '">' + s + '</span></div></div>';
        }
      });
      html += '</div>';
      cardsDiv.innerHTML = html;
    }
    var chartDiv = document.getElementById('guard-chart');
    if (chartDiv) {
      var now = Date.now();
      var hourly = {};
      visRows.forEach(function(r) {
        var ts = r.getAttribute('data-ts');
        if (!ts || ts === '-') return;
        try {
          var d = new Date(ts);
          var diffH = (now - d.getTime()) / 3600000;
          if (diffH >= 0 && diffH <= 24) {
            var hour = Math.floor(diffH);
            if (!hourly[hour]) hourly[hour] = {blocked:0,warned:0,allowed:0,executed:0,failed:0};
            var st = r.getAttribute('data-status') || 'allowed';
            if (hourly[hour][st] !== undefined) hourly[hour][st]++;
          }
        } catch(e) {}
      });
      var maxVal = 0;
      for (var h = 0; h < 24; h++) {
        if (hourly[h]) {
          var tot = 0; for (var k in hourly[h]) tot += hourly[h][k];
          if (tot > maxVal) maxVal = tot;
        }
      }
      if (maxVal === 0) maxVal = 1;
      var ch = '<h2 style="border:none;margin-top:8px;">Activity</h2><div class="bar-chart">';
      for (var h = 23; h >= 0; h--) {
        var bucket = hourly[h] || {};
        var btot = 0; for (var k in bucket) btot += bucket[k];
        var height = btot ? Math.max(4, Math.floor(70 * btot / maxVal)) : 4;
        var color = bucket.blocked ? '#f85149' : (bucket.warned ? '#d29922' : '#3fb950');
        ch += '<div class="bar" style="height:' + height + 'px;background:' + color + ';" data-tip="' + h + 'h ago: ' + btot + ' events"></div>';
      }
      ch += '</div>';
      chartDiv.innerHTML = ch;
    }
  }

  /* ── Column sorting ───────────────────────────── */
  document.querySelectorAll('th.sortable').forEach(function(th) {
    th.addEventListener('click', function() {
      var table = th.closest('table');
      var tbody = table.querySelector('tbody');
      if (!tbody) return;
      var col = parseInt(th.dataset.col, 10);
      var type = th.dataset.type || 'str';
      var isAsc = th.classList.contains('sort-asc');

      // Clear sort indicators for this table
      table.querySelectorAll('th.sortable').forEach(function(h) {
        h.classList.remove('sort-asc', 'sort-desc');
      });

      var dir = isAsc ? 'desc' : 'asc';
      th.classList.add('sort-' + dir);

      // Sort only visible rows
      var allRows = Array.from(tbody.querySelectorAll('tr'));
      var visible = allRows.filter(function(r) { return r.dataset._visible === '1'; });
      var hidden = allRows.filter(function(r) { return r.dataset._visible !== '1'; });

      visible.sort(function(a, b) {
        var aVal = a.children[col] ? a.children[col].textContent.trim() : '';
        var bVal = b.children[col] ? b.children[col].textContent.trim() : '';
        var cmp = 0;
        if (type === 'num') {
          cmp = (parseFloat(aVal) || 0) - (parseFloat(bVal) || 0);
        } else if (type === 'sev') {
          cmp = (SEV_ORDER[aVal] !== undefined ? SEV_ORDER[aVal] : 99) -
                (SEV_ORDER[bVal] !== undefined ? SEV_ORDER[bVal] : 99);
        } else if (type === 'ts') {
          var aT = aVal ? new Date(aVal).getTime() : 0;
          var bT = bVal ? new Date(bVal).getTime() : 0;
          cmp = aT - bT;
        } else {
          cmp = aVal.localeCompare(bVal);
        }
        return dir === 'asc' ? cmp : -cmp;
      });

      // Re-append sorted + hidden
      visible.forEach(function(r) { tbody.appendChild(r); });
      hidden.forEach(function(r) { tbody.appendChild(r); });

      // Re-paginate
      var tableId = table.id;
      var pagerId = tableId.replace('-table', '-pager');
      paginate(tableId, pagerId, visible, 1);
    });
  });

  /* ── Modal ────────────────────────────────────── */
  var overlay = document.getElementById('detail-modal');
  var modalBody = document.getElementById('detail-body');

  document.querySelectorAll('.clickable-row').forEach(function(row) {
    row.addEventListener('click', function() {
      var raw = row.getAttribute('data-detail');
      if (!raw) return;
      try {
        var data = JSON.parse(raw);
        var html = '';
        var keys = Object.keys(data);
        keys.forEach(function(k) {
          var v = data[k];
          var display;
          if (typeof v === 'object' && v !== null) {
            display = '<pre>' + escapeHtml(JSON.stringify(v, null, 2)) + '</pre>';
          } else {
            display = '<code>' + escapeHtml(String(v)) + '</code>';
          }
          html += '<div class="detail-label">' + escapeHtml(k) + '</div>'
                + '<div class="detail-value">' + display + '</div>';
        });
        modalBody.innerHTML = html;
        overlay.classList.add('open');
      } catch(e) {}
    });
  });

  document.getElementById('modal-close-btn').addEventListener('click', function() {
    overlay.classList.remove('open');
  });
  overlay.addEventListener('click', function(e) {
    if (e.target === overlay) overlay.classList.remove('open');
  });

  function escapeHtml(s) {
    var d = document.createElement('div');
    d.appendChild(document.createTextNode(s));
    return d.innerHTML;
  }

  /* ── Timezone toggle ───────────────────────────── */
  var showLocal = false;
  window.toggleTimezone = function() {
    showLocal = !showLocal;
    var btn = document.getElementById('tz-toggle');
    if (btn) btn.textContent = showLocal ? 'Show UTC' : 'Show Local Time';
    document.querySelectorAll('.utc-ts').forEach(function(el) {
      var utc = el.getAttribute('data-utc');
      if (!utc || utc === '-') return;
      if (showLocal) {
        try {
          var d = new Date(utc);
          var y = d.getFullYear();
          var mo = String(d.getMonth()+1).padStart(2,'0');
          var da = String(d.getDate()).padStart(2,'0');
          var hh = String(d.getHours()).padStart(2,'0');
          var mi = String(d.getMinutes()).padStart(2,'0');
          var ss = String(d.getSeconds()).padStart(2,'0');
          el.textContent = y+'-'+mo+'-'+da+'T'+hh+':'+mi+':'+ss;
        } catch(e) {}
      } else {
        el.textContent = utc;
      }
    });
  };

  /* ── Init ─────────────────────────────────────── */
  // Mark all rows visible initially, then apply default filters
  document.querySelectorAll('#scan-table tbody tr, #guard-table tbody tr').forEach(function(r) {
    r.dataset._visible = '1';
  });
  if (document.getElementById('scan-table')) {
    paginate('scan-table', 'scan-pager',
      Array.from(document.querySelectorAll('#scan-table tbody tr')), 1);
  }
  if (document.getElementById('guard-table')) {
    filterGuardByTime();
  }
})();
"""


def generate_dashboard(
    *,
    scan_json_path: str | Path | None = None,
    guard_log_path: str | Path | None = None,
    max_guard_events: int = 500,
) -> str:
    """Generate a self-contained HTML dashboard string."""
    scan_data = _load_scan_json(scan_json_path)
    guard_events = _load_guard_events(guard_log_path, max_events=max_guard_events)

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ClawCare Dashboard</title>
<style>{_CSS}</style>
</head>
<body>
<h1>🐾 ClawCare Dashboard</h1>
<div class="subtitle">v{clawcare.__version__} &middot; Generated <span class="utc-ts" data-utc="{_e(now_str)}">{_e(now_str)}</span></div>

<button id="tz-toggle" class="tz-toggle" onclick="window.toggleTimezone()">Show Local Time</button>

<div class="tab-bar">
  <button class="tab-btn active" data-tab="scan">Scan Results</button>
  <button class="tab-btn" data-tab="guard">Guard Audit</button>
</div>

{_scan_section(scan_data)}
{_guard_section(guard_events)}

<!-- Detail Modal -->
<div id="detail-modal" class="modal-overlay">
  <div class="modal">
    <button id="modal-close-btn" class="modal-close">&times;</button>
    <h3>Finding Details</h3>
    <div id="detail-body" class="detail-grid"></div>
  </div>
</div>

<div class="footer">
ClawCare v{clawcare.__version__} &middot; <a href="https://github.com/AgentSafety/ClawCare" style="color:#58a6ff">GitHub</a>
</div>
<script>{_JS}</script>
</body>
</html>"""
