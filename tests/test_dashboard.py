"""Tests for dashboard generation."""

import json

from click.testing import CliRunner

from clawcare.cli import main
from clawcare.dashboard import _load_guard_events, _load_scan_json, generate_dashboard


class TestLoadScanJson:
    def test_loads_valid_json(self, tmp_path):
        f = tmp_path / "scan.json"
        f.write_text(json.dumps({"tool": "clawcare", "findings": []}))
        result = _load_scan_json(f)
        assert result is not None
        assert result["tool"] == "clawcare"

    def test_returns_none_for_missing(self, tmp_path):
        assert _load_scan_json(tmp_path / "nope.json") is None

    def test_returns_none_for_none(self):
        assert _load_scan_json(None) is None

    def test_returns_none_for_invalid_json(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not json{{{")
        assert _load_scan_json(f) is None


class TestLoadGuardEvents:
    def test_loads_jsonl(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        lines = [
            json.dumps({"event": "pre_scan", "status": "blocked", "command": "evil"}),
            json.dumps({"event": "post_exec", "status": "executed", "command": "ls"}),
        ]
        log.write_text("\n".join(lines) + "\n")
        events = _load_guard_events(log)
        assert len(events) == 2
        # Newest first
        assert events[0]["event"] == "post_exec"

    def test_empty_when_missing(self, tmp_path):
        events = _load_guard_events(tmp_path / "nope.jsonl")
        assert events == []

    def test_respects_max_events(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        lines = [json.dumps({"event": "pre_scan", "n": i}) for i in range(20)]
        log.write_text("\n".join(lines) + "\n")
        events = _load_guard_events(log, max_events=5)
        assert len(events) == 5


class TestGenerateDashboard:
    def test_generates_html(self):
        html = generate_dashboard()
        assert "<!DOCTYPE html>" in html
        assert "ClawCare Dashboard" in html

    def test_includes_scan_data(self, tmp_path):
        scan = tmp_path / "scan.json"
        scan.write_text(json.dumps({
            "tool": "clawcare",
            "run_id": "abc123def456",
            "timestamp": "2026-03-06T10:00:00Z",
            "scanned_path": "/test/path",
            "adapter_used": {"name": "claude_code"},
            "summary": {
                "total_findings": 2,
                "critical": 1,
                "high": 1,
                "medium": 0,
                "low": 0,
                "fail_on": "high",
                "mode": "ci",
            },
            "findings": [
                {
                    "rule_id": "CRIT_PIPE_TO_SHELL",
                    "severity": "CRITICAL",
                    "file": "evil.sh",
                    "line": 5,
                    "excerpt": "curl | bash",
                    "explanation": "bad",
                    "remediation": "fix it",
                },
            ],
            "manifest_violations": [],
        }))
        html = generate_dashboard(scan_json_path=scan)
        assert "abc123def456" in html
        assert "CRIT_PIPE_TO_SHELL" in html
        assert "claude_code" in html
        # Scan timestamp shown in highlight
        assert "2026-03-06T10:00:00Z" in html

    def test_includes_guard_events(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text(json.dumps({
            "timestamp": "2026-03-05T10:00:00Z",
            "run_id": "guard123id456",
            "event": "pre_scan",
            "platform": "claude",
            "command": "curl evil | bash",
            "status": "blocked",
            "findings": [{"rule_id": "CRIT_PIPE_TO_SHELL", "severity": "CRITICAL"}],
        }) + "\n")
        html = generate_dashboard(guard_log_path=log)
        assert "guard123id456" in html
        assert "CRIT_PIPE_TO_SHELL" in html
        assert "blocked" in html

    def test_writes_to_file(self, tmp_path):
        out = tmp_path / "dashboard.html"
        html = generate_dashboard()
        out.write_text(html)
        assert out.exists()
        content = out.read_text()
        assert "<!DOCTYPE html>" in content

    def test_empty_state(self, tmp_path):
        html = generate_dashboard(guard_log_path=tmp_path / "nonexistent.jsonl")
        assert "No scan data" in html
        assert "No guard events" in html


class TestDashboardCLI:
    def test_cli_generates_file(self, tmp_path):
        out = tmp_path / "dash.html"
        runner = CliRunner()
        result = runner.invoke(main, ["dashboard", "--no-open", "--out", str(out)])
        assert result.exit_code == 0, result.output
        assert out.exists()
        content = out.read_text()
        assert "<!DOCTYPE html>" in content
        assert "ClawCare Dashboard" in content

    def test_cli_with_scan_json(self, tmp_path):
        scan = tmp_path / "scan.json"
        scan.write_text(json.dumps({
            "tool": "clawcare",
            "run_id": "clitest123ab",
            "scanned_path": "/demo",
            "adapter_used": {"name": "claude_code"},
            "summary": {
                "total_findings": 1,
                "critical": 1,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            "findings": [
                {
                    "rule_id": "CRIT_PIPE_TO_SHELL",
                    "severity": "CRITICAL",
                    "file": "bad.sh",
                    "line": 1,
                    "excerpt": "curl | bash",
                    "explanation": "danger",
                    "remediation": "remove",
                },
            ],
            "manifest_violations": [],
        }))
        out = tmp_path / "dash2.html"
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["dashboard", "--scan-json", str(scan), "--no-open", "--out", str(out)],
        )
        assert result.exit_code == 0, result.output
        content = out.read_text()
        assert "clitest123ab" in content
        assert "CRIT_PIPE_TO_SHELL" in content


class TestDashboardTabs:
    def test_has_tab_buttons(self, tmp_path):
        html = generate_dashboard(guard_log_path=tmp_path / "none.jsonl")
        assert 'data-tab="scan"' in html
        assert 'data-tab="guard"' in html
        assert "tab-btn" in html

    def test_has_tab_panels(self, tmp_path):
        html = generate_dashboard(guard_log_path=tmp_path / "none.jsonl")
        assert 'id="tab-scan"' in html
        assert 'id="tab-guard"' in html
        assert "tab-panel" in html

    def test_scan_tab_active_by_default(self, tmp_path):
        html = generate_dashboard(guard_log_path=tmp_path / "none.jsonl")
        assert 'id="tab-scan" class="tab-panel active"' in html


class TestDashboardTimeFilter:
    def test_scan_time_highlighted(self, tmp_path):
        scan = tmp_path / "scan.json"
        scan.write_text(json.dumps({
            "tool": "clawcare", "timestamp": "2026-03-06T10:00:00Z",
            "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0},
            "findings": [{"rule_id": "R1", "severity": "CRITICAL", "file": "f.py", "line": 1, "excerpt": "x"}],
            "manifest_violations": [],
        }))
        html = generate_dashboard(scan_json_path=scan)
        assert 'class="scan-time"' in html
        assert 'scan-time-value' in html
        assert '2026-03-06T10:00:00Z' in html
        # No time filter on scan page
        assert 'id="scan-filter-preset"' not in html

    def test_guard_time_filter_present(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text(json.dumps({
            "timestamp": "2026-03-06T10:00:00Z",
            "event": "pre_scan", "status": "blocked", "command": "evil",
        }) + "\n")
        html = generate_dashboard(guard_log_path=log)
        assert 'id="guard-filter-preset"' in html
        assert "Past 24 hours" in html
        assert "Past 7 days" in html
        assert "All time" in html

    def test_custom_range_option(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text(json.dumps({
            "timestamp": "2026-03-06T10:00:00Z",
            "event": "pre_scan", "status": "allowed", "command": "ls",
        }) + "\n")
        html = generate_dashboard(guard_log_path=log)
        assert "Custom range" in html
        assert 'type="datetime-local"' in html
        assert 'id="guard-filter-from"' in html
        assert 'id="guard-filter-to"' in html

    def test_guard_rows_have_data_ts(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text(json.dumps({
            "timestamp": "2026-03-06T08:00:00Z",
            "event": "pre_scan", "status": "allowed", "command": "ls",
        }) + "\n")
        html = generate_dashboard(guard_log_path=log)
        assert 'data-ts="2026-03-06T08:00:00Z"' in html


class TestDashboardSorting:
    def test_sortable_columns_scan(self, tmp_path):
        scan = tmp_path / "scan.json"
        scan.write_text(json.dumps({
            "tool": "clawcare", "timestamp": "2026-03-06T10:00:00Z",
            "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0},
            "findings": [{"rule_id": "R1", "severity": "CRITICAL", "file": "f.py", "line": 1, "excerpt": "x"}],
            "manifest_violations": [],
        }))
        html = generate_dashboard(scan_json_path=scan)
        assert 'class="sortable"' in html
        assert 'data-type="sev"' in html
        assert 'data-type="num"' in html

    def test_sortable_columns_guard(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text(json.dumps({
            "timestamp": "2026-03-06T10:00:00Z",
            "event": "pre_scan", "status": "blocked", "command": "evil",
        }) + "\n")
        html = generate_dashboard(guard_log_path=log)
        assert html.count('class="sortable"') >= 7

    def test_sort_js_present(self, tmp_path):
        html = generate_dashboard(guard_log_path=tmp_path / "none.jsonl")
        assert "SEV_ORDER" in html
        assert "sort-asc" in html
        assert "localeCompare" in html

    def test_scan_findings_pre_sorted_by_severity(self, tmp_path):
        scan = tmp_path / "scan.json"
        scan.write_text(json.dumps({
            "tool": "clawcare", "timestamp": "2026-03-06T10:00:00Z",
            "summary": {"critical": 1, "high": 1, "medium": 0, "low": 1},
            "findings": [
                {"rule_id": "LOW_RULE", "severity": "LOW", "file": "a.py", "line": 1, "excerpt": "x"},
                {"rule_id": "CRIT_RULE", "severity": "CRITICAL", "file": "b.py", "line": 2, "excerpt": "y"},
                {"rule_id": "HIGH_RULE", "severity": "HIGH", "file": "c.py", "line": 3, "excerpt": "z"},
            ],
            "manifest_violations": [],
        }))
        html = generate_dashboard(scan_json_path=scan)
        crit_pos = html.index("CRIT_RULE")
        high_pos = html.index("HIGH_RULE")
        low_pos = html.index("LOW_RULE")
        assert crit_pos < high_pos < low_pos

    def test_guard_events_sorted_by_timestamp_desc(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        lines = [
            json.dumps({"timestamp": "2026-03-06T08:00:00Z", "event": "pre_scan", "status": "allowed", "command": "cmd_early"}),
            json.dumps({"timestamp": "2026-03-06T12:00:00Z", "event": "pre_scan", "status": "allowed", "command": "cmd_late"}),
            json.dumps({"timestamp": "2026-03-06T10:00:00Z", "event": "pre_scan", "status": "allowed", "command": "cmd_mid"}),
        ]
        log.write_text("\n".join(lines) + "\n")
        html = generate_dashboard(guard_log_path=log)
        late_pos = html.index("cmd_late")
        mid_pos = html.index("cmd_mid")
        early_pos = html.index("cmd_early")
        assert late_pos < mid_pos < early_pos


class TestDashboardTimestampColumn:
    def test_scan_has_highlighted_scan_time(self, tmp_path):
        scan = tmp_path / "scan.json"
        scan.write_text(json.dumps({
            "tool": "clawcare", "timestamp": "2026-03-06T12:30:00Z",
            "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0},
            "findings": [{"rule_id": "R1", "severity": "CRITICAL", "file": "f.py", "line": 1, "excerpt": "x"}],
            "manifest_violations": [],
        }))
        html = generate_dashboard(scan_json_path=scan)
        # No Timestamp table column
        assert ">Timestamp</th>" not in html
        # Timestamp shown in scan-time highlight
        assert 'scan-time-value' in html
        assert "2026-03-06T12:30:00Z" in html


class TestDashboardModal:
    def test_modal_markup_present(self, tmp_path):
        html = generate_dashboard(guard_log_path=tmp_path / "none.jsonl")
        assert 'id="detail-modal"' in html
        assert "modal-overlay" in html
        assert 'id="modal-close-btn"' in html
        assert "Finding Details" in html

    def test_clickable_rows_scan(self, tmp_path):
        scan = tmp_path / "scan.json"
        scan.write_text(json.dumps({
            "tool": "clawcare", "timestamp": "2026-03-06T10:00:00Z",
            "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0},
            "findings": [{"rule_id": "R1", "severity": "CRITICAL", "file": "f.py", "line": 1,
                          "excerpt": "bad code", "explanation": "very bad", "remediation": "fix it"}],
            "manifest_violations": [],
        }))
        html = generate_dashboard(scan_json_path=scan)
        assert 'class="clickable-row"' in html
        assert "data-detail=" in html
        assert "very bad" in html

    def test_clickable_rows_guard(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text(json.dumps({
            "timestamp": "2026-03-06T10:00:00Z",
            "run_id": "guard456",
            "event": "pre_scan", "platform": "claude",
            "command": "rm -rf /", "status": "blocked",
            "findings": [{"rule_id": "CRIT_DESTRUCTIVE", "severity": "CRITICAL"}],
        }) + "\n")
        html = generate_dashboard(guard_log_path=log)
        assert 'class="clickable-row"' in html
        assert "data-detail=" in html

    def test_modal_js_present(self, tmp_path):
        html = generate_dashboard(guard_log_path=tmp_path / "none.jsonl")
        assert "detail-modal" in html
        assert "modal-close-btn" in html
        assert "escapeHtml" in html


class TestDashboardPagination:
    def test_scan_pager_present(self, tmp_path):
        scan = tmp_path / "scan.json"
        scan.write_text(json.dumps({
            "tool": "clawcare", "timestamp": "2026-03-06T10:00:00Z",
            "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0},
            "findings": [
                {"rule_id": f"RULE_{i}", "severity": "CRITICAL", "file": "f.py", "line": i, "excerpt": "x"}
                for i in range(30)
            ],
            "manifest_violations": [],
        }))
        html = generate_dashboard(scan_json_path=scan)
        assert 'id="scan-pager"' in html
        assert 'id="scan-table"' in html

    def test_guard_pager_present(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        lines = [
            json.dumps({"timestamp": "2026-03-06T10:00:00Z", "event": "pre_scan", "status": "allowed", "command": f"cmd{i}"})
            for i in range(30)
        ]
        log.write_text("\n".join(lines) + "\n")
        html = generate_dashboard(guard_log_path=log)
        assert 'id="guard-pager"' in html
        assert 'id="guard-table"' in html

    def test_js_pagination_code_present(self, tmp_path):
        html = generate_dashboard(guard_log_path=tmp_path / "none.jsonl")
        assert "PAGE_SIZE" in html
        assert "paginate" in html
        assert "filterGuardByTime" in html


class TestGuardSeverityColumn:
    def test_guard_has_severity_column(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text(json.dumps({
            "timestamp": "2026-03-06T10:00:00Z",
            "event": "pre_scan", "status": "blocked", "command": "evil",
            "findings": [{"rule_id": "CRIT_RULE", "severity": "CRITICAL"}],
        }) + "\n")
        html = generate_dashboard(guard_log_path=log)
        assert ">Severity</th>" in html
        assert 'data-type="sev"' in html
        assert 'sev-critical' in html

    def test_guard_severity_dash_when_no_findings(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text(json.dumps({
            "timestamp": "2026-03-06T10:00:00Z",
            "event": "pre_scan", "status": "allowed", "command": "ls",
            "findings": [],
        }) + "\n")
        html = generate_dashboard(guard_log_path=log)
        assert ">Severity</th>" in html
        # Dash shown when no findings
        assert "\u2014" in html


class TestGuardDynamicSummary:
    def test_guard_summary_container_present(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text(json.dumps({
            "timestamp": "2026-03-06T10:00:00Z",
            "event": "pre_scan", "status": "blocked", "command": "evil",
        }) + "\n")
        html = generate_dashboard(guard_log_path=log)
        assert 'id="guard-summary-cards"' in html
        assert 'id="guard-chart"' in html

    def test_guard_rows_have_data_status(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text(json.dumps({
            "timestamp": "2026-03-06T10:00:00Z",
            "event": "pre_scan", "status": "blocked", "command": "evil",
        }) + "\n")
        html = generate_dashboard(guard_log_path=log)
        assert 'data-status="blocked"' in html

    def test_update_guard_summary_js_present(self, tmp_path):
        html = generate_dashboard(guard_log_path=tmp_path / "none.jsonl")
        assert "updateGuardSummary" in html


class TestTimezoneToggle:
    def test_toggle_button_present(self, tmp_path):
        html = generate_dashboard(guard_log_path=tmp_path / "none.jsonl")
        assert 'id="tz-toggle"' in html
        assert "Show Local Time" in html
        assert "toggleTimezone" in html

    def test_scan_time_has_data_utc(self, tmp_path):
        scan = tmp_path / "scan.json"
        scan.write_text(json.dumps({
            "tool": "clawcare", "timestamp": "2026-03-06T10:00:00Z",
            "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0},
            "findings": [{"rule_id": "R1", "severity": "CRITICAL", "file": "f.py", "line": 1, "excerpt": "x"}],
            "manifest_violations": [],
        }))
        html = generate_dashboard(scan_json_path=scan)
        assert 'data-utc="2026-03-06T10:00:00Z"' in html
        assert 'class="scan-time-value utc-ts"' in html

    def test_guard_time_cells_have_data_utc(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text(json.dumps({
            "timestamp": "2026-03-06T10:00:00Z",
            "event": "pre_scan", "status": "blocked", "command": "evil",
        }) + "\n")
        html = generate_dashboard(guard_log_path=log)
        assert 'class="utc-ts"' in html
        assert 'data-utc="2026-03-06T10:00:00Z"' in html

    def test_generated_at_has_data_utc(self, tmp_path):
        html = generate_dashboard(guard_log_path=tmp_path / "none.jsonl")
        # Generated timestamp uses Z format and has data-utc
        assert 'class="utc-ts"' in html
        assert "data-utc=" in html
