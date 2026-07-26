from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich.rule import Rule
from rich import box

from core.models import AnalysisReport, LogLevel, ParseResult, AnomalyResult

console = Console()

LEVEL_STYLES = {
    "TRACE": "dim",
    "DEBUG": "cyan",
    "INFO": "green",
    "WARNING": "yellow",
    "ERROR": "red",
    "CRITICAL": "bold red",
    "FATAL": "bold bright_red on dark_red",
    "UNKNOWN": "dim white",
}

ANOMALY_STYLES = {
    "security": "bold red",
    "traffic_burst": "yellow",
    "latency_spike": "magenta",
    "repeated_error": "red",
    "high_frequency_source": "cyan",
}


def _fmt_dt(dt: datetime | None) -> str:
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _health_panel(report: AnalysisReport) -> Panel:
    errors = report.level_distribution.get("ERROR", 0) + \
             report.level_distribution.get("CRITICAL", 0) + \
             report.level_distribution.get("FATAL", 0)
    error_pct = errors / report.total_entries * 100 if report.total_entries else 0
    health = "✅ HEALTHY" if error_pct < 1 else ("⚠ DEGRADED" if error_pct < 5 else "🔴 CRITICAL")
    style = "green" if error_pct < 1 else ("yellow" if error_pct < 5 else "red")

    tr_start = _fmt_dt(report.time_range[0]) if report.time_range else "N/A"
    tr_end = _fmt_dt(report.time_range[1]) if report.time_range else "N/A"
    duration = ""
    if report.time_range:
        secs = (report.time_range[1] - report.time_range[0]).total_seconds()
        duration = f"{secs/3600:.1f}h" if secs >= 3600 else f"{secs/60:.1f}m"

    lines = [
        f"[bold {style}]{health}[/]",
        f"Total entries : [bold]{report.total_entries:,}[/]",
        f"Time range    : {tr_start} → {tr_end} ({duration})",
        f"Error rate    : [bold {style}]{error_pct:.2f}%[/]",
        f"Unique hosts  : {len(report.unique_hosts)}",
        f"Anomalies     : [bold yellow]{len(report.anomalies)}[/] "
          f"([bold red]{sum(1 for a in report.anomalies if a.score>=7)}[/] high)",
    ]
    tp = report.throughput_stats
    if tp:
        lines.append(
            f"Throughput    : avg {tp.get('avg_rate_per_min',0):.1f}/min  "
            f"peak {tp.get('peak_rate_per_min',0):,}/min"
        )
    return Panel("\n".join(lines), title="[bold]System Health[/]", border_style=style)


def _level_table(report: AnalysisReport) -> Table:
    t = Table(title="Log Level Distribution", box=box.SIMPLE_HEAVY, header_style="bold magenta")
    t.add_column("Level", style="bold")
    t.add_column("Count", justify="right")
    t.add_column("Pct", justify="right")
    t.add_column("Bar")
    total = report.total_entries or 1
    ordered = ["TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "FATAL", "UNKNOWN"]
    for lvl in ordered:
        count = report.level_distribution.get(lvl, 0)
        if count == 0:
            continue
        pct = count / total * 100
        bar = "█" * int(pct / 2)
        style = LEVEL_STYLES.get(lvl, "")
        t.add_row(lvl, f"{count:,}", f"{pct:.1f}%", f"[{style}]{bar}[/]")
    return t


def _top_errors_table(report: AnalysisReport, n: int = 15) -> Table:
    t = Table(title=f"Top Error Patterns (top {n})", box=box.SIMPLE_HEAVY, header_style="bold red")
    t.add_column("Count", justify="right", style="bold red")
    t.add_column("Error Pattern")
    for msg, count in report.top_errors[:n]:
        t.add_row(str(count), msg[:120])
    return t


def _top_sources_table(report: AnalysisReport, n: int = 10) -> Table:
    t = Table(title=f"Top Sources (top {n})", box=box.SIMPLE_HEAVY, header_style="bold cyan")
    t.add_column("Source", style="cyan")
    t.add_column("Count", justify="right")
    t.add_column("Bar")
    top_count = report.top_sources[0][1] if report.top_sources else 1
    for src, count in report.top_sources[:n]:
        bar = "█" * int(count / top_count * 30)
        t.add_row(src or "<unknown>", f"{count:,}", f"[cyan]{bar}[/]")
    return t


def _anomalies_table(anomalies: list[AnomalyResult], n: int = 20) -> Table:
    t = Table(title=f"Anomalies Detected ({len(anomalies)} total)", box=box.SIMPLE_HEAVY, header_style="bold yellow")
    t.add_column("Score", justify="right", style="bold")
    t.add_column("Type", style="bold")
    t.add_column("Line", justify="right", style="dim")
    t.add_column("Description")
    t.add_column("Action")
    for a in anomalies[:n]:
        style = ANOMALY_STYLES.get(a.anomaly_type, "white")
        t.add_row(
            f"[{style}]{a.score:.1f}[/]",
            f"[{style}]{a.anomaly_type}[/]",
            str(a.entry.line_number),
            a.description[:80],
            a.suggested_action[:60],
        )
    return t


def _patterns_table(report: AnalysisReport, n: int = 10) -> Table:
    t = Table(title=f"Top Log Patterns (top {n})", box=box.SIMPLE_HEAVY, header_style="bold green")
    t.add_column("Count", justify="right", style="green")
    t.add_column("Level", style="bold")
    t.add_column("Template")
    for p in report.patterns[:n]:
        lvl = p.get("dominant_level", "?")
        style = LEVEL_STYLES.get(lvl, "")
        t.add_row(
            str(p["count"]),
            f"[{style}]{lvl}[/]",
            p["template"][:120],
        )
    return t


def _keyword_table(report: AnalysisReport) -> Table:
    t = Table(title="Keyword Frequency", box=box.SIMPLE_HEAVY, header_style="bold magenta")
    t.add_column("Keyword", style="yellow")
    t.add_column("Hits", justify="right")
    for kw, count in list(report.keyword_frequency.items())[:15]:
        t.add_row(kw, str(count))
    return t


def _hourly_chart(report: AnalysisReport) -> str:
    if not report.hourly_distribution:
        return ""
    max_val = max(report.hourly_distribution.values(), default=1)
    lines = ["Hourly Activity (UTC)"]
    for hour in range(24):
        count = report.hourly_distribution.get(hour, 0)
        bar = "█" * int(count / max_val * 40)
        lines.append(f"  {hour:02d}h │{bar:<40} {count:>6}")
    return "\n".join(lines)


def print_parse_summary(result: ParseResult) -> None:
    console.print(Rule("[bold blue]Parse Summary[/]"))
    console.print(f"  Format detected : [bold]{result.detected_format.value}[/]")
    console.print(f"  Total lines     : {result.total_lines:,}")
    console.print(f"  Parsed          : [green]{result.parsed_lines:,}[/] ({result.success_rate:.1f}%)")
    console.print(f"  Failed          : [red]{result.failed_lines:,}[/]")
    console.print(f"  Parse time      : {result.parse_duration_ms:.1f}ms")
    if result.errors:
        console.print(f"  Parse errors (first {min(5,len(result.errors))}):")
        for err in result.errors[:5]:
            console.print(f"    [dim red]{err}[/]")


def print_full_report(report: AnalysisReport, show_clusters: list[dict] | None = None) -> None:
    console.print()
    console.print(_health_panel(report))
    console.print()

    console.print(Rule("[bold blue]Analysis[/]"))
    console.print(Columns([_level_table(report), _top_sources_table(report)]))
    console.print()

    if report.anomalies:
        console.print(_anomalies_table(report.anomalies))
        console.print()

    if report.top_errors:
        console.print(_top_errors_table(report))
        console.print()

    if report.patterns:
        console.print(_patterns_table(report))
        console.print()

    if report.keyword_frequency:
        console.print(_keyword_table(report))
        console.print()

    if report.hourly_distribution:
        console.print(Panel(_hourly_chart(report), title="Hourly Distribution", border_style="blue"))
        console.print()

    if show_clusters:
        t = Table(title="ML Clusters", box=box.SIMPLE_HEAVY, header_style="bold green")
        t.add_column("ID", justify="right")
        t.add_column("Size", justify="right")
        t.add_column("Level")
        t.add_column("Keywords")
        t.add_column("Sample")
        for cl in show_clusters[:15]:
            lvl = cl.get("dominant_level", "?")
            style = LEVEL_STYLES.get(lvl, "")
            sample = (cl.get("sample_messages") or [""])[0][:60]
            t.add_row(
                str(cl["cluster_id"]),
                str(cl["size"]),
                f"[{style}]{lvl}[/]",
                ", ".join(cl.get("top_words", [])[:5]),
                sample,
            )
        console.print(t)
        console.print()

    console.print(Panel(report.summary, title="[bold]Summary[/]", border_style="green"))
    console.print()
