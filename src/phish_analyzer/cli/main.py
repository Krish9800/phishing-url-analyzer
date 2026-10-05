"""Command Line Interface for Phishing URL & Threat Intelligence Analyzer."""

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from phish_analyzer.config.settings import settings
from phish_analyzer.models.report import RiskLevel, ThreatReport
from phish_analyzer.scoring.engine import ScoringEngine

app = typer.Typer(
    name="phish-analyzer",
    help="Defensive Phishing URL, Domain Threat Intelligence, and Homoglyph Spoofing Analyzer.",
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


def _render_rich_report(report: ThreatReport, display_url: str) -> None:
    """Render a structured and color-coded threat evaluation card in terminal."""
    level_styles = {
        RiskLevel.BENIGN: ("green", "✅ BENIGN - CLEAN"),
        RiskLevel.SUSPICIOUS: ("yellow", "⚠️ SUSPICIOUS - ELEVATED RISK"),
        RiskLevel.MALICIOUS: ("red", "🚨 MALICIOUS - HIGH THREAT DETECTED"),
    }
    color, badge = level_styles.get(report.risk_level, ("white", report.risk_level.value))

    # Header Panel
    console.print(
        Panel(
            f"[bold {color}]{badge}[/bold {color}]\n"
            f"[bold]Target URL:[/bold] {display_url}\n"
            f"[bold]Composite Threat Score:[/bold] [{color}]{report.threat_score}/100[/{color}]",
            title="🛡️ Threat Evaluation Result",
            border_style=color,
        )
    )

    # Lexical Components Table
    p = report.parsed_url
    meta_table = Table(title="Lexical & Structural Components", show_header=True)
    meta_table.add_column("Property", style="cyan", no_wrap=True)
    meta_table.add_column("Value", style="magenta")

    meta_table.add_row("Scheme", p.scheme or "(none)")
    meta_table.add_row("Hostname", p.hostname or "(none)")
    meta_table.add_row("Registered Domain", p.registered_domain or "(none)")
    meta_table.add_row("Subdomains", ", ".join(p.subdomains) if p.subdomains else "(none)")
    meta_table.add_row("IP Host Detected", "Yes" if p.has_ip_host else "No")
    meta_table.add_row("Punycode (IDN)", "Yes" if p.is_punycode else "No")
    meta_table.add_row("Domain Shannon Entropy", f"{p.domain_entropy:.3f} bits/symbol")
    console.print(meta_table)

    # Heuristic Triggers Table
    if report.triggers:
        trigger_table = Table(
            title=f"Security Heuristics Triggered ({len(report.triggers)})",
            show_header=True,
            header_style="bold red",
        )
        trigger_table.add_column("Rule ID", style="bold yellow", no_wrap=True)
        trigger_table.add_column("Severity", style="bold")
        trigger_table.add_column("Weight", justify="right")
        trigger_table.add_column("Description")
        trigger_table.add_column("Evidence", style="dim")

        for t in report.triggers:
            sev_color = {
                "LOW": "blue",
                "MEDIUM": "yellow",
                "HIGH": "bright_red",
                "CRITICAL": "bold red on white",
            }.get(t.severity.value, "white")
            trigger_table.add_row(
                t.rule_id,
                f"[{sev_color}]{t.severity.value}[/{sev_color}]",
                str(t.score_weight),
                t.description,
                t.evidence,
            )
        console.print(trigger_table)
    else:
        console.print("[green]✔ No security heuristics or deceptive traits triggered.[/green]")

    # Defensive Recommendations
    if report.recommendations:
        rec_panel = "\n".join(f" • {rec}" for rec in report.recommendations)
        console.print(
            Panel(
                rec_panel,
                title="📋 Prescriptive Defensive Recommendations",
                border_style="cyan",
            )
        )


@app.command()
def analyze(
    url: Annotated[str, typer.Argument(help="Target URL string to evaluate")],
    output_json: Annotated[
        bool, typer.Option("--json", "-j", help="Output machine-readable JSON format")
    ] = False,
    output_cef: Annotated[
        bool, typer.Option("--cef", "-c", help="Output ArcSight CEF syslog format")
    ] = False,
    defang: Annotated[
        bool, typer.Option("--defang/--no-defang", help="Defang displayed URL in output")
    ] = True,
) -> None:
    """Analyze a single URL for phishing indicators, homoglyphs, and obfuscation."""
    report = ScoringEngine.analyze(url)

    if output_json:
        typer.echo(json.dumps(report.to_dict(), indent=2))
        return

    if output_cef:
        typer.echo(report.to_cef())
        return

    display_url = report.defanged_url if defang else report.raw_url
    _render_rich_report(report, display_url)


@app.command()
def batch(
    file_path: Annotated[
        Path,
        typer.Argument(
            help="Path to text file containing URLs to evaluate (one per line)",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Optional output JSONL file for results"),
    ] = None,
) -> None:
    """Batch analyze multiple URLs from a file and produce aggregate triage statistics."""
    lines = [
        line.strip()
        for line in file_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    if not lines:
        console.print("[yellow]No valid URLs found in file.[/yellow]")
        return

    console.print(f"[bold]Evaluating {len(lines)} URLs from [cyan]{file_path}[/cyan]...[/bold]")

    counts = {RiskLevel.BENIGN: 0, RiskLevel.SUSPICIOUS: 0, RiskLevel.MALICIOUS: 0}
    reports: list[ThreatReport] = []

    for line in lines:
        report = ScoringEngine.analyze(line)
        reports.append(report)
        counts[report.risk_level] += 1

    if output:
        with output.open("w", encoding="utf-8") as f:
            for rep in reports:
                f.write(json.dumps(rep.to_dict()) + "\n")
        console.print(f"[green]Saved {len(reports)} reports to [cyan]{output}[/cyan][/green]")

    # Print summary table
    summary_table = Table(title="Batch Triage Summary", show_header=True)
    summary_table.add_column("Category", style="cyan")
    summary_table.add_column("Count", justify="right", style="bold")
    summary_table.add_column("Percentage", justify="right")

    total = len(reports)
    benign_pct = f"{counts[RiskLevel.BENIGN] / total * 100:.1f}%"
    susp_pct = f"{counts[RiskLevel.SUSPICIOUS] / total * 100:.1f}%"
    mal_pct = f"{counts[RiskLevel.MALICIOUS] / total * 100:.1f}%"

    summary_table.add_row("[green]BENIGN[/green]", str(counts[RiskLevel.BENIGN]), benign_pct)
    summary_table.add_row(
        "[yellow]SUSPICIOUS[/yellow]", str(counts[RiskLevel.SUSPICIOUS]), susp_pct
    )
    summary_table.add_row("[red]MALICIOUS[/red]", str(counts[RiskLevel.MALICIOUS]), mal_pct)
    console.print(summary_table)


@app.command()
def version() -> None:
    """Display application metadata and version."""
    v_info = (
        f"[bold cyan]{settings.APP_NAME}[/bold cyan] "
        f"version [bold green]{settings.VERSION}[/bold green]"
    )
    console.print(v_info)


if __name__ == "__main__":
    app()
