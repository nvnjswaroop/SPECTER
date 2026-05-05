#!/usr/bin/env python3
"""
👻 SPECTER
Security Pentest Engine with Configurable Threat Exploration and Reporting

Works with: NVIDIA · OpenRouter · Anthropic · Ollama · OpenAI
No Docker required.
"""

import argparse
import sys
import os
import logging
import yaml
import concurrent.futures
from datetime import datetime
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from rich.text import Text

# Ensure UTF-8 output on Windows consoles
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")
console = Console()

BANNER = """[bold red]
 ███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗
 ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
 ███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝
 ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗
 ███████║██║     ███████╗╚██████╗   ██║   ███████╗██║  ██║
 ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═0
[/bold red][dim]  Security Pentest Engine with Configurable Threat Exploration & Reporting
  Works with NVIDIA · OpenRouter · Anthropic · Ollama · OpenAI[/dim]
"""

AGENT_MAP = {
    "recon": ("agents.recon", "ReconAgent"),
    "injection": ("agents.injection", "InjectionAgent"),
    "xss": ("agents.xss", "XSSAgent"),
    "auth": ("agents.auth", "AuthAgent"),
    "lfi": ("agents.lfi", "LFIAgent"),
    "open_redirect": ("agents.open_redirect", "OpenRedirectAgent"),
    "file_upload": ("agents.file_upload", "FileUploadAgent"),
    "ssrf": ("agents.ssrf", "SSRFAgent"),
    "adaptive": ("agents.adaptive_recon", "AdaptiveReconAgent"),
}

ALL_AGENTS = list(AGENT_MAP.keys())

# ------------------------------------------------------------------
def setup_logging(verbose: bool) -> None:
    """Configure the root logger.

    Args:
        verbose: If ``True`` set logging level to ``DEBUG``; otherwise ``WARNING``.
    """
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("specter.log"),
        ]
    )


def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    """Load the YAML configuration file.

    Args:
        path: Path to the configuration file.

    Returns:
        Parsed configuration as a dictionary.
    """
    if not os.path.exists(path):
        console.print(f"[red]✗ config.yaml not found. Copy and edit the template.[/red]")
        sys.exit(1)
    with open(path) as f:
        return yaml.safe_load(f)

# ------------------------------------------------------------------
def cmd_test_connection(config_path: str = "config.yaml") -> None:
    """Test the LLM connection using the provided configuration.

    Args:
        config_path: Path to the configuration YAML file.
    """
    from core.llm_router import LLMRouter
    console.print(Panel("[bold]Testing LLM Connection[/bold]", style="cyan"))
    try:
        router = LLMRouter(config_path)
        info = router.info()
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("k", style="cyan")
        t.add_column("v")
        t.add_row("Provider", info["provider"])
        t.add_row("Model", info["model"])
        t.add_row("Base URL", info["base_url"])
        console.print(t)

        console.print("Connecting...", end=" ")
        ok, msg = router.test_connection()
        if ok:
            console.print(f"[bold green]✅ {msg}[/bold green]")
        else:
            console.print(f"[bold red]❌ {msg}[/bold red]")
            sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

# ------------------------------------------------------------------
def cmd_list_sessions() -> None:
    """List all previously stored scan sessions."""
    from core.session import SessionManager
    sm = SessionManager()
    sessions = sm.list_all()
    if not sessions:
        console.print("[dim]No past sessions found.[/dim]")
        return
    t = Table(title="Past Sessions", box=box.ROUNDED)
    t.add_column("Session ID", style="cyan")
    t.add_column("Target")
    t.add_column("Status", style="green")
    t.add_column("Findings", justify="right")
    t.add_column("Agents Done")
    t.add_column("Started")
    for s in sessions:
        t.add_row(
            s["id"], s["target"], s["status"],
            str(len(s.get("findings", []))),
            ", ".join(s.get("agents_completed", [])),
            s.get("started", "")[:19],
        )
    console.print(t)

# ------------------------------------------------------------------
def run_agent(agent_name: str, router: Any, target: str, config: Dict[str, Any], session: Dict[str, Any]) -> List[Any]:
    """Instantiate and run a single agent.

    Args:
        agent_name: Key of the agent in ``AGENT_MAP``.
        router: Initialized ``LLMRouter`` instance.
        target: Target URL to scan.
        config: Configuration dictionary.
        session: Current session dictionary.

    Returns:
        List of findings produced by the agent.
    """
    module_name, class_name = AGENT_MAP[agent_name]
    import importlib
    mod = importlib.import_module(module_name)
    cls = getattr(mod, class_name)
    agent = cls(router, target, config)

    # Pass the session to the agent if it supports it
    if hasattr(agent, "session"):
        agent.session = session

    return agent.run()

# ------------------------------------------------------------------
def _run_agents_concurrently(
    agents_to_run: List[str],
    router: Any,
    target: str,
    config: Dict[str, Any],
    session: Dict[str, Any],
) -> List[Any]:
    """Execute agents in parallel using a thread pool.

    Returns:
        A flat list of all findings collected from the agents.
    """
    all_findings: List[Any] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(agents_to_run)) as executor:
        futures = {
            executor.submit(run_agent, name, router, target, config, session): name
            for name in agents_to_run
        }
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                findings = future.result()
                all_findings.extend(findings)
                from core.session import SessionManager
                SessionManager().update(session, findings, name)
            except Exception as e:
                console.print(f"[red][{name}] Error: {e}[/red]")
    return all_findings


def _run_agents_sequential(
    agents_to_run: List[str],
    router: Any,
    target: str,
    config: Dict[str, Any],
    session: Dict[str, Any],
) -> List[Any]:
    """Execute agents sequentially (single‑threaded)."""
    all_findings: List[Any] = []
    from core.session import SessionManager
    sm = SessionManager()
    for name in agents_to_run:
        try:
            findings = run_agent(name, router, target, config, session)
            all_findings.extend(findings)
            sm.update(session, findings, name)
        except Exception as e:
            console.print(f"[red][{name}] Error: {e}[/red]")
    return all_findings


def _print_summary_and_generate_reports(
    all_findings: List[Any],
    session: Dict[str, Any],
    config: Dict[str, Any],
) -> None:
    """Print a summary table and generate HTML/MD/JSON reports.

    Args:
        all_findings: List of findings collected from all agents.
        session: Session metadata dictionary.
        config: Configuration dictionary.
    """
    console.print(f"\n[bold]{'━'*55}[/bold]")
    console.print(f"[bold green]✅ Scan Complete![/bold green]  {len(all_findings)} total finding(s)")
    if all_findings:
        t = Table(title="Findings Summary", box=box.ROUNDED)
        t.add_column("#", justify="right", style="dim")
        t.add_column("Severity", style="bold")
        t.add_column("Title")
        t.add_column("Agent", style="dim")
        t.add_column("Endpoint", style="dim")
        sev_style = {
            "CRITICAL": "red",
            "HIGH": "orange3",
            "MEDIUM": "yellow",
            "LOW": "green",
            "INFO": "dim",
        }
        for i, f in enumerate(all_findings, 1):
            sev = getattr(f, "severity", f.get("severity", "INFO"))
            title = getattr(f, "title", f.get("title", ""))
            agent = getattr(f, "agent", f.get("agent", ""))
            ep = getattr(f, "endpoint", f.get("endpoint", ""))
            style = sev_style.get(sev, "white")
            t.add_row(str(i), f"[{style}]{sev}[/{style}]", title, agent, ep[:50])
        console.print(t)

    reporter = Reporter(session, config.get("output", {}).get("report_dir", "reports"))
    paths = reporter.generate_all()
    console.print(f"\n[bold]📄 Reports generated:[/bold]")
    for fmt, path in paths.items():
        console.print(f"   [{fmt.upper()}] {path}")
    console.print(f"\n[dim]Session: sessions/{session['id']}.json[/dim]")

# ------------------------------------------------------------------
def cmd_scan(
    target: str,
    agents_to_run: List[str],
    threads: int,
    output_formats: List[str],
    config_path: str,
) -> None:
    """Orchestrate a full scan against ``target``.

    Args:
        target: URL of the target web application.
        agents_to_run: List of agent identifiers to execute.
        threads: Number of parallel threads (1 = sequential).
        output_formats: Desired report formats.
        config_path: Path to the configuration file.
    """
    from core.llm_router import LLMRouter
    from core.session import SessionManager
    from reports.reporter import Reporter

    config = load_config(config_path)
    sm = SessionManager(config.get("output", {}).get("session_dir", "sessions"))
    session = sm.new(target, agents_to_run)

    console.print(f"\n[bold green]🎯 Target:[/bold green]  {target}")
    console.print(f"[bold green]📋 Session:[/bold green] {session['id']}")
    console.print(f"[bold green]🤖 Agents:[/bold green]  {', '.join(agents_to_run)}")
    console.print(f"[bold green]⚙️  Threads:[/bold green] {threads}\n")

    try:
        router = LLMRouter(config_path)
    except Exception as e:
        console.print(f"[red]LLM init failed: {e}[/red]")
        sm.fail(session, str(e))
        sys.exit(1)

    if threads > 1:
        all_findings = _run_agents_concurrently(agents_to_run, router, target, config, session)
    else:
        all_findings = _run_agents_sequential(agents_to_run, router, target, config, session)

    sm.complete(session)
    _print_summary_and_generate_reports(all_findings, session, config)

# ------------------------------------------------------------------
def main() -> None:
    """Entry point for the CLI.

    Parses arguments, displays the banner, and dispatches to sub‑commands.
    """
    console.print(BANNER)

    parser = argparse.ArgumentParser(
        description="👻 SPECTER — AI Pentest Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
    Examples:
      python specter.py -u https://target.com
      python specter.py -u https://target.com --agents recon injection xss
      python specter.py --test-connection
      python specter.py --sessions
        """,
    )
    parser.add_argument("-u", "--url", help="Target URL to scan")
    parser.add_argument(
        "--agents",
        nargs="+",
        default=ALL_AGENTS,
        choices=ALL_AGENTS,
        metavar="AGENT",
        help=f"Agents to run. Choices: {', '.join(ALL_AGENTS)}",
    )
    parser.add_argument("--threads", type=int, default=1, help="Parallel agents (default: 1, use 3 for faster scans)")
    parser.add_argument(
        "--formats",
        nargs="+",
        default=["html", "markdown", "json"],
        help="Report formats (html markdown json)",
    )
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--test-connection", action="store_true")
    parser.add_argument("--sessions", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()
    setup_logging(args.verbose)

    if args.test_connection:
        cmd_test_connection(args.config)
    elif args.sessions:
        cmd_list_sessions()
    elif args.url:
        console.print(
            Panel(
                "[bold yellow]⚠ LEGAL NOTICE[/bold yellow]\n"
                "Only scan targets you own or have written authorization to test.\n"
                "Unauthorized scanning is illegal.",
                style="yellow",
            )
        )
        confirm = (
            os.getenv("SPECTER_AUTO_CONFIRM", "").strip().lower()
            or input("Type 'yes' to confirm you have authorization: ").strip().lower()
        )
        if confirm != "yes":
            console.print("[red]Aborted.[/red]")
            sys.exit(0)
        cmd_scan(args.url, args.agents, args.threads, args.formats, args.config)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
