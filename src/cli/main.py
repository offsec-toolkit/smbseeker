import asyncio
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from typing import Optional, List
import os

from ..core.scanner import Scanner
from ..core.engine import Engine
from ..smb.client import SMBClient
from ..smb.session import SMBSession
from ..analysis.content_analyzer import ContentAnalyzer, IOCAnalyzer
from ..analysis.plugin_manager import PluginManager
from ..reporting.db import DBManager
from ..reporting.manager import ReportManager

app = typer.Typer(help="SMBSeeker: Professional SMB Scanning and Analysis Tool")
console = Console()

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP, range (CIDR), or hostname"),
    username: str = typer.Option("", "--user", "-u", help="SMB Username"),
    password: str = typer.Option("", "--pass", "-p", help="SMB Password"),
    domain: str = typer.Option("", "--domain", "-d", help="SMB Domain"),
    guest: bool = typer.Option(False, "--guest", "-g", help="Use guest login"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Recursive file scanning"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    format: str = typer.Option("json", "--format", "-f", help="Output format (json, csv, txt)"),
    db_path: str = typer.Option("smbseeker.db", "--db", help="Database path"),
    concurrency: int = typer.Option(50, "--concurrency", "-c", help="Scanner concurrency"),
):
    """Scan a target for SMB shares and sensitive files."""
    
    async def run_scan():
        console.print(f"[bold blue]Starting SMBSeeker scan on {target}[/bold blue]")
        
        db = DBManager(db_path)
        scanner = Scanner(concurrency=concurrency)
        analyzer = ContentAnalyzer()
        
        # Load plugins
        plugin_manager = PluginManager(os.path.join(os.path.dirname(__file__), "..", "plugins"))
        plugin_manager.load_plugins()
        
        # 1. Discover targets
        found_ips = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(description="Scanning for open SMB ports...", total=None)
            if "/" in target:
                async for ip in scanner.scan_range(target):
                    found_ips.append(ip)
            else:
                res = await scanner.check_port(target)
                if res: found_ips.append(res)

        if not found_ips:
            console.print("[yellow]No targets found with open SMB ports.[/yellow]")
            return

        console.print(f"[green]Found {len(found_ips)} target(s) with port 445 open.[/green]")

        # 2. Process each target
        session = SMBSession(username=username, password=password, domain=domain, use_guest=guest)
        
        all_results = []
        for ip in found_ips:
            client = SMBClient(ip)
            if client.connect(session, retries=3):
                shares = client.list_shares()
                for share in shares:
                    share_name = share['name']
                    if share_name.endswith('$') and not guest:
                        continue
                        
                    console.print(f"  [cyan]Accessing share: {share_name}[/cyan]")
                    files = client.list_files(share_name, recursive=recursive)
                    
                    for f_info in files:
                        if not f_info['is_directory']:
                            # Only analyze the beginning of files to stay fast and memory-safe
                            # max_size is set to 1MB by default in get_file_content
                            content = client.get_file_content(share_name, f_info['path'])
                            
                            # Analyze with built-in analyzer
                            findings = analyzer.analyze(content, f_info)
                            
                            # Analyze with plugins
                            for plugin in plugin_manager.plugins:
                                findings.extend(plugin.analyze(content, f_info))
                            
                            result_record = {
                                "target": ip,
                                "share": share_name,
                                "file_path": f_info['path'],
                                "file_name": f_info['name'],
                                "is_directory": False,
                                "size": f_info['size'],
                                "findings": findings
                            }
                            db.save_result(result_record)
                            all_results.append(result_record)
                client.disconnect()

        # 3. Reporting
        if output:
            if format == "json":
                ReportManager.to_json(all_results, output)
            elif format == "csv":
                ReportManager.to_csv(all_results, output)
            elif format == "txt":
                ReportManager.to_text_summary(all_results, output)
        
        # Display summary table
        table = Table(title="Scan Results Summary")
        table.add_column("Target", style="cyan")
        table.add_column("Share", style="magenta")
        table.add_column("File", style="green")
        table.add_column("Findings", justify="right")

        for r in all_results:
            table.add_row(
                r['target'], 
                r['share'], 
                r['file_name'], 
                str(len(r['findings']))
            )
            
        console.print(table)
        console.print(f"[bold green]Scan completed. {len(all_results)} files processed.[/bold green]")

    asyncio.run(run_scan())

if __name__ == "__main__":
    app()
