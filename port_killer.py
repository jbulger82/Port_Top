import psutil
import socket
import subprocess
import asyncio
from datetime import datetime
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, DataTable, Button, Static, Label, RichLog
from textual.screen import ModalScreen
from textual.binding import Binding
from textual.worker import Worker, WorkerState
from textual import on

class NmapModal(ModalScreen):
    """A modal screen to display Nmap scan results."""
    
    CSS = """
    NmapModal {
        align: center middle;
    }
    
    #modal_dialog {
        grid-size: 1;
        grid-gutter: 1;
        grid-rows: 1fr 3;
        padding: 0 1;
        width: 80%;
        height: 70%;
        border: thick $accent;
        background: $surface;
    }
    
    #scan_output {
        height: 1fr;
        border: solid $secondary;
        overflow-y: scroll;
        background: $surface-lighten-1;
    }
    
    #close_btn {
        width: 100%;
        margin-top: 1;
    }
    """

    def __init__(self, port, output):
        super().__init__()
        self.port = port
        self.output = output

    def compose(self) -> ComposeResult:
        with Container(id="modal_dialog"):
            yield Label(f"Nmap Scan Results: Port {self.port}", classes="modal_header")
            log = RichLog(id="scan_output", wrap=True, highlight=True, markup=True)
            log.write(self.output)
            yield log
            yield Button("Close", variant="primary", id="close_btn")

    @on(Button.Pressed, "#close_btn")
    def close_modal(self):
        self.dismiss()


class PortTopApp(App):
    """A TUI to monitor ports, kill processes, and scan targets."""

    CSS = """
    Screen {
        layout: vertical;
    }

    #stats_bar {
        height: 3;
        dock: top;
        background: $primary-darken-2;
        color: $text;
        padding: 1;
        align-vertical: middle;
    }

    DataTable {
        height: 1fr;
        border: solid $secondary;
    }
    
    .status-listen { color: $success; }
    .status-est { color: $warning; }
    .status-other { color: $text-muted; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh_table", "Refresh"),
        Binding("k", "kill_process", "Kill PID"),
        Binding("s", "scan_port", "Nmap Scan"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="stats_bar"):
            yield Label(" CPU: ", id="lbl_cpu")
            yield Label("0%", id="val_cpu")
            yield Label(" | MEM: ", id="lbl_mem")
            yield Label("0%", id="val_mem")
            yield Label(" | PROCS: ", id="lbl_procs")
            yield Label("0", id="val_procs")
        
        yield DataTable(cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "PortTop :: Network Process Manager"
        self.sub_title = "Select a row -> [K]ill or [S]can"
        
        table = self.query_one(DataTable)
        table.add_columns("PID", "Process Name", "User", "Proto", "Local Address", "Status")
        
        # Initial data load
        self.refresh_data()
        
        # Set intervals for auto-refresh
        self.set_interval(2.0, self.update_stats)
        self.set_interval(3.0, self.refresh_data)

    def update_stats(self):
        """Update the top bar stats."""
        try:
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory().percent
            procs = len(psutil.pids())
            
            self.query_one("#val_cpu").update(f"{cpu}%")
            self.query_one("#val_mem").update(f"{mem}%")
            self.query_one("#val_procs").update(str(procs))
            
            # Color coding for high usage
            self.query_one("#val_cpu").styles.color = "red" if cpu > 80 else "green"
            self.query_one("#val_mem").styles.color = "red" if mem > 80 else "green"
        except Exception:
            pass

    def refresh_data(self):
        """Fetch network connections and update the table."""
        table = self.query_one(DataTable)
        # Store current cursor to restore it later if possible
        cursor_row = table.cursor_coordinate.row
        
        # Get all network connections
        try:
            connections = psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            self.notify("Run as root/admin to see all processes!", severity="warning")
            connections = []

        table_data = []
        for i, conn in enumerate(connections):
            if conn.pid is None:
                continue
                
            try:
                proc = psutil.Process(conn.pid)
                name = proc.name()
                username = proc.username()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = "Unknown/Dead"
                username = "?"

            laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            status = conn.status

            # Simple formatting for visual cues
            status_styled = f"[{'green' if status == 'LISTEN' else 'yellow' if status == 'ESTABLISHED' else 'white'}]{status}[/]"
            
            # Key for the row must be unique. 
            # We combine PID, Port, Protocol and loop index to ensure uniqueness 
            # even if a process has multiple connections on the same port (e.g. TCP+UDP or multiple established)
            row_key = f"{conn.pid}-{conn.laddr.port}-{proto}-{i}"
            
            table_data.append((
                str(conn.pid),
                name,
                username,
                proto,
                laddr,
                status_styled,
                row_key # Hidden key for logic
            ))

        # We prefer to clear and re-add to keep it simple, 
        # ideally we would diff the data but for MVP full refresh is safer
        table.clear()
        
        for pid, name, user, proto, addr, status, key in table_data:
            table.add_row(pid, name, user, proto, addr, status, key=key)

        # Try to restore cursor position roughly
        if cursor_row < table.row_count:
            table.move_cursor(row=cursor_row)

    def action_refresh_table(self):
        self.refresh_data()
        self.notify("Table refreshed")

    def action_kill_process(self):
        """Kill the process associated with the selected row."""
        table = self.query_one(DataTable)
        try:
            row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
            row = table.get_row(row_key)
            pid_str = row[0] # PID is first column
            pid = int(pid_str)
            
            # Kill logic
            proc = psutil.Process(pid)
            proc.kill()
            self.notify(f"Killed process {pid} ({row[1]})", severity="information")
            
            # Immediate refresh
            self.refresh_data()
            
        except (ValueError, psutil.NoSuchProcess):
            self.notify("Process already dead or invalid selection", severity="error")
        except psutil.AccessDenied:
            self.notify("Permission denied: Cannot kill this process", severity="error")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    async def run_nmap_scan(self, ip, port):
        """Run nmap in a subprocess."""
        cmd = ["nmap", "-sV", "-p", str(port), ip]
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if stdout:
                return stdout.decode().strip()
            return stderr.decode().strip()
        except FileNotFoundError:
            return "Error: 'nmap' command not found. Please install nmap."

    def action_scan_port(self):
        """Initiate an Nmap scan on the selected port."""
        table = self.query_one(DataTable)
        try:
            row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
            row = table.get_row(row_key)
            laddr = row[4] # Local Address column
            
            # Parse IP and Port
            if ":" in laddr:
                ip, port = laddr.split(":")
                # If listening on all interfaces (0.0.0.0), scan localhost
                if ip == "0.0.0.0" or ip == "::":
                    ip = "127.0.0.1"
                
                self.notify(f"Scanning {ip}:{port}...", severity="information")
                
                # Run the worker
                self.run_worker(
                    self.perform_scan(ip, port), 
                    exclusive=False, 
                    group="scans"
                )
            else:
                self.notify("Invalid address format", severity="error")
                
        except Exception:
            self.notify("Select a row first", severity="warning")

    async def perform_scan(self, ip, port):
        """Worker function to run the scan and show results."""
        result = await self.run_nmap_scan(ip, port)
        self.app.push_screen(NmapModal(port, result))

def main():
    app = PortTopApp()
    app.run()


if __name__ == "__main__":
    main()
