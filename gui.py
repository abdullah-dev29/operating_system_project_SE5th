# gui.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
from allocation import ResourceManager
from visualization import GraphVisualizer
import tkinter.font as tkfont
from datetime import datetime
import json


# Theme palette
BG = "#F5F5F5"
SIDEBAR_BG = "#E8E8E8"
ACCENT = "#4A90E2"
ACCENT_DARK = "#357ABD"
TEXT_COLOR = "#333333"


class ResourceAllocationApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Deadlock Simulator — Interactive RAG Visualizer & Analyzer")
        self.root.geometry("1200x750")
        self.root.configure(bg=BG)
        self.manager = ResourceManager()

        # Statistics tracking
        self.stats = {
            'allocations': 0,
            'releases': 0,
            'requests': 0,
            'deadlocks_detected': 0,
            'safety_checks': 0,
            'recoveries': 0
        }

        # fonts
        self.title_font = tkfont.Font(family="Segoe UI", size=18, weight="bold")
        self.sub_font = tkfont.Font(family="Segoe UI", size=10)
        self.btn_font = tkfont.Font(family="Segoe UI", size=10, weight="bold")

        self.create_widgets()
        self.visualizer = GraphVisualizer(self.manager, self.canvas)
        self.visualizer.show_graph()  # initial graph

    def create_widgets(self):
        # Header
        header = tk.Frame(self.root, bg=BG, pady=10)
        header.pack(fill="x")
        title = tk.Label(header, text="Deadlock Simulator", font=self.title_font, bg=BG, fg=TEXT_COLOR)
        title.pack()
        subtitle = tk.Label(header, text="Interactive Resource Allocation Graph Visualizer & Analyzer", font=self.sub_font, bg=BG, fg=TEXT_COLOR)
        subtitle.pack()

        # Main container
        main = tk.Frame(self.root, bg=BG)
        main.pack(fill="both", expand=True, padx=12, pady=(4,12))

        # Left sidebar (controls) - with STYLED VISIBLE scrollbar
        sidebar_container = tk.Frame(main, bg=SIDEBAR_BG, width=340)
        sidebar_container.pack(side="left", fill="y")
        sidebar_container.pack_propagate(False)

        # Custom style for scrollbar
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Vertical.TScrollbar",
                       background=ACCENT,
                       troughcolor=SIDEBAR_BG,
                       bordercolor=SIDEBAR_BG,
                       arrowcolor="white",
                       width=14)
        style.map("Vertical.TScrollbar",
                 background=[('active', ACCENT_DARK), ('!active', ACCENT)])

        # Canvas for scrolling
        sidebar_canvas = tk.Canvas(sidebar_container, bg=SIDEBAR_BG, highlightthickness=0, width=310)
        scrollbar = ttk.Scrollbar(sidebar_container, orient="vertical", command=sidebar_canvas.yview)
        sidebar = tk.Frame(sidebar_canvas, bg=SIDEBAR_BG, padx=10, pady=10)

        sidebar.bind(
            "<Configure>",
            lambda e: sidebar_canvas.configure(scrollregion=sidebar_canvas.bbox("all"))
        )

        sidebar_canvas.create_window((0, 0), window=sidebar, anchor="nw")
        sidebar_canvas.configure(yscrollcommand=scrollbar.set)

        # Pack with visible scrollbar
        sidebar_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Enable mouse wheel scrolling
        def _on_mousewheel(event):
            sidebar_canvas.yview_scroll(int(-1*(event.delta/120)), "units")

        def _bind_to_mousewheel(event):
            sidebar_canvas.bind_all("<MouseWheel>", _on_mousewheel)

        def _unbind_from_mousewheel(event):
            sidebar_canvas.unbind_all("<MouseWheel>")

        sidebar_canvas.bind('<Enter>', _bind_to_mousewheel)
        sidebar_canvas.bind('<Leave>', _unbind_from_mousewheel)

        ctrl_title = tk.Label(sidebar, text="Controls", bg=SIDEBAR_BG, font=("Segoe UI", 12, "bold"), fg=TEXT_COLOR)
        ctrl_title.pack(anchor="w", pady=(0,8))

        # Process input
        tk.Label(sidebar, text="Process Name", bg=SIDEBAR_BG, fg=TEXT_COLOR).pack(anchor="w", pady=(6,0))
        self.process_entry = ttk.Entry(sidebar, width=28)
        self.process_entry.pack(pady=4)

        # Resource input
        tk.Label(sidebar, text="Resource Name", bg=SIDEBAR_BG, fg=TEXT_COLOR).pack(anchor="w", pady=(8,0))
        self.resource_entry = ttk.Entry(sidebar, width=28)
        self.resource_entry.pack(pady=4)

        # Resource instances input
        tk.Label(sidebar, text="Resource Instances (optional)", bg=SIDEBAR_BG, fg=TEXT_COLOR).pack(anchor="w", pady=(8,0))
        self.instances_entry = ttk.Entry(sidebar, width=28)
        self.instances_entry.insert(0, "1")
        self.instances_entry.pack(pady=4)

        # Buttons frame
        btn_frame = tk.Frame(sidebar, bg=SIDEBAR_BG)
        btn_frame.pack(fill="x", pady=12)

        # Row 1: Request and Allocate
        self._make_button(btn_frame, "Request", self.request_resource).grid(row=0, column=0, padx=4, pady=4, sticky="ew")
        self._make_button(btn_frame, "Allocate", self.allocate_resource).grid(row=0, column=1, padx=4, pady=4, sticky="ew")

        # Row 2: Release and Check Deadlock
        self._make_button(btn_frame, "Release", self.release_resource).grid(row=1, column=0, padx=4, pady=4, sticky="ew")
        self._make_button(btn_frame, "Check Deadlock", self.check_deadlock).grid(row=1, column=1, padx=4, pady=4, sticky="ew")

        # Row 3: Check Safety and Recover
        self._make_button(btn_frame, "Check Safety", self.check_safety).grid(row=2, column=0, padx=4, pady=4, sticky="ew")
        self._make_button(btn_frame, "Recover", self.recover_deadlock).grid(row=2, column=1, padx=4, pady=4, sticky="ew")

        # Row 4: Clear All (full width)
        self._make_button(btn_frame, "Clear All", self.clear_log).grid(row=3, column=0, columnspan=2, padx=4, pady=4, sticky="ew")

        # Configure grid columns to expand equally
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)

        # Separator line
        separator1 = tk.Frame(sidebar, bg="#CCCCCC", height=1)
        separator1.pack(fill="x", pady=10)

        # Test Scenarios Section
        test_title = tk.Label(sidebar, text="Test Scenarios", bg=SIDEBAR_BG, font=("Segoe UI", 11, "bold"), fg=TEXT_COLOR)
        test_title.pack(anchor="w", pady=(6,6))

        test_frame = tk.Frame(sidebar, bg=SIDEBAR_BG)
        test_frame.pack(fill="x")

        self._make_secondary_button(test_frame, "Load Deadlock Scenario", self.load_deadlock_scenario).pack(fill="x", pady=3)
        self._make_secondary_button(test_frame, "Load Safe State Scenario", self.load_safe_scenario).pack(fill="x", pady=3)
        self._make_secondary_button(test_frame, "Load Unsafe State", self.load_unsafe_scenario).pack(fill="x", pady=3)
        self._make_secondary_button(test_frame, "Load Multi-Instance Test", self.load_multi_instance_scenario).pack(fill="x", pady=3)

        # Separator line
        separator2 = tk.Frame(sidebar, bg="#CCCCCC", height=1)
        separator2.pack(fill="x", pady=10)

        # Export/Statistics Section
        export_title = tk.Label(sidebar, text="Reports & Stats", bg=SIDEBAR_BG, font=("Segoe UI", 11, "bold"), fg=TEXT_COLOR)
        export_title.pack(anchor="w", pady=(6,6))

        export_frame = tk.Frame(sidebar, bg=SIDEBAR_BG)
        export_frame.pack(fill="x")

        self._make_secondary_button(export_frame, "Export Log", self.export_log).pack(fill="x", pady=3)
        self._make_secondary_button(export_frame, "View Statistics", self.show_statistics).pack(fill="x", pady=3)
        self._make_secondary_button(export_frame, "Export Report (JSON)", self.export_report).pack(fill="x", pady=3)
        self._make_secondary_button(export_frame, "View Pending Requests", self.view_pending_requests).pack(fill="x", pady=3)

        # Add some bottom padding for better scrolling
        bottom_spacer = tk.Frame(sidebar, bg=SIDEBAR_BG, height=20)
        bottom_spacer.pack()

        # Right panel (visualization)
        viz_panel = tk.Frame(main, bg=BG)
        viz_panel.pack(side="left", fill="both", expand=True, padx=(12,0))

        viz_header = tk.Frame(viz_panel, bg=BG)
        viz_header.pack(fill="x", pady=(0,6))
        tk.Label(viz_header, text="Visualization", bg=BG, fg=TEXT_COLOR, font=("Segoe UI", 12, "bold")).pack(anchor="w")

        self.canvas = tk.Frame(viz_panel, bg="white", bd=1, relief="solid")
        self.canvas.pack(fill="both", expand=True)

        # Bottom status panel
        status_frame = tk.Frame(self.root, bg=BG)
        status_frame.pack(fill="x", padx=12, pady=(6,14))
        tk.Label(status_frame, text="Activity Log", bg=BG, fg=TEXT_COLOR, font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.status_text = tk.Text(status_frame, height=6, wrap="word", font=("Segoe UI", 10))
        self.status_text.pack(fill="x", pady=6)
        self.status_text.config(state="disabled")

    def _make_button(self, parent, text, command):
        """Primary action buttons"""
        b = tk.Button(parent, text=text, command=command, bg=ACCENT, fg="white", activebackground=ACCENT_DARK,
                      relief="flat", font=self.btn_font, padx=8, pady=6)
        b.bind("<Enter>", lambda e: b.config(bg=ACCENT_DARK))
        b.bind("<Leave>", lambda e: b.config(bg=ACCENT))
        return b

    def _make_secondary_button(self, parent, text, command):
        """Secondary buttons for test scenarios and reports"""
        return ttk.Button(parent, text=text, command=command)

    def _log(self, msg):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.status_text.config(state="normal")
        self.status_text.insert(tk.END, f"[{timestamp}] {msg}\n")
        self.status_text.see(tk.END)
        self.status_text.config(state="disabled")

    # NEW: Request Resource (Process requests, waits for approval)
    def request_resource(self):
        process = self.process_entry.get().strip()
        resource = self.resource_entry.get().strip()
        instances_str = self.instances_entry.get().strip()

        if process and resource:
            try:
                instances = int(instances_str) if instances_str else 1
                msg = self.manager.request_resource(process, resource, instances)
                self._log(msg)
                self.stats['requests'] += 1
                self.process_entry.delete(0, tk.END)
                self.resource_entry.delete(0, tk.END)
                self.instances_entry.delete(0, tk.END)
                self.instances_entry.insert(0, "1")
                self.visualizer.show_graph()
            except ValueError:
                messagebox.showerror("Input Error", "Instances must be a number.")
        else:
            messagebox.showerror("Input Error", "Please enter both process and resource.")

    def allocate_resource(self):
        """Direct allocation (immediate approval)"""
        process = self.process_entry.get().strip()
        resource = self.resource_entry.get().strip()
        instances_str = self.instances_entry.get().strip()

        if process and resource:
            try:
                instances = int(instances_str) if instances_str else 1
                msg = self.manager.allocate(process, resource, instances)
                self._log(msg)
                self.stats['allocations'] += 1
                self.process_entry.delete(0, tk.END)
                self.resource_entry.delete(0, tk.END)
                self.instances_entry.delete(0, tk.END)
                self.instances_entry.insert(0, "1")
                self.visualizer.show_graph()
            except ValueError:
                messagebox.showerror("Input Error", "Instances must be a number.")
        else:
            messagebox.showerror("Input Error", "Please enter both process and resource.")

    def release_resource(self):
        process = self.process_entry.get().strip()
        resource = self.resource_entry.get().strip()
        if process and resource:
            msg = self.manager.release(process, resource)
            if "No allocation" in msg:
                messagebox.showerror("Error", msg)
            else:
                self._log(msg)
                self.stats['releases'] += 1
            self.process_entry.delete(0, tk.END)
            self.resource_entry.delete(0, tk.END)
            self.visualizer.show_graph()
        else:
            messagebox.showerror("Input Error", "Please enter both process and resource.")

    def check_deadlock(self):
        has_deadlock, message, cycles = self.manager.detect_deadlock()
        self._log(message)
        if has_deadlock:
            self.stats['deadlocks_detected'] += 1
            messagebox.showwarning("Deadlock Alert", message)
        else:
            messagebox.showinfo("Deadlock Check", message)
        self.visualizer.show_graph()

    def check_safety(self):
        is_safe, message, sequence = self.manager.check_safety()
        self._log(message)
        self.stats['safety_checks'] += 1

        if is_safe:
            messagebox.showinfo("Safety Check", f"System is SAFE!\n\nSafe Sequence: {sequence}")
        else:
            messagebox.showwarning("Safety Check", "System is UNSAFE!\n\n" + message)
        self.visualizer.show_graph()

    def recover_deadlock(self):
        has_deadlock, _, cycles = self.manager.detect_deadlock()

        if not has_deadlock:
            messagebox.showinfo("Recovery", "No deadlock detected. Recovery not needed.")
            return

        # Find a process to terminate
        first_cycle_nodes = {u for edge in cycles[0] for u in edge}
        process_to_terminate = next((n for n in first_cycle_nodes if n in self.manager.processes), None)

        if process_to_terminate:
            msg = self.manager.terminate_process(process_to_terminate)
            self._log(f"RECOVERY ACTION: {msg}")
            self.stats['recoveries'] += 1
            messagebox.showinfo("Recovery", f"Terminated process: {process_to_terminate}\n\nDeadlock resolved!")
            self.visualizer.show_graph()
        else:
            messagebox.showerror("Recovery", "Could not identify process to terminate.")

    def clear_log(self):
        msg = self.manager.clear_all()
        self._log(msg)
        self.visualizer.show_graph()

    # Test Scenario Loaders
    def load_deadlock_scenario(self):
        self.manager.clear_all()
        self._log("Loading Deadlock Scenario (Circular Wait)...")

        self.manager.allocate("P1", "R1")
        self.manager.allocate("P2", "R2")
        self._log("Allocated R1 to P1, R2 to P2")

        self.manager.allocate("P1", "R2")
        self.manager.allocate("P2", "R1")
        self._log("Created circular wait: P1 waits for R2, P2 waits for R1")

        self.visualizer.show_graph()
        messagebox.showinfo("Test Scenario", "Deadlock scenario loaded!\n\nClick 'Check Deadlock' to detect.")

    def load_safe_scenario(self):
        self.manager.clear_all()
        self._log("Loading Safe State Scenario...")

        self.manager.allocate("P1", "R1")
        self.manager.allocate("P2", "R2")
        self.manager.allocate("P3", "R3")
        self._log("Loaded safe state: P1->R1, P2->R2, P3->R3 (no circular dependencies)")

        self.visualizer.show_graph()
        messagebox.showinfo("Test Scenario", "Safe state scenario loaded!\n\nClick 'Check Safety' to verify.")

    def load_unsafe_scenario(self):
        self.manager.clear_all()
        self._log("Loading Unsafe State Scenario...")

        self.manager.allocate("P1", "R1")
        self.manager.allocate("P2", "R2")
        self.manager.allocate("P3", "R3")

        self.manager.allocate("P1", "R2")
        self.manager.allocate("P2", "R3")
        self.manager.allocate("P3", "R1")

        self._log("Loaded unsafe state with multiple waiting requests")
        self.visualizer.show_graph()
        messagebox.showinfo("Test Scenario", "Unsafe state scenario loaded!\n\nCheck safety to analyze.")

    def load_multi_instance_scenario(self):
        self.manager.clear_all()
        self._log("Loading Multi-Instance Resource Scenario...")

        self.manager.allocate("P1", "Printer", 2)
        self.manager.allocate("P2", "Printer", 2)
        self.manager.allocate("P3", "Scanner", 3)

        self._log("Loaded: Printer (2 instances), Scanner (3 instances)")
        self.visualizer.show_graph()
        messagebox.showinfo("Test Scenario", "Multi-instance scenario loaded!\n\nPrinter has 2 instances allocated.")

    # NEW: View Pending Requests
    def view_pending_requests(self):
        requests = self.manager.get_pending_requests()

        if not requests:
            messagebox.showinfo("Pending Requests", "No pending requests in the system.")
            return

        # Create popup window
        req_window = tk.Toplevel(self.root)
        req_window.title("Pending Resource Requests")
        req_window.geometry("500x400")
        req_window.configure(bg=BG)

        tk.Label(req_window, text="Pending Requests", font=self.title_font, bg=BG, fg=TEXT_COLOR).pack(pady=10)

        # Scrollable list
        list_frame = tk.Frame(req_window, bg="white", bd=1, relief="solid")
        list_frame.pack(fill="both", expand=True, padx=20, pady=10)

        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")

        listbox = tk.Listbox(list_frame, font=("Segoe UI", 10), yscrollcommand=scrollbar.set)
        listbox.pack(fill="both", expand=True)
        scrollbar.config(command=listbox.yview)

        for req in requests:
            listbox.insert(tk.END, f"{req['process']} → {req['resource']} ({req['instances']} instance(s))")

        # Approve button
        def approve_selected():
            selection = listbox.curselection()
            if selection:
                idx = selection[0]
                req = requests[idx]
                msg = self.manager.approve_request(req['process'], req['resource'])
                self._log(f"APPROVED: {msg}")
                messagebox.showinfo("Request Approved", msg)
                req_window.destroy()
                self.visualizer.show_graph()
            else:
                messagebox.showwarning("Selection", "Please select a request to approve.")

        btn_frame = tk.Frame(req_window, bg=BG)
        btn_frame.pack(pady=10)
        self._make_button(btn_frame, "Approve Selected", approve_selected).pack(side="left", padx=5)
        self._make_button(btn_frame, "Close", req_window.destroy).pack(side="left", padx=5)

    def export_log(self):
        content = self.status_text.get("1.0", tk.END)
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"activity_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if filename:
            with open(filename, 'w') as f:
                f.write(f"Deadlock Simulator Activity Log\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*60 + "\n\n")
                f.write(content)
            messagebox.showinfo("Export", f"Log exported to:\n{filename}")

    def show_statistics(self):
        stats_window = tk.Toplevel(self.root)
        stats_window.title("System Statistics")
        stats_window.geometry("450x400")
        stats_window.configure(bg=BG)

        tk.Label(stats_window, text="System Statistics", font=self.title_font, bg=BG, fg=TEXT_COLOR).pack(pady=10)

        stats_frame = tk.Frame(stats_window, bg="white", bd=1, relief="solid")
        stats_frame.pack(fill="both", expand=True, padx=20, pady=10)

        stats_data = [
            ("Total Requests:", self.stats['requests']),
            ("Total Allocations:", self.stats['allocations']),
            ("Total Releases:", self.stats['releases']),
            ("Deadlocks Detected:", self.stats['deadlocks_detected']),
            ("Safety Checks:", self.stats['safety_checks']),
            ("Recovery Actions:", self.stats['recoveries']),
            ("Active Processes:", len(self.manager.processes)),
            ("Active Resources:", len(self.manager.resources)),
            ("Pending Requests:", len(self.manager.get_pending_requests())),
            ("Graph Edges:", self.manager.allocation_graph.number_of_edges())
        ]

        for i, (label, value) in enumerate(stats_data):
            row_frame = tk.Frame(stats_frame, bg="white")
            row_frame.pack(fill="x", padx=15, pady=6)
            tk.Label(row_frame, text=label, font=("Segoe UI", 11), bg="white", anchor="w").pack(side="left")
            tk.Label(row_frame, text=str(value), font=("Segoe UI", 11, "bold"), bg="white", fg=ACCENT, anchor="e").pack(side="right")

    def export_report(self):
        report = {
            "timestamp": datetime.now().isoformat(),
            "statistics": self.stats,
            "system_state": {
                "processes": list(self.manager.processes),
                "resources": list(self.manager.resources),
                "resource_instances": dict(self.manager.resource_instances),
                "pending_requests": self.manager.get_pending_requests(),
                "edges": len(list(self.manager.allocation_graph.edges()))
            },
            "deadlock_status": {
                "has_deadlock": self.manager.detect_deadlock()[0],
                "message": self.manager.detect_deadlock()[1]
            },
            "safety_status": {
                "is_safe": self.manager.check_safety()[0],
                "message": self.manager.check_safety()[1]
            }
        }

        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        if filename:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=4)
            messagebox.showinfo("Export", f"Report exported to:\n{filename}")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = ResourceAllocationApp()
    app.run()
