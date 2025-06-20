import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import subprocess
import platform
import threading
import queue
import time

class PingToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Multi-Mode GUI Ping Tool")
        self.root.geometry("550x600") # Increased height for tabs
        self.root.resizable(False, False)

        self.stop_event = threading.Event()

        # --- GUI Style ---
        style = ttk.Style()
        style.configure("TLabel", font=("Helvetica", 10))
        style.configure("TButton", font=("Helvetica", 10, "bold"))
        style.configure("TEntry", font=("Helvetica", 10))
        style.configure("Header.TLabel", font=("Helvetica", 12, "bold"))
        style.configure('TNotebook.Tab', font=('Helvetica', '10', 'bold'))

        # --- Main Frame ---
        main_frame = ttk.Frame(root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # --- Notebook for Mode Tabs ---
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(expand=True, fill='both', pady=(0, 15))

        # --- TAB 1: Normal Mode ---
        self.normal_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.normal_tab, text=' Normal Mode ')
        self.create_normal_mode_widgets()

        # --- TAB 2: Pattern Mode ---
        self.pattern_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.pattern_tab, text=' Pattern Mode {x} ')
        self.create_pattern_mode_widgets()

        # --- Shared Controls (Start, Stop, Export) ---
        self.create_shared_controls(main_frame)

        # --- Results Display & Status Bar ---
        self.create_results_and_status(main_frame)

        self.result_queue = queue.Queue()

    def create_normal_mode_widgets(self):
        """Creates widgets for the Normal Mode tab."""
        frame = self.normal_tab
        ttk.Label(frame, text="IP Network Prefix (e.g., 192.168.1):").pack(anchor="w", pady=(0, 5))
        self.normal_prefix_var = tk.StringVar(value="192.168.1")
        ttk.Entry(frame, textvariable=self.normal_prefix_var).pack(fill="x", pady=(0, 15))

        range_frame = ttk.Frame(frame)
        range_frame.pack(fill="x")
        ttk.Label(range_frame, text="Start Range (1-254):").pack(side="left")
        self.normal_start_var = tk.StringVar(value="1")
        ttk.Entry(range_frame, textvariable=self.normal_start_var, width=10).pack(side="left", padx=5)

        ttk.Label(range_frame, text="End Range (1-254):").pack(side="left", padx=(10, 0))
        self.normal_end_var = tk.StringVar(value="254")
        ttk.Entry(range_frame, textvariable=self.normal_end_var, width=10).pack(side="left", padx=5)

    def create_pattern_mode_widgets(self):
        """Creates widgets for the Pattern Mode tab."""
        frame = self.pattern_tab
        ttk.Label(frame, text="IP Address Pattern (use {x} as placeholder):").pack(anchor="w", pady=(0, 5))
        self.pattern_pattern_var = tk.StringVar(value="10.{x}.15.91")
        ttk.Entry(frame, textvariable=self.pattern_pattern_var).pack(fill="x", pady=(0, 15))

        range_frame = ttk.Frame(frame)
        range_frame.pack(fill="x")
        ttk.Label(range_frame, text="Start Range:").pack(side="left")
        self.pattern_start_var = tk.StringVar(value="31")
        ttk.Entry(range_frame, textvariable=self.pattern_start_var, width=10).pack(side="left", padx=5)

        ttk.Label(range_frame, text="End Range:").pack(side="left", padx=(10, 0))
        self.pattern_end_var = tk.StringVar(value="95")
        ttk.Entry(range_frame, textvariable=self.pattern_end_var, width=10).pack(side="left", padx=5)
        
    def create_shared_controls(self, parent_frame):
        """Creates the Start, Stop, and Export buttons."""
        controls_frame = ttk.Frame(parent_frame)
        controls_frame.pack(fill=tk.X, pady=(0, 5))
        controls_frame.columnconfigure(0, weight=1)
        controls_frame.columnconfigure(1, weight=1)

        self.start_button = ttk.Button(controls_frame, text="Start Ping Sweep", command=self.start_ping_thread)
        self.start_button.grid(row=0, column=0, sticky=tk.EW, padx=(0, 5))

        self.stop_button = ttk.Button(controls_frame, text="Stop", command=self.stop_ping_sweep, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, sticky=tk.EW, padx=(5, 0))
        
        self.export_button = ttk.Button(parent_frame, text="Export Results to .txt", command=self.export_to_txt, state=tk.DISABLED)
        self.export_button.pack(fill=tk.X, pady=(5, 15))

    def create_results_and_status(self, parent_frame):
        """Creates the results text area and the status bar."""
        ttk.Label(parent_frame, text="Results:", style="Header.TLabel").pack(anchor="w")
        self.results_text = scrolledtext.ScrolledText(parent_frame, wrap=tk.WORD, font=("Consolas", 10), height=15)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.configure(state='disabled')
        
        self.results_text.tag_config('SUCCESS', foreground='green')
        self.results_text.tag_config('FAILED', foreground='red')
        self.results_text.tag_config('INFO', foreground='blue', font=("Consolas", 10, "bold"))

        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def start_ping_thread(self):
        """Determines active tab and starts the pinging thread with correct parameters."""
        self.stop_event.clear()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.export_button.config(state=tk.DISABLED)

        self.results_text.config(state='normal')
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state='disabled')
        
        try:
            current_tab = self.notebook.index(self.notebook.select())
            # Mode 0: Normal Mode
            if current_tab == 0:
                prefix = self.normal_prefix_var.get().strip()
                if not prefix or prefix.endswith('.'):
                    raise ValueError("IP Prefix cannot be empty or end with a dot.")
                pattern = f"{prefix}.{{x}}"
                start = int(self.normal_start_var.get())
                end = int(self.normal_end_var.get())
                if not (0 < start <= 254 and 0 < end <= 254):
                     raise ValueError("For Normal Mode, range must be between 1 and 254.")
            # Mode 1: Pattern Mode
            else:
                pattern = self.pattern_pattern_var.get().strip()
                if "{x}" not in pattern:
                    raise ValueError("IP pattern must contain '{x}'.")
                start = int(self.pattern_start_var.get())
                end = int(self.pattern_end_var.get())

            if start > end:
                raise ValueError("Start range must be less than or equal to End range.")
                
        except ValueError as e:
            messagebox.showerror("Invalid Input", str(e))
            self.reset_button_states()
            return

        ping_thread = threading.Thread(target=self.ping_sweep, args=(pattern, start, end), daemon=True)
        ping_thread.start()
        self.update_results()

    def ping_sweep(self, pattern, start, end):
        """The core pinging logic. Works for both modes."""
        self.status_var.set(f"Pinging pattern '{pattern}' from {start} to {end}...")
        self.result_queue.put((f"--- Starting Ping Sweep at {time.strftime('%Y-%m-%d %H:%M:%S')} ---", 'INFO'))
        
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        timeout_val = '500' if platform.system().lower() == 'windows' else '0.5'

        for i in range(start, end + 1):
            if self.stop_event.is_set(): break
            ip = pattern.replace("{x}", str(i))
            command = ['ping', param, '1', timeout_param, timeout_val, ip]
            try:
                creation_flags = 0
                if platform.system().lower() == 'windows':
                    creation_flags = subprocess.CREATE_NO_WINDOW
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True, creationflags=creation_flags)
                if "ttl" in result.stdout.lower(): self.result_queue.put((f"[SUCCESS] {ip} is UP", 'SUCCESS'))
                else: self.result_queue.put((f"[FAILED]  {ip} is DOWN or timed out", 'FAILED'))
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                self.result_queue.put((f"[FAILED]  {ip} is DOWN or unreachable", 'FAILED'))
        
        if self.stop_event.is_set():
            self.result_queue.put(("--- Ping Sweep stopped by user ---", 'INFO'))
            self.status_var.set("Stopped by user.")
        else:
            self.result_queue.put(("--- Ping Sweep Completed ---", 'INFO'))
            self.status_var.set("Ready")

        self.root.after(100, self.reset_button_states)

    def stop_ping_sweep(self):
        self.status_var.set("Stopping...")
        self.stop_event.set()
        self.stop_button.config(state=tk.DISABLED)

    def export_to_txt(self):
        content = self.results_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("Export Empty", "There are no results to export.")
            return
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt", filetypes=[("Text Documents", "*.txt"), ("All Files", "*.*")],
                title="Save Ping Results", initialfile="ping_results.txt"
            )
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f: f.write(content)
                self.status_var.set(f"Results exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to save file.\nError: {e}")
            self.status_var.set("Export failed.")

    def update_results(self):
        try:
            while True:
                message, tag = self.result_queue.get_nowait()
                self.results_text.configure(state='normal')
                self.results_text.insert(tk.END, message + '\n', tag)
                self.results_text.configure(state='disabled')
                self.results_text.see(tk.END)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.update_results)

    def reset_button_states(self):
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        if len(self.results_text.get("1.0", "end-1c")) > 0:
            self.export_button.config(state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk()
    app = PingToolApp(root)
    root.mainloop()