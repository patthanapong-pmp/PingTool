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
        self.root.title("Advanced GUI Ping Tool")
        self.root.geometry("550x550")
        self.root.resizable(False, False)

        self.stop_event = threading.Event()

        style = ttk.Style()
        style.configure("TLabel", font=("Helvetica", 10))
        style.configure("TButton", font=("Helvetica", 10, "bold"))
        style.configure("TEntry", font=("Helvetica", 10))
        style.configure("Header.TLabel", font=("Helvetica", 12, "bold"))

        main_frame = ttk.Frame(root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=(0, 15))
        input_frame.columnconfigure(1, weight=1)

        # --- NEW: IP Pattern Input ---
        ttk.Label(input_frame, text="IP Address Pattern:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.ip_pattern_var = tk.StringVar(value="10.{x}.15.91")
        self.ip_pattern_entry = ttk.Entry(input_frame, textvariable=self.ip_pattern_var)
        self.ip_pattern_entry.grid(row=0, column=1, columnspan=2, sticky=tk.EW)
        ttk.Label(input_frame, text="Use {x} as the placeholder for the range.").grid(row=1, column=1, columnspan=2, sticky=tk.W, pady=(2,0))


        # --- Range Inputs ---
        range_frame = ttk.Frame(input_frame)
        range_frame.grid(row=2, column=1, columnspan=2, sticky=tk.EW, pady=(10,0))

        ttk.Label(range_frame, text="Start Range:").pack(side=tk.LEFT)
        self.start_range_var = tk.StringVar(value="31")
        self.start_range_entry = ttk.Entry(range_frame, textvariable=self.start_range_var, width=10)
        self.start_range_entry.pack(side=tk.LEFT, padx=(5, 20))
        
        ttk.Label(range_frame, text="End Range:").pack(side=tk.LEFT)
        self.end_range_var = tk.StringVar(value="95")
        self.end_range_entry = ttk.Entry(range_frame, textvariable=self.end_range_var, width=10)
        self.end_range_entry.pack(side=tk.LEFT, padx=5)

        controls_frame = ttk.Frame(main_frame)
        controls_frame.pack(fill=tk.X, pady=(5, 15))
        controls_frame.columnconfigure(0, weight=1)
        controls_frame.columnconfigure(1, weight=1)

        self.start_button = ttk.Button(controls_frame, text="Start Ping Sweep", command=self.start_ping_thread)
        self.start_button.grid(row=0, column=0, sticky=tk.EW, padx=(0, 5))

        self.stop_button = ttk.Button(controls_frame, text="Stop", command=self.stop_ping_sweep, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, sticky=tk.EW, padx=(5, 0))
        
        self.export_button = ttk.Button(main_frame, text="Export Results to .txt", command=self.export_to_txt, state=tk.DISABLED)
        self.export_button.pack(fill=tk.X, pady=(5, 15))

        ttk.Label(main_frame, text="Results:", style="Header.TLabel").pack(anchor="w")
        self.results_text = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, font=("Consolas", 10), height=15)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.configure(state='disabled')
        
        self.results_text.tag_config('SUCCESS', foreground='green')
        self.results_text.tag_config('FAILED', foreground='red')
        self.results_text.tag_config('INFO', foreground='blue', font=("Consolas", 10, "bold"))

        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.result_queue = queue.Queue()

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

    def start_ping_thread(self):
        self.stop_event.clear()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.export_button.config(state=tk.DISABLED)

        self.results_text.config(state='normal')
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state='disabled')
        
        try:
            pattern = self.ip_pattern_var.get().strip()
            if "{x}" not in pattern:
                raise ValueError("IP pattern must contain '{x}'.")
            start = int(self.start_range_var.get())
            end = int(self.end_range_var.get())
            if start > end:
                raise ValueError("Start range must be less than or equal to End range.")
        except ValueError as e:
            messagebox.showerror("Invalid Input", str(e))
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            return

        ping_thread = threading.Thread(target=self.ping_sweep, args=(pattern, start, end), daemon=True)
        ping_thread.start()
        self.update_results()

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
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.status_var.set(f"Results exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to save file.\nError: {e}")
            self.status_var.set("Export failed.")

    def ping_sweep(self, pattern, start, end):
        self.status_var.set(f"Pinging pattern {pattern} from {start} to {end}...")
        self.result_queue.put((f"--- Starting Ping Sweep at {time.strftime('%Y-%m-%d %H:%M:%S')} ---", 'INFO'))
        
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        timeout_val = '500' if platform.system().lower() == 'windows' else '0.5'

        for i in range(start, end + 1):
            if self.stop_event.is_set():
                break

            ip = pattern.replace("{x}", str(i))
            command = ['ping', param, '1', timeout_param, timeout_val, ip]
            
            try:
                creation_flags = 0
                if platform.system().lower() == 'windows':
                    creation_flags = subprocess.CREATE_NO_WINDOW
                
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True, creationflags=creation_flags)
                
                if "ttl" in result.stdout.lower():
                    self.result_queue.put((f"[SUCCESS] {ip} is UP", 'SUCCESS'))
                else:
                    self.result_queue.put((f"[FAILED]  {ip} is DOWN or timed out", 'FAILED'))

            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                self.result_queue.put((f"[FAILED]  {ip} is DOWN or unreachable", 'FAILED'))
        
        if self.stop_event.is_set():
            self.result_queue.put(("--- Ping Sweep stopped by user ---", 'INFO'))
            self.status_var.set("Stopped by user.")
        else:
            self.result_queue.put(("--- Ping Sweep Completed ---", 'INFO'))
            self.status_var.set("Ready")

        self.root.after(100, self.reset_button_states)

    def reset_button_states(self):
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        if len(self.results_text.get("1.0", "end-1c")) > 0:
            self.export_button.config(state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk()
    app = PingToolApp(root)
    root.mainloop()