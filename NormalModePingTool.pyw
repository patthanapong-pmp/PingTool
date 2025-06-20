import tkinter as tk
from tkinter import ttk, scrolledtext
import subprocess
import platform
import threading
import queue

class PingToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("GUI Ping Tool")
        self.root.geometry("550x500")
        self.root.resizable(False, False)

        # --- Style ---
        style = ttk.Style()
        style.configure("TLabel", font=("Helvetica", 10))
        style.configure("TButton", font=("Helvetica", 10, "bold"))
        style.configure("TEntry", font=("Helvetica", 10))
        style.configure("Header.TLabel", font=("Helvetica", 12, "bold"))

        # --- Main Frame ---
        main_frame = ttk.Frame(root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Input Frame ---
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=(0, 15))
        input_frame.columnconfigure(1, weight=1)

        ttk.Label(input_frame, text="IP Network Prefix:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.ip_network_var = tk.StringVar(value="10.30.13")
        self.ip_network_entry = ttk.Entry(input_frame, textvariable=self.ip_network_var)
        self.ip_network_entry.grid(row=0, column=1, columnspan=2, sticky=tk.EW)

        ttk.Label(input_frame, text="Start Range:").grid(row=1, column=0, sticky=tk.W, pady=(10, 0))
        self.start_range_var = tk.StringVar(value="1")
        self.start_range_entry = ttk.Entry(input_frame, textvariable=self.start_range_var, width=10)
        self.start_range_entry.grid(row=1, column=1, sticky=tk.W, pady=(10, 0))
        
        ttk.Label(input_frame, text="End Range:").grid(row=1, column=1, sticky=tk.E, padx=(20,10))
        self.end_range_var = tk.StringVar(value="254")
        self.end_range_entry = ttk.Entry(input_frame, textvariable=self.end_range_var, width=10)
        self.end_range_entry.grid(row=1, column=2, sticky=tk.W, pady=(10, 0))

        # --- Controls ---
        self.start_button = ttk.Button(main_frame, text="Start Ping Sweep", command=self.start_ping_thread)
        self.start_button.pack(fill=tk.X, pady=(0, 15))

        # --- Results Display ---
        ttk.Label(main_frame, text="Results:", style="Header.TLabel").pack(anchor="w")
        self.results_text = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, font=("Consolas", 10), height=15)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.configure(state='disabled')
        
        # --- Tag configurations for colors ---
        self.results_text.tag_config('SUCCESS', foreground='green')
        self.results_text.tag_config('FAILED', foreground='red')
        self.results_text.tag_config('INFO', foreground='blue')

        # --- Status Bar ---
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # --- Queue for thread communication ---
        self.result_queue = queue.Queue()

    def update_results(self):
        """ Periodically check the queue and update the GUI """
        try:
            while True:
                message, tag = self.result_queue.get_nowait()
                self.results_text.configure(state='normal')
                self.results_text.insert(tk.END, message + '\n', tag)
                self.results_text.configure(state='disabled')
                self.results_text.see(tk.END) # Auto-scroll
        except queue.Empty:
            pass # No new messages
        finally:
            self.root.after(100, self.update_results)

    def start_ping_thread(self):
        """ Start the ping process in a separate thread to avoid freezing the GUI """
        self.start_button.config(state=tk.DISABLED)
        self.results_text.config(state='normal')
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state='disabled')
        
        try:
            network = self.ip_network_var.get().strip()
            start = int(self.start_range_var.get())
            end = int(self.end_range_var.get())
            if not network or start > end or start < 0 or end > 255:
                raise ValueError("Invalid input.")
        except ValueError:
            self.status_var.set("Error: Please check your input values.")
            self.start_button.config(state=tk.NORMAL)
            return

        # Start the background thread
        ping_thread = threading.Thread(
            target=self.ping_sweep,
            args=(network, start, end),
            daemon=True
        )
        ping_thread.start()
        self.update_results()

    def ping_sweep(self, network, start, end):
        """ The actual ping logic that runs in the background """
        self.status_var.set(f"Pinging from {network}.{start} to {network}.{end}...")
        self.result_queue.put((f"--- Starting Ping Sweep ---", 'INFO'))
        
        # Determine the correct ping command based on the OS
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        timeout_val = '500' if platform.system().lower() == 'windows' else '0.5'

        for i in range(start, end + 1):
            ip = f"{network}.{i}"
            command = ['ping', param, '1', timeout_param, timeout_val, ip]
            
            try:
                # --- THIS IS THE KEY FIX ---
                # Set creation flags to hide the console window on Windows
                creation_flags = 0
                if platform.system().lower() == 'windows':
                    creation_flags = subprocess.CREATE_NO_WINDOW
                
                result = subprocess.run(
                    command, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    text=True, 
                    check=True,
                    creationflags=creation_flags # Add this flag here
                )
                
                # For some OS, a 0 exit code doesn't guarantee a valid reply
                if "ttl" in result.stdout.lower():
                    self.result_queue.put((f"[SUCCESS] {ip} is UP", 'SUCCESS'))
                else:
                    self.result_queue.put((f"[FAILED]  {ip} is DOWN or timed out", 'FAILED'))

            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                self.result_queue.put((f"[FAILED]  {ip} is DOWN or unreachable", 'FAILED'))
        
        self.result_queue.put(("--- Ping Sweep Completed ---", 'INFO'))
        self.status_var.set("Ready")
        self.start_button.config(state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk()
    app = PingToolApp(root)
    root.mainloop()