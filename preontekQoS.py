import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import time
import threading
import subprocess
import socket
import psutil
import platform
import os
import sys
import json
from collections import deque
import speedtest
import ping3
import scapy.all as scapy
from datetime import datetime
import queue
import random
import re

class preontekQoS:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PreontekQoS Management System")
        self.root.geometry("1400x900")
        self.root.configure(bg="#1a237e")
        
        # Initialize variables
        self.monitoring = False
        self.traffic_data = {}
        self.ip_list = []
        self.bandwidth_history = deque(maxlen=60)
        self.latency_history = deque(maxlen=60)
        self.jitter_history = deque(maxlen=60)
        self.traffic_shaping_rules = {}
        self.active_monitors = {}
        self.interface = self.detect_wan_interface()
        self.cake_enabled = False
        self.fq_codel_enabled = False
        
        # Load settings
        self.load_settings()
        
        # Setup UI
        self.setup_menu()
        self.setup_dashboard()
        self.setup_command_interface()
        
        # Start background monitoring
        self.start_background_monitoring()
        
    def detect_wan_interface(self):
        """Detect the primary WAN interface"""
        try:
            if platform.system() == "Linux":
                # Find interface with default route
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'default via' in line:
                        return line.split()[4]
            else:
                # Windows/Mac - use first non-loopback interface
                interfaces = psutil.net_io_counters(pernic=True)
                for interface in interfaces:
                    if not interface.startswith('lo'):
                        return interface
        except Exception:
            return "eth0"  # Default fallback
        
    def load_settings(self):
        """Load settings from config file"""
        try:
            with open('lltms_config.json', 'r') as f:
                config = json.load(f)
                self.ip_list = config.get('ip_list', [])
                self.traffic_shaping_rules = config.get('traffic_shaping_rules', {})
                self.interface = config.get('interface', self.interface)
                self.cake_enabled = config.get('cake_enabled', False)
                self.fq_codel_enabled = config.get('fq_codel_enabled', False)
        except (FileNotFoundError, json.JSONDecodeError):
            self.traffic_shaping_rules = {
                'default': {
                    'priority': 'medium',
                    'bandwidth_limit': None,
                    'latency_threshold': 50,  # More aggressive default for low-latency
                    'jitter_threshold': 10    # New jitter threshold
                }
            }
    
    def save_settings(self):
        """Save settings to config file"""
        config = {
            'ip_list': self.ip_list,
            'traffic_shaping_rules': self.traffic_shaping_rules,
            'interface': self.interface,
            'cake_enabled': self.cake_enabled,
            'fq_codel_enabled': self.fq_codel_enabled
        }
        with open('lltms_config.json', 'w') as f:
            json.dump(config, f, indent=4)
    
    def setup_menu(self):
        """Setup the menu bar"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save Settings", command=self.save_settings)
        file_menu.add_command(label="Load Settings", command=self.load_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Refresh Dashboard", command=self.update_dashboard)
        view_menu.add_command(label="Show Traffic Logs", command=self.show_traffic_logs)
        view_menu.add_command(label="Show QoS Statistics", command=self.show_qos_stats)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Speed Test", command=self.run_speed_test)
        tools_menu.add_command(label="Ping Tool", command=self.show_ping_tool)
        tools_menu.add_command(label="Traceroute", command=self.show_traceroute_tool)
        tools_menu.add_command(label="IP Scanner", command=self.show_ip_scanner)
        tools_menu.add_command(label="Traffic Shaper", command=self.show_traffic_shaper)
        tools_menu.add_command(label="Network Commands", command=self.show_network_commands)
        tools_menu.add_command(label="Interface Settings", command=self.show_interface_settings)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # QoS menu
        qos_menu = tk.Menu(menubar, tearoff=0)
        qos_menu.add_command(label="Enable CAKE", command=self.enable_cake)
        qos_menu.add_command(label="Enable FQ-CoDel", command=self.enable_fq_codel)
        qos_menu.add_command(label="Disable QoS", command=self.disable_qos)
        qos_menu.add_separator()
        qos_menu.add_command(label="Optimize TCP", command=self.optimize_tcp)
        menubar.add_cascade(label="QoS", menu=qos_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def setup_dashboard(self):
        """Setup the main dashboard with enhanced metrics"""
        # Main frame
        main_frame = tk.Frame(self.root, bg="#1a237e")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - Monitoring controls
        left_panel = tk.Frame(main_frame, bg="#303f9f", width=300, padx=10, pady=10)
        left_panel.pack(side=tk.LEFT, fill=tk.Y)
        left_panel.pack_propagate(False)
        
        # Interface info
        interface_frame = tk.LabelFrame(left_panel, text="Network Interface", bg="#303f9f", fg="white")
        interface_frame.pack(fill=tk.X, pady=5)
        
        self.interface_label = tk.Label(interface_frame, text=f"Interface: {self.interface}", 
                                      bg="#303f9f", fg="white")
        self.interface_label.pack(pady=5)
        
        # QoS status
        qos_frame = tk.LabelFrame(left_panel, text="QoS Status", bg="#303f9f", fg="white")
        qos_frame.pack(fill=tk.X, pady=5)
        
        self.qos_status_label = tk.Label(qos_frame, text="QoS: Disabled", bg="#303f9f", fg="white")
        self.qos_status_label.pack(pady=5)
        
        # IP Management Section
        ip_mgmt_frame = tk.LabelFrame(left_panel, text="IP Address Management", bg="#303f9f", fg="white")
        ip_mgmt_frame.pack(fill=tk.X, pady=5)
        
        # IP Entry with Label
        ip_entry_frame = tk.Frame(ip_mgmt_frame, bg="#303f9f")
        ip_entry_frame.pack(fill=tk.X, pady=2)
        tk.Label(ip_entry_frame, text="IP Address:", bg="#303f9f", fg="white").pack(side=tk.LEFT)
        self.ip_entry = tk.Entry(ip_entry_frame)
        self.ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Add/Remove Buttons
        btn_frame = tk.Frame(ip_mgmt_frame, bg="#303f9f")
        btn_frame.pack(fill=tk.X, pady=5)
        add_ip_btn = tk.Button(btn_frame, text="Add IP", command=self.add_ip, bg="#4CAF50", fg="white")
        add_ip_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        remove_ip_btn = tk.Button(btn_frame, text="Remove IP", command=self.remove_ip, bg="#F44336", fg="white")
        remove_ip_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        
        # IP List with Scrollbar
        ip_list_frame = tk.LabelFrame(left_panel, text="Monitored IPs", bg="#303f9f", fg="white")
        ip_list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        scrollbar = tk.Scrollbar(ip_list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.ip_listbox = tk.Listbox(ip_list_frame, bg="#424242", fg="white", selectbackground="#1976d2",
                                   yscrollcommand=scrollbar.set)
        self.ip_listbox.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.ip_listbox.yview)
        
        self.update_ip_listbox()
        
        # Monitoring controls
        monitor_frame = tk.LabelFrame(left_panel, text="Monitoring Controls", bg="#303f9f", fg="white")
        monitor_frame.pack(fill=tk.X, pady=5)
        
        self.monitor_btn = tk.Button(monitor_frame, text="Start Monitoring", command=self.toggle_monitoring,
                                    bg="#2196F3", fg="white")
        self.monitor_btn.pack(fill=tk.X, pady=5)
        
        # Right panel - Stats and charts
        right_panel = tk.Frame(main_frame, bg="#1a237e")
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Top stats
        stats_frame = tk.Frame(right_panel, bg="#1a237e")
        stats_frame.pack(fill=tk.X, pady=5)
        
        # Current bandwidth
        self.bw_label = tk.Label(stats_frame, text="Bandwidth: 0 Mbps", font=("Arial", 12), 
                                bg="#1a237e", fg="white")
        self.bw_label.pack(side=tk.LEFT, padx=10)
        
        # Current latency
        self.latency_label = tk.Label(stats_frame, text="Latency: 0 ms", font=("Arial", 12), 
                                    bg="#1a237e", fg="white")
        self.latency_label.pack(side=tk.LEFT, padx=10)
        
        # Current jitter
        self.jitter_label = tk.Label(stats_frame, text="Jitter: 0 ms", font=("Arial", 12), 
                                   bg="#1a237e", fg="white")
        self.jitter_label.pack(side=tk.LEFT, padx=10)
        
        # Traffic status
        self.traffic_status = tk.Label(stats_frame, text="Traffic: Normal", font=("Arial", 12), 
                                      bg="#1a237e", fg="white")
        self.traffic_status.pack(side=tk.LEFT, padx=10)
        
        # Charts frame
        charts_frame = tk.Frame(right_panel, bg="#1a237e")
        charts_frame.pack(fill=tk.BOTH, expand=True)
        
        # Bandwidth chart
        bw_chart_frame = tk.Frame(charts_frame, bg="#1a237e")
        bw_chart_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.bw_fig, self.bw_ax = plt.subplots(figsize=(5, 3), facecolor="#1a237e")
        self.bw_ax.set_title("Bandwidth Usage (Mbps)", color="white")
        self.bw_ax.set_facecolor("#1a237e")
        self.bw_ax.tick_params(colors="white")
        self.bw_line, = self.bw_ax.plot([], [], 'b-')
        self.bw_ax.set_xlim(0, 60)
        self.bw_ax.set_ylim(0, 100)
        
        self.bw_canvas = FigureCanvasTkAgg(self.bw_fig, master=bw_chart_frame)
        self.bw_canvas.draw()
        self.bw_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Latency chart
        latency_chart_frame = tk.Frame(charts_frame, bg="#1a237e")
        latency_chart_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.latency_fig, self.latency_ax = plt.subplots(figsize=(5, 3), facecolor="#1a237e")
        self.latency_ax.set_title("Latency (ms)", color="white")
        self.latency_ax.set_facecolor("#1a237e")
        self.latency_ax.tick_params(colors="white")
        self.latency_line, = self.latency_ax.plot([], [], 'r-')
        self.latency_ax.set_xlim(0, 60)
        self.latency_ax.set_ylim(0, 100)  # More focused range for low-latency
        
        self.latency_canvas = FigureCanvasTkAgg(self.latency_fig, master=latency_chart_frame)
        self.latency_canvas.draw()
        self.latency_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Jitter chart
        jitter_chart_frame = tk.Frame(charts_frame, bg="#1a237e")
        jitter_chart_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.jitter_fig, self.jitter_ax = plt.subplots(figsize=(5, 3), facecolor="#1a237e")
        self.jitter_ax.set_title("Jitter (ms)", color="white")
        self.jitter_ax.set_facecolor("#1a237e")
        self.jitter_ax.tick_params(colors="white")
        self.jitter_line, = self.jitter_ax.plot([], [], 'g-')
        self.jitter_ax.set_xlim(0, 60)
        self.jitter_ax.set_ylim(0, 20)  # Focused range for jitter
        
        self.jitter_canvas = FigureCanvasTkAgg(self.jitter_fig, master=jitter_chart_frame)
        self.jitter_canvas.draw()
        self.jitter_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Bottom frame for queue and traffic distribution
        bottom_frame = tk.Frame(right_panel, bg="#1a237e")
        bottom_frame.pack(fill=tk.BOTH, expand=True)
        
        # Traffic pie chart
        pie_chart_frame = tk.Frame(bottom_frame, bg="#1a237e")
        pie_chart_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.pie_fig, self.pie_ax = plt.subplots(figsize=(5, 3), facecolor="#1a237e")
        self.pie_ax.set_title("Traffic Distribution", color="white")
        self.pie_ax.set_facecolor("#1a237e")
        
        self.pie_canvas = FigureCanvasTkAgg(self.pie_fig, master=pie_chart_frame)
        self.pie_canvas.draw()
        self.pie_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Queue status
        queue_frame = tk.LabelFrame(bottom_frame, text="Queue Status", bg="#1a237e", fg="white")
        queue_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.queue_text = tk.Text(queue_frame, height=8, bg="#424242", fg="white")
        self.queue_text.pack(fill=tk.BOTH, expand=True)
        self.queue_text.insert(tk.END, "Queue monitoring will appear here...")
    
    def setup_command_interface(self):
        """Setup the command line interface at the bottom"""
        cmd_frame = tk.Frame(self.root, bg="#0d47a1", height=150)
        cmd_frame.pack(fill=tk.X, side=tk.BOTTOM)
        cmd_frame.pack_propagate(False)
        
        tk.Label(cmd_frame, text="Command Interface", bg="#0d47a1", fg="white").pack(anchor=tk.W)
        
        self.cmd_entry = tk.Entry(cmd_frame, bg="#424242", fg="white", insertbackground="white")
        self.cmd_entry.pack(fill=tk.X, padx=5, pady=2)
        self.cmd_entry.bind("<Return>", self.execute_command)
        
        self.cmd_output = scrolledtext.ScrolledText(cmd_frame, bg="#424242", fg="white", height=5)
        self.cmd_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)
        self.cmd_output.insert(tk.END, "LLTMS> Type 'help' for available commands\n")
    
    def toggle_monitoring(self):
        """Toggle monitoring on/off"""
        self.monitoring = not self.monitoring
        
        if self.monitoring:
            self.monitor_btn.config(text="Stop Monitoring", bg="#F44336")
            self.cmd_output.insert(tk.END, "LLTMS> Monitoring started\n")
            self.initialize_qos()
        else:
            self.monitor_btn.config(text="Start Monitoring", bg="#2196F3")
            self.cmd_output.insert(tk.END, "LLTMS> Monitoring stopped\n")
    
    def initialize_qos(self):
        """Initialize QoS settings when monitoring starts"""
        if self.cake_enabled:
            self.enable_cake()
        elif self.fq_codel_enabled:
            self.enable_fq_codel()
    
    def add_ip(self):
        """Add an IP to the monitoring list"""
        ip = self.ip_entry.get().strip()
        
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address")
            return
            
        try:
            socket.inet_aton(ip)
        except socket.error:
            messagebox.showerror("Error", "Invalid IP address")
            return
            
        if ip not in self.ip_list:
            self.ip_list.append(ip)
            self.update_ip_listbox()
            self.ip_entry.delete(0, tk.END)
            self.cmd_output.insert(tk.END, f"preontek> Added IP: {ip}\n")
            self.save_settings()
        else:
            messagebox.showinfo("Info", "IP already in the list")
    
    def remove_ip(self):
        """Remove selected IP from the monitoring list"""
        selection = self.ip_listbox.curselection()
        
        if not selection:
            messagebox.showerror("Error", "Please select an IP to remove")
            return
            
        ip = self.ip_listbox.get(selection[0])
        self.ip_list.remove(ip)
        self.update_ip_listbox()
        self.cmd_output.insert(tk.END, f"LLTMS> Removed IP: {ip}\n")
        self.save_settings()
    
    def update_ip_listbox(self):
        """Update the IP listbox with current IPs"""
        self.ip_listbox.delete(0, tk.END)
        for ip in sorted(self.ip_list):
            self.ip_listbox.insert(tk.END, ip)
    
    def update_dashboard(self):
        """Update dashboard with current stats"""
        # Update bandwidth chart
        if self.bandwidth_history:
            self.bw_line.set_data(range(len(self.bandwidth_history)), list(self.bandwidth_history))
            self.bw_ax.relim()
            self.bw_ax.autoscale_view()
            self.bw_canvas.draw()
        
        # Update latency chart
        if self.latency_history:
            self.latency_line.set_data(range(len(self.latency_history)), list(self.latency_history))
            self.latency_ax.relim()
            self.latency_ax.autoscale_view()
            self.latency_canvas.draw()
        
        # Update jitter chart
        if self.jitter_history:
            self.jitter_line.set_data(range(len(self.jitter_history)), list(self.jitter_history))
            self.jitter_ax.relim()
            self.jitter_ax.autoscale_view()
            self.jitter_canvas.draw()
        
        # Update pie chart
        if self.traffic_data:
            labels = []
            sizes = []
            
            for ip, data in self.traffic_data.items():
                labels.append(ip)
                sizes.append(data.get('bytes', 0))
            
            if sizes:
                self.pie_ax.clear()
                self.pie_ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, 
                               textprops={'color': 'white'})
                self.pie_ax.set_title("Traffic Distribution", color="white")
                self.pie_ax.set_facecolor("#1a237e")
                self.pie_canvas.draw()
    
    def start_background_monitoring(self):
        """Start background monitoring thread"""
        def monitor():
            last_latency = None
            while True:
                if self.monitoring:
                    self.check_bandwidth()
                    current_latency = self.check_latency()
                    
                    # Calculate jitter (difference from last latency)
                    if last_latency is not None and current_latency is not None:
                        jitter = abs(current_latency - last_latency)
                        self.jitter_history.append(jitter)
                        self.jitter_label.config(text=f"Jitter: {jitter:.2f} ms")
                    
                    last_latency = current_latency
                    self.monitor_traffic()
                    self.update_queue_status()
                    self.apply_traffic_shaping()
                
                self.root.after(1000, self.update_dashboard)
                time.sleep(1)
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
    
    def check_bandwidth(self):
        """Check current bandwidth usage"""
        net_io = psutil.net_io_counters()
        bytes_sent = net_io.bytes_sent
        bytes_recv = net_io.bytes_recv
        
        time.sleep(1)
        
        net_io = psutil.net_io_counters()
        new_bytes_sent = net_io.bytes_sent
        new_bytes_recv = net_io.bytes_recv
        
        sent_speed = (new_bytes_sent - bytes_sent) / 1024 / 1024 * 8  # Mbps
        recv_speed = (new_bytes_recv - bytes_recv) / 1024 / 1024 * 8  # Mbps
        
        total_speed = sent_speed + recv_speed
        self.bandwidth_history.append(total_speed)
        
        self.bw_label.config(text=f"Bandwidth: {total_speed:.2f} Mbps")
        
        # Check for congestion
        if total_speed > 80:  # 80% of assumed 100Mbps capacity
            self.traffic_status.config(text="Traffic: Congested", fg="red")
        elif total_speed > 50:
            self.traffic_status.config(text="Traffic: Moderate", fg="orange")
        else:
            self.traffic_status.config(text="Traffic: Normal", fg="green")
    
    def check_latency(self):
        """Check latency to default gateway"""
        try:
            # Get default gateway
            if platform.system() == "Windows":
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                gateway = None
                for line in lines:
                    if "Default Gateway" in line:
                        gateway = line.split(":")[1].strip()
                        break
            else:  # Linux/Mac
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                gateway = None
                for line in lines:
                    if "default via" in line:
                        gateway = line.split()[2]
                        break
            
            if gateway:
                latency = ping3.ping(gateway, unit='ms')
                if latency:
                    self.latency_history.append(latency)
                    self.latency_label.config(text=f"Latency: {latency:.2f} ms")
                    
                    # Check for high latency
                    if latency > 50:  # More aggressive threshold for low-latency
                        self.traffic_status.config(text="Traffic: High Latency", fg="orange")
                    return latency
        except Exception as e:
            print(f"Latency check error: {e}")
        return None
    
    def monitor_traffic(self):
        """Monitor network traffic per IP"""
        try:
            # This is a simplified version - in a real implementation you would use
            # tools like ntopng, netflow, or similar to get per-IP traffic stats
            if not self.ip_list:
                return
                
            # Simulate some traffic data for demo purposes
            for ip in self.ip_list:
                if ip not in self.traffic_data:
                    self.traffic_data[ip] = {
                        'bytes': random.randint(100, 1000),
                        'packets': random.randint(10, 100),
                        'last_seen': datetime.now().isoformat(),
                        'latency': random.randint(5, 50),
                        'jitter': random.randint(1, 10)
                    }
                else:
                    # Simulate traffic changes
                    self.traffic_data[ip]['bytes'] += random.randint(10, 100)
                    self.traffic_data[ip]['packets'] += random.randint(1, 10)
                    self.traffic_data[ip]['last_seen'] = datetime.now().isoformat()
                    self.traffic_data[ip]['latency'] = random.randint(5, 50)
                    self.traffic_data[ip]['jitter'] = random.randint(1, 10)
        except Exception as e:
            print(f"Traffic monitoring error: {e}")
    
    def update_queue_status(self):
        """Update queue status display"""
        self.queue_text.delete(1.0, tk.END)
        
        if not self.ip_list:
            self.queue_text.insert(tk.END, "No IPs being monitored. Add IPs to see queue status.")
            return
            
        self.queue_text.insert(tk.END, "Current Queue Status:\n")
        self.queue_text.insert(tk.END, "IP Address\tPriority\tBW Limit\tLatency\tJitter\n")
        self.queue_text.insert(tk.END, "-"*70 + "\n")
        
        for ip in self.ip_list:
            priority = self.traffic_shaping_rules.get(ip, {}).get('priority', 'medium')
            bw_limit = self.traffic_shaping_rules.get(ip, {}).get('bandwidth_limit', 'None')
            latency = self.traffic_data.get(ip, {}).get('latency', random.randint(10, 50))
            jitter = self.traffic_data.get(ip, {}).get('jitter', random.randint(1, 10))
            
            self.queue_text.insert(tk.END, f"{ip}\t{priority}\t{bw_limit}\t{latency} ms\t{jitter} ms\n")
    
    def apply_traffic_shaping(self):
        """Apply traffic shaping rules with CAKE or FQ-CoDel"""
        if not self.monitoring:
            return
            
        try:
            # If no specific QoS is enabled, apply basic shaping
            if not self.cake_enabled and not self.fq_codel_enabled:
                self.apply_basic_shaping()
            
            # Apply traffic shaping rules for each IP
            for ip, rules in self.traffic_shaping_rules.items():
                priority = rules.get('priority', 'medium')
                bw_limit = rules.get('bandwidth_limit')
                latency_threshold = rules.get('latency_threshold', 50)
                jitter_threshold = rules.get('jitter_threshold', 10)
                
                # Get current metrics for this IP
                current_latency = self.traffic_data.get(ip, {}).get('latency', 0)
                current_jitter = self.traffic_data.get(ip, {}).get('jitter', 0)
                
                # Adjust shaping based on current conditions
                if current_latency > latency_threshold or current_jitter > jitter_threshold:
                    self.adjust_shaping_for_latency(ip, priority, bw_limit)
        except Exception as e:
            print(f"Traffic shaping error: {e}")
    
    def apply_basic_shaping(self):
        """Apply basic traffic shaping"""
        if platform.system() == "Linux":
            try:
                # Clear existing rules
                subprocess.run(['tc', 'qdisc', 'del', 'dev', self.interface, 'root'], 
                             stderr=subprocess.DEVNULL)
                
                # Apply basic HTB with 3 classes (high, medium, low)
                subprocess.run(['tc', 'qdisc', 'add', 'dev', self.interface, 'root', 'handle', '1:', 'htb'])
                subprocess.run(['tc', 'class', 'add', 'dev', self.interface, 'parent', '1:', 
                               'classid', '1:1', 'htb', 'rate', '100mbit', 'ceil', '100mbit'])
                
                # High priority class (40% guaranteed, 60% ceiling)
                subprocess.run(['tc', 'class', 'add', 'dev', self.interface, 'parent', '1:1', 
                               'classid', '1:10', 'htb', 'rate', '40mbit', 'ceil', '60mbit', 'prio', '0'])
                
                # Medium priority class (30% guaranteed, 40% ceiling)
                subprocess.run(['tc', 'class', 'add', 'dev', self.interface, 'parent', '1:1', 
                               'classid', '1:20', 'htb', 'rate', '30mbit', 'ceil', '40mbit', 'prio', '1'])
                
                # Low priority class (20% guaranteed, 30% ceiling)
                subprocess.run(['tc', 'class', 'add', 'dev', self.interface, 'parent', '1:1', 
                               'classid', '1:30', 'htb', 'rate', '20mbit', 'ceil', '30mbit', 'prio', '2'])
                
                # Apply SFQ to each class for fairness
                subprocess.run(['tc', 'qdisc', 'add', 'dev', self.interface, 'parent', '1:10', 'handle', '10:', 'sfq'])
                subprocess.run(['tc', 'qdisc', 'add', 'dev', self.interface, 'parent', '1:20', 'handle', '20:', 'sfq'])
                subprocess.run(['tc', 'qdisc', 'add', 'dev', self.interface, 'parent', '1:30', 'handle', '30:', 'sfq'])
                
                # Apply filters based on IP (simplified - in reality you'd need more complex matching)
                for ip, rules in self.traffic_shaping_rules.items():
                    priority = rules.get('priority', 'medium')
                    classid = '1:10' if priority == 'high' else '1:20' if priority == 'medium' else '1:30'
                    
                    subprocess.run(['tc', 'filter', 'add', 'dev', self.interface, 'protocol', 'ip', 
                                   'parent', '1:', 'prio', '1', 'u32', 'match', 'ip', 'dst', ip, 
                                   'flowid', classid])
            except Exception as e:
                print(f"Basic shaping error: {e}")
    
    def adjust_shaping_for_latency(self, ip, priority, bw_limit):
        """Adjust shaping parameters when latency/jitter thresholds are exceeded"""
        if platform.system() != "Linux":
            return
            
        try:
            # For high latency situations, we reduce the bandwidth ceiling
            if priority == 'high':
                new_ceil = bw_limit * 0.9 if bw_limit else '50mbit'
                subprocess.run(['tc', 'class', 'change', 'dev', self.interface, 
                               'classid', '1:10', 'htb', 'ceil', str(new_ceil)])
            elif priority == 'medium':
                new_ceil = bw_limit * 0.8 if bw_limit else '30mbit'
                subprocess.run(['tc', 'class', 'change', 'dev', self.interface, 
                               'classid', '1:20', 'htb', 'ceil', str(new_ceil)])
            else:  # low
                new_ceil = bw_limit * 0.7 if bw_limit else '15mbit'
                subprocess.run(['tc', 'class', 'change', 'dev', self.interface, 
                               'classid', '1:30', 'htb', 'ceil', str(new_ceil)])
        except Exception as e:
            print(f"Adjust shaping error: {e}")
    
    def enable_cake(self):
        """Enable CAKE QoS"""
        try:
            if platform.system() == "Linux":
                # Clear existing qdisc
                subprocess.run(['tc', 'qdisc', 'del', 'dev', self.interface, 'root'], 
                             stderr=subprocess.DEVNULL)
                
                # Apply CAKE with diffserv4 (prioritize ACK, EF, CS1, and default)
                subprocess.run(['tc', 'qdisc', 'add', 'dev', self.interface, 'root', 'cake', 
                               'bandwidth', '100mbit', 'diffserv4'])
                
                self.cake_enabled = True
                self.fq_codel_enabled = False
                self.qos_status_label.config(text="QoS: CAKE (diffserv4)")
                self.cmd_output.insert(tk.END, "LLTMS> Enabled CAKE QoS with diffserv4\n")
                self.save_settings()
            else:
                self.cmd_output.insert(tk.END, "LLTMS> CAKE is only available on Linux\n")
        except Exception as e:
            self.cmd_output.insert(tk.END, f"LLTMS> Error enabling CAKE: {e}\n")
    
    def enable_fq_codel(self):
        """Enable FQ-CoDel QoS"""
        try:
            if platform.system() == "Linux":
                # Clear existing qdisc
                subprocess.run(['tc', 'qdisc', 'del', 'dev', self.interface, 'root'], 
                             stderr=subprocess.DEVNULL)
                
                # Apply FQ-CoDel with ECN
                subprocess.run(['tc', 'qdisc', 'add', 'dev', self.interface, 'root', 'fq_codel', 
                               'ecn'])
                
                self.fq_codel_enabled = True
                self.cake_enabled = False
                self.qos_status_label.config(text="QoS: FQ-CoDel (ECN)")
                self.cmd_output.insert(tk.END, "LLTMS> Enabled FQ-CoDel QoS with ECN\n")
                self.save_settings()
            else:
                self.cmd_output.insert(tk.END, "LLTMS> FQ-CoDel is only available on Linux\n")
        except Exception as e:
            self.cmd_output.insert(tk.END, f"LLTMS> Error enabling FQ-CoDel: {e}\n")
    
    def disable_qos(self):
        """Disable QoS"""
        try:
            if platform.system() == "Linux":
                subprocess.run(['tc', 'qdisc', 'del', 'dev', self.interface, 'root'], 
                             stderr=subprocess.DEVNULL)
                
                self.cake_enabled = False
                self.fq_codel_enabled = False
                self.qos_status_label.config(text="QoS: Disabled")
                self.cmd_output.insert(tk.END, "LLTMS> Disabled QoS\n")
                self.save_settings()
            else:
                self.cmd_output.insert(tk.END, "LLTMS> QoS is only configurable on Linux\n")
        except Exception as e:
            self.cmd_output.insert(tk.END, f"LLTMS> Error disabling QoS: {e}\n")
    
    def optimize_tcp(self):
        """Optimize TCP stack for low latency"""
        try:
            if platform.system() == "Linux":
                # Enable BBR congestion control
                subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_congestion_control=bbr'])
                
                # Increase TCP buffer sizes
                subprocess.run(['sysctl', '-w', 'net.core.rmem_max=2500000'])
                subprocess.run(['sysctl', '-w', 'net.core.wmem_max=2500000'])
                subprocess.run(['sysctl', '-w', 'net.core.rmem_default=2500000'])
                subprocess.run(['sysctl', '-w', 'net.core.wmem_default=2500000'])
                
                # Enable ECN
                subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_ecn=1'])
                
                # Reduce TCP keepalive time
                subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_keepalive_time=60'])
                subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_keepalive_intvl=10'])
                subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_keepalive_probes=6'])
                
                self.cmd_output.insert(tk.END, "LLTMS> Optimized TCP stack for low latency\n")
            else:
                self.cmd_output.insert(tk.END, "LLTMS> TCP optimization is only available on Linux\n")
        except Exception as e:
            self.cmd_output.insert(tk.END, f"LLTMS> Error optimizing TCP: {e}\n")
    
    def execute_command(self, event=None):
        """Execute command line command"""
        cmd = self.cmd_entry.get().strip()
        self.cmd_entry.delete(0, tk.END)
        
        if not cmd:
            return
            
        self.cmd_output.insert(tk.END, f"LLTMS> {cmd}\n")
        
        # Parse command
        parts = cmd.split()
        command = parts[0].lower()
        args = parts[1:]
        
        try:
            if command == "help":
                self.show_help()
            elif command == "ping":
                if len(args) < 1:
                    self.cmd_output.insert(tk.END, "Usage: ping <ip>\n")
                else:
                    self.ping_ip(args[0])
            elif command == "scan":
                if len(args) < 1:
                    self.cmd_output.insert(tk.END, "Usage: scan <ip_range>\n")
                else:
                    self.scan_network(args[0])
            elif command == "tracert":
                if len(args) < 1:
                    self.cmd_output.insert(tk.END, "Usage: tracert <ip>\n")
                else:
                    self.traceroute(args[0])
            elif command == "add":
                if len(args) < 1:
                    self.cmd_output.insert(tk.END, "Usage: add <ip>\n")
                else:
                    self.ip_entry.insert(0, args[0])
                    self.add_ip()
            elif command == "remove":
                if len(args) < 1:
                    self.cmd_output.insert(tk.END, "Usage: remove <ip>\n")
                else:
                    # Select the IP in the listbox
                    for i, ip in enumerate(self.ip_list):
                        if ip == args[0]:
                            self.ip_listbox.selection_clear(0, tk.END)
                            self.ip_listbox.selection_set(i)
                            self.remove_ip()
                            break
                    else:
                        self.cmd_output.insert(tk.END, f"IP {args[0]} not found in list\n")
            elif command == "start":
                self.monitoring = True
                self.monitor_btn.config(text="Stop Monitoring", bg="#F44336")
                self.cmd_output.insert(tk.END, "Monitoring started\n")
            elif command == "stop":
                self.monitoring = False
                self.monitor_btn.config(text="Start Monitoring", bg="#2196F3")
                self.cmd_output.insert(tk.END, "Monitoring stopped\n")
            elif command == "clear":
                self.cmd_output.delete(1.0, tk.END)
                self.cmd_output.insert(tk.END, "LLTMS> ")
            elif command == "ip":
                if len(args) > 0 and args[0] == "r":
                    self.run_ip_route()
                else:
                    self.cmd_output.insert(tk.END, "Usage: ip r (show routing table)\n")
            elif command == "ss":
                if len(args) > 0 and args[0] == "-tunap":
                    self.run_ss_tunap()
                else:
                    self.cmd_output.insert(tk.END, "Usage: ss -tunap (show socket statistics)\n")
            elif command == "tc":
                if len(args) >= 7 and args[0] == "qdisc" and args[1] == "add" and args[2] == "dev":
                    interface = args[3]
                    if args[4] == "root" and args[5] == "cake":
                        bandwidth = args[6]
                        diffserv = args[7] if len(args) > 7 else ""
                        self.apply_cake_qdisc(interface, bandwidth, diffserv)
                    elif args[4] == "root" and args[5] == "fq_codel":
                        self.apply_fq_codel_qdisc(interface)
                    else:
                        self.cmd_output.insert(tk.END, "Usage: tc qdisc add dev <interface> root cake <bandwidth> [diffserv]\n")
                else:
                    self.cmd_output.insert(tk.END, "Usage: tc qdisc add dev <interface> root cake <bandwidth> [diffserv]\n")
            elif command == "cake":
                self.enable_cake()
            elif command == "fq_codel":
                self.enable_fq_codel()
            elif command == "disable_qos":
                self.disable_qos()
            elif command == "optimize_tcp":
                self.optimize_tcp()
            elif command == "set_interface":
                if len(args) < 1:
                    self.cmd_output.insert(tk.END, "Usage: set_interface <interface>\n")
                else:
                    self.interface = args[0]
                    self.interface_label.config(text=f"Interface: {self.interface}")
                    self.save_settings()
                    self.cmd_output.insert(tk.END, f"LLTMS> Interface set to {self.interface}\n")
            elif command == "exit":
                self.root.quit()
            else:
                self.cmd_output.insert(tk.END, f"Unknown command: {command}\n")
        except Exception as e:
            self.cmd_output.insert(tk.END, f"Error executing command: {e}\n")
        
        self.cmd_output.see(tk.END)
    
    def run_ip_route(self):
        """Execute 'ip r' command to show routing table"""
        try:
            if platform.system() == "Linux":
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
                self.cmd_output.insert(tk.END, result.stdout)
            else:
                result = subprocess.run(['route', 'print'], capture_output=True, text=True)
                self.cmd_output.insert(tk.END, result.stdout)
        except Exception as e:
            self.cmd_output.insert(tk.END, f"Error running ip route: {e}\n")
    
    def run_ss_tunap(self):
        """Execute 'ss -tunap' command to show socket statistics"""
        try:
            if platform.system() == "Linux":
                result = subprocess.run(['ss', '-tunap'], capture_output=True, text=True)
                self.cmd_output.insert(tk.END, result.stdout)
            else:
                result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
                self.cmd_output.insert(tk.END, result.stdout)
        except Exception as e:
            self.cmd_output.insert(tk.END, f"Error running ss -tunap: {e}\n")
    
    def apply_cake_qdisc(self, interface, bandwidth, diffserv=""):
        """Apply CAKE qdisc to interface"""
        try:
            if platform.system() == "Linux":
                cmd = ['tc', 'qdisc', 'add', 'dev', interface, 'root', 'cake', 'bandwidth', bandwidth]
                if diffserv:
                    cmd.append(diffserv)
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    self.cmd_output.insert(tk.END, f"Successfully applied CAKE qdisc to {interface}\n")
                    self.cake_enabled = True
                    self.fq_codel_enabled = False
                    self.qos_status_label.config(text=f"QoS: CAKE ({diffserv if diffserv else 'default'})")
                    self.save_settings()
                else:
                    self.cmd_output.insert(tk.END, f"Error applying CAKE qdisc: {result.stderr}\n")
            else:
                self.cmd_output.insert(tk.END, "CAKE qdisc is only available on Linux\n")
        except Exception as e:
            self.cmd_output.insert(tk.END, f"Error applying CAKE qdisc: {e}\n")
    
    def apply_fq_codel_qdisc(self, interface):
        """Apply FQ-CoDel qdisc to interface"""
        try:
            if platform.system() == "Linux":
                cmd = ['tc', 'qdisc', 'add', 'dev', interface, 'root', 'fq_codel', 'ecn']
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    self.cmd_output.insert(tk.END, f"Successfully applied FQ-CoDel qdisc to {interface}\n")
                    self.fq_codel_enabled = True
                    self.cake_enabled = False
                    self.qos_status_label.config(text="QoS: FQ-CoDel (ECN)")
                    self.save_settings()
                else:
                    self.cmd_output.insert(tk.END, f"Error applying FQ-CoDel qdisc: {result.stderr}\n")
            else:
                self.cmd_output.insert(tk.END, "FQ-CoDel qdisc is only available on Linux\n")
        except Exception as e:
            self.cmd_output.insert(tk.END, f"Error applying FQ-CoDel qdisc: {e}\n")
    
    def show_help(self):
        """Show help for command line interface"""
        help_text = """
Available commands:
  help                 - Show this help message
  ping <ip>            - Ping an IP address
  scan <ip_range>      - Scan a network range (e.g., 192.168.1.0/24)
  tracert <ip>         - Trace route to an IP address
  add <ip>             - Add an IP to monitor
  remove <ip>          - Remove an IP from monitoring
  start                - Start monitoring
  stop                 - Stop monitoring
  clear                - Clear the command output
  ip r                 - Show routing table
  ss -tunap            - Show socket statistics
  tc qdisc add dev eth0 root cake <bandwidth> [diffserv] - Apply CAKE qdisc
  tc qdisc add dev eth0 root fq_codel - Apply FQ-CoDel qdisc
  cake                 - Enable CAKE QoS
  fq_codel             - Enable FQ-CoDel QoS
  disable_qos          - Disable QoS
  optimize_tcp         - Optimize TCP stack for low latency
  set_interface <iface> - Set network interface
  exit                 - Exit the application
"""
        self.cmd_output.insert(tk.END, help_text)
    
    def ping_ip(self, ip):
        """Ping an IP address"""
        try:
            latency = ping3.ping(ip, unit='ms')
            if latency is not None:
                self.cmd_output.insert(tk.END, f"Ping to {ip}: {latency:.2f} ms\n")
            else:
                self.cmd_output.insert(tk.END, f"Ping to {ip} failed\n")
        except Exception as e:
            self.cmd_output.insert(tk.END, f"Ping error: {e}\n")
    
    def scan_network(self, ip_range):
        """Scan a network range for active IPs"""
        self.cmd_output.insert(tk.END, f"Scanning network {ip_range}...\n")
        self.cmd_output.insert(tk.END, "This may take a while...\n")
        
        try:
            # Use scapy for ARP scanning
            answered, _ = scapy.arping(ip_range, timeout=2, verbose=False)
            
            self.cmd_output.insert(tk.END, "Active IPs found:\n")
            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                self.cmd_output.insert(tk.END, f"  {ip}\t{mac}\n")
        except Exception as e:
            self.cmd_output.insert(tk.END, f"Scan error: {e}\n")
    
    def traceroute(self, ip):
        """Perform a traceroute to an IP"""
        self.cmd_output.insert(tk.END, f"Tracing route to {ip}...\n")
        
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['tracert', ip], capture_output=True, text=True)
            else:
                result = subprocess.run(['traceroute', ip], capture_output=True, text=True)
            
            self.cmd_output.insert(tk.END, result.stdout)
        except Exception as e:
            self.cmd_output.insert(tk.END, f"Traceroute error: {e}\n")
    
    def run_speed_test(self):
        """Run a speed test"""
        try:
            self.cmd_output.insert(tk.END, "Running speed test...\n")
            
            st = speedtest.Speedtest()
            st.get_best_server()
            
            download = st.download() / 1024 / 1024  # Mbps
            upload = st.upload() / 1024 / 1024  # Mbps
            
            self.cmd_output.insert(tk.END, 
                                 f"Download: {download:.2f} Mbps\nUpload: {upload:.2f} Mbps\n")
            
            # Update bandwidth history with download speed
            self.bandwidth_history.append(download)
        except Exception as e:
            self.cmd_output.insert(tk.END, f"Speed test error: {e}\n")
    
    def show_ping_tool(self):
        """Show ping tool window"""
        ping_window = tk.Toplevel(self.root)
        ping_window.title("Ping Tool")
        ping_window.geometry("400x300")
        ping_window.configure(bg="#1a237e")
        
        tk.Label(ping_window, text="IP Address:", bg="#1a237e", fg="white").pack(pady=5)
        ip_entry = tk.Entry(ping_window)
        ip_entry.pack(pady=5)
        
        result_text = tk.Text(ping_window, height=10, bg="#424242", fg="white")
        result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        def do_ping():
            ip = ip_entry.get().strip()
            if not ip:
                return
                
            result_text.insert(tk.END, f"Pinging {ip}...\n")
            
            try:
                for i in range(4):  # Send 4 pings
                    latency = ping3.ping(ip, unit='ms')
                    if latency is not None:
                        result_text.insert(tk.END, f"Reply from {ip}: time={latency:.2f}ms\n")
                    else:
                        result_text.insert(tk.END, f"Request timed out\n")
                    ping_window.update()
                    time.sleep(1)
            except Exception as e:
                result_text.insert(tk.END, f"Error: {e}\n")
        
        ping_btn = tk.Button(ping_window, text="Ping", command=do_ping)
        ping_btn.pack(pady=5)
    
    def show_traceroute_tool(self):
        """Show traceroute tool window"""
        traceroute_window = tk.Toplevel(self.root)
        traceroute_window.title("Traceroute Tool")
        traceroute_window.geometry("500x400")
        traceroute_window.configure(bg="#1a237e")
        
        tk.Label(traceroute_window, text="IP Address:", bg="#1a237e", fg="white").pack(pady=5)
        ip_entry = tk.Entry(traceroute_window)
        ip_entry.pack(pady=5)
        
        result_text = tk.Text(traceroute_window, height=15, bg="#424242", fg="white")
        result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        def do_traceroute():
            ip = ip_entry.get().strip()
            if not ip:
                return
                
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Tracing route to {ip}...\n")
            
            try:
                if platform.system() == "Windows":
                    result = subprocess.run(['tracert', ip], capture_output=True, text=True)
                else:
                    result = subprocess.run(['traceroute', ip], capture_output=True, text=True)
                
                result_text.insert(tk.END, result.stdout)
            except Exception as e:
                result_text.insert(tk.END, f"Error: {e}\n")
        
        traceroute_btn = tk.Button(traceroute_window, text="Trace", command=do_traceroute)
        traceroute_btn.pack(pady=5)
    
    def show_ip_scanner(self):
        """Show IP scanner tool window"""
        scanner_window = tk.Toplevel(self.root)
        scanner_window.title("IP Scanner")
        scanner_window.geometry("500x400")
        scanner_window.configure(bg="#1a237e")
        
        tk.Label(scanner_window, text="IP Range (e.g., 192.168.1.0/24):", 
                bg="#1a237e", fg="white").pack(pady=5)
        range_entry = tk.Entry(scanner_window)
        range_entry.pack(pady=5)
        
        result_text = tk.Text(scanner_window, height=15, bg="#424242", fg="white")
        result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        scan_btn = tk.Button(scanner_window, text="Scan", command=lambda: self.do_scan(range_entry, result_text))
        scan_btn.pack(pady=5)
    
    def show_network_commands(self):
        """Show network commands tool window"""
        commands_window = tk.Toplevel(self.root)
        commands_window.title("Preontek Network Commands")
        commands_window.geometry("600x500")
        commands_window.configure(bg="#1a237e")
        
        # Command selection
        cmd_frame = tk.Frame(commands_window, bg="#1a237e")
        cmd_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(cmd_frame, text="Select Command:", bg="#1a237e", fg="white").pack(side=tk.LEFT, padx=5)
        
        self.cmd_var = tk.StringVar()
        cmd_combo = ttk.Combobox(cmd_frame, textvariable=self.cmd_var, 
                                values=["ip r", "ss -tunap", "tc qdisc add dev eth0 root cake bandwidth 100mbit diffserv4",
                                       "tc qdisc add dev eth0 root fq_codel", "sysctl -w net.ipv4.tcp_congestion_control=bbr"])
        cmd_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        cmd_combo.current(0)
        
        # Parameters frame
        param_frame = tk.Frame(commands_window, bg="#1a237e")
        param_frame.pack(fill=tk.X, pady=5)
        
        self.param_label = tk.Label(param_frame, text="Parameters:", bg="#1a237e", fg="white")
        self.param_label.pack(side=tk.LEFT, padx=5)
        
        self.param_entry = tk.Entry(param_frame)
        self.param_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Result display
        result_frame = tk.LabelFrame(commands_window, text="Command Output", bg="#1a237e", fg="white")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, height=15, bg="#424242", fg="white")
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Buttons
        btn_frame = tk.Frame(commands_window, bg="#1a237e")
        btn_frame.pack(fill=tk.X, pady=5)
        
        run_btn = tk.Button(btn_frame, text="Run Command", command=self.run_network_command)
        run_btn.pack(side=tk.LEFT, padx=5)
        
        close_btn = tk.Button(btn_frame, text="Close", command=commands_window.destroy)
        close_btn.pack(side=tk.RIGHT, padx=5)
        
        # Update parameters based on command selection
        cmd_combo.bind("<<ComboboxSelected>>", self.update_command_params)
        self.update_command_params()
    
    def update_command_params(self, event=None):
        """Update parameters based on selected command"""
        cmd = self.cmd_var.get()
        
        if cmd == "ip r":
            self.param_label.config(text="Parameters:")
            self.param_entry.delete(0, tk.END)
            self.param_entry.config(state=tk.DISABLED)
        elif cmd == "ss -tunap":
            self.param_label.config(text="Parameters:")
            self.param_entry.delete(0, tk.END)
            self.param_entry.config(state=tk.DISABLED)
        elif cmd.startswith("tc qdisc"):
            self.param_label.config(text="Interface:")
            self.param_entry.config(state=tk.NORMAL)
            self.param_entry.delete(0, tk.END)
            self.param_entry.insert(0, self.interface)
        elif cmd.startswith("sysctl"):
            self.param_label.config(text="Parameter:")
            self.param_entry.config(state=tk.NORMAL)
            self.param_entry.delete(0, tk.END)
    
    def run_network_command(self):
        """Run the selected network command"""
        cmd = self.cmd_var.get()
        
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Executing: {cmd}\n")
        self.result_text.insert(tk.END, "="*50 + "\n")
        
        try:
            if cmd == "ip r":
                self.run_ip_route_gui()
            elif cmd == "ss -tunap":
                self.run_ss_tunap_gui()
            elif cmd.startswith("tc qdisc"):
                interface = self.param_entry.get().strip()
                if not interface:
                    self.result_text.insert(tk.END, "Error: Please specify an interface\n")
                    return
                
                if "cake" in cmd:
                    # Extract bandwidth from command template
                    bandwidth = "100mbit"
                    diffserv = "diffserv4"
                    self.apply_cake_qdisc_gui(interface, bandwidth, diffserv)
                elif "fq_codel" in cmd:
                    self.apply_fq_codel_qdisc_gui(interface)
            elif cmd.startswith("sysctl"):
                param = self.param_entry.get().strip()
                if not param:
                    self.result_text.insert(tk.END, "Error: Please specify a parameter\n")
                    return
                
                self.run_sysctl_gui(param)
        except Exception as e:
            self.result_text.insert(tk.END, f"Error: {e}\n")
    
    def run_ip_route_gui(self):
        """Run ip route command for GUI"""
        try:
            if platform.system() == "Linux":
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
                self.result_text.insert(tk.END, result.stdout)
            else:
                result = subprocess.run(['route', 'print'], capture_output=True, text=True)
                self.result_text.insert(tk.END, result.stdout)
        except Exception as e:
            self.result_text.insert(tk.END, f"Error running ip route: {e}\n")
    
    def run_ss_tunap_gui(self):
        """Run ss -tunap command for GUI"""
        try:
            if platform.system() == "Linux":
                result = subprocess.run(['ss', '-tunap'], capture_output=True, text=True)
                self.result_text.insert(tk.END, result.stdout)
            else:
                result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
                self.result_text.insert(tk.END, result.stdout)
        except Exception as e:
            self.result_text.insert(tk.END, f"Error running ss -tunap: {e}\n")
    
    def apply_cake_qdisc_gui(self, interface, bandwidth, diffserv=""):
        """Apply CAKE qdisc for GUI"""
        try:
            if platform.system() == "Linux":
                cmd = ['tc', 'qdisc', 'add', 'dev', interface, 'root', 'cake', 'bandwidth', bandwidth]
                if diffserv:
                    cmd.append(diffserv)
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    self.result_text.insert(tk.END, f"Successfully applied CAKE qdisc to {interface}\n")
                    self.cake_enabled = True
                    self.fq_codel_enabled = False
                    self.qos_status_label.config(text=f"QoS: CAKE ({diffserv if diffserv else 'default'})")
                    self.save_settings()
                else:
                    self.result_text.insert(tk.END, f"Error applying CAKE qdisc: {result.stderr}\n")
            else:
                self.result_text.insert(tk.END, "CAKE qdisc is only available on Linux\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error applying CAKE qdisc: {e}\n")
    
    def apply_fq_codel_qdisc_gui(self, interface):
        """Apply FQ-CoDel qdisc for GUI"""
        try:
            if platform.system() == "Linux":
                cmd = ['tc', 'qdisc', 'add', 'dev', interface, 'root', 'fq_codel', 'ecn']
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    self.result_text.insert(tk.END, f"Successfully applied FQ-CoDel qdisc to {interface}\n")
                    self.fq_codel_enabled = True
                    self.cake_enabled = False
                    self.qos_status_label.config(text="QoS: FQ-CoDel (ECN)")
                    self.save_settings()
                else:
                    self.result_text.insert(tk.END, f"Error applying FQ-CoDel qdisc: {result.stderr}\n")
            else:
                self.result_text.insert(tk.END, "FQ-CoDel qdisc is only available on Linux\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error applying FQ-CoDel qdisc: {e}\n")
    
    def run_sysctl_gui(self, param):
        """Run sysctl command for GUI"""
        try:
            if platform.system() == "Linux":
                cmd = ['sysctl', '-w', param]
                result = subprocess.run(cmd, capture_output=True, text=True)
                self.result_text.insert(tk.END, result.stdout)
            else:
                self.result_text.insert(tk.END, "sysctl is only available on Linux\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error running sysctl: {e}\n")
    
    def do_scan(self, range_entry, result_text):
        """Perform network scan"""
        ip_range = range_entry.get().strip()
        if not ip_range:
            return
            
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Scanning {ip_range}...\n")
        result_text.insert(tk.END, "This may take a while...\n")
        result_text.update()
        
        try:
            answered, _ = scapy.arping(ip_range, timeout=2, verbose=False)
            
            result_text.insert(tk.END, "\nActive IPs found:\n")
            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                result_text.insert(tk.END, f"  {ip}\t{mac}\n")
        except Exception as e:
            result_text.insert(tk.END, f"Scan error: {e}\n")
    
    def show_traffic_shaper(self):
        """Show traffic shaping configuration window"""
        shaper_window = tk.Toplevel(self.root)
        shaper_window.title("Traffic Shaper")
        shaper_window.geometry("600x500")
        shaper_window.configure(bg="#1a237e")
        
        # IP selection
        ip_frame = tk.Frame(shaper_window, bg="#1a237e")
        ip_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(ip_frame, text="IP Address:", bg="#1a237e", fg="white").pack(side=tk.LEFT, padx=5)
        
        ip_combo = ttk.Combobox(ip_frame, values=self.ip_list)
        ip_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        if self.ip_list:
            ip_combo.current(0)
        
        # Priority settings
        priority_frame = tk.Frame(shaper_window, bg="#1a237e")
        priority_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(priority_frame, text="Priority:", bg="#1a237e", fg="white").pack(side=tk.LEFT, padx=5)
        
        self.priority_var = tk.StringVar(value="medium")
        tk.Radiobutton(priority_frame, text="High", variable=self.priority_var, 
                      value="high", bg="#1a237e", fg="white", selectcolor="#424242").pack(side=tk.LEFT)
        tk.Radiobutton(priority_frame, text="Medium", variable=self.priority_var, 
                      value="medium", bg="#1a237e", fg="white", selectcolor="#424242").pack(side=tk.LEFT)
        tk.Radiobutton(priority_frame, text="Low", variable=self.priority_var, 
                      value="low", bg="#1a237e", fg="white", selectcolor="#424242").pack(side=tk.LEFT)
        
        # Bandwidth limit
        bw_frame = tk.Frame(shaper_window, bg="#1a237e")
        bw_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(bw_frame, text="Bandwidth Limit (Mbps):", bg="#1a237e", fg="white").pack(side=tk.LEFT, padx=5)
        
        self.bw_limit_entry = tk.Entry(bw_frame)
        self.bw_limit_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Latency threshold
        latency_frame = tk.Frame(shaper_window, bg="#1a237e")
        latency_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(latency_frame, text="Latency Threshold (ms):", bg="#1a237e", fg="white").pack(side=tk.LEFT, padx=5)
        
        self.latency_threshold_entry = tk.Entry(latency_frame)
        self.latency_threshold_entry.insert(0, "50")  # More aggressive default for low-latency
        self.latency_threshold_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Jitter threshold
        jitter_frame = tk.Frame(shaper_window, bg="#1a237e")
        jitter_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(jitter_frame, text="Jitter Threshold (ms):", bg="#1a237e", fg="white").pack(side=tk.LEFT, padx=5)
        
        self.jitter_threshold_entry = tk.Entry(jitter_frame)
        self.jitter_threshold_entry.insert(0, "10")
        self.jitter_threshold_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Current rules display
        rules_frame = tk.LabelFrame(shaper_window, text="Current Rules", bg="#1a237e", fg="white")
        rules_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.rules_text = tk.Text(rules_frame, height=10, bg="#424242", fg="white")
        self.rules_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.update_rules_display()
        
        # Buttons
        btn_frame = tk.Frame(shaper_window, bg="#1a237e")
        btn_frame.pack(fill=tk.X, pady=5)
        
        apply_btn = tk.Button(btn_frame, text="Apply", 
                             command=lambda: self.apply_shaping_rule(ip_combo.get()))
        apply_btn.pack(side=tk.LEFT, padx=5)
        
        remove_btn = tk.Button(btn_frame, text="Remove", 
                              command=lambda: self.remove_shaping_rule(ip_combo.get()))
        remove_btn.pack(side=tk.LEFT, padx=5)
        
        close_btn = tk.Button(btn_frame, text="Close", command=shaper_window.destroy)
        close_btn.pack(side=tk.RIGHT, padx=5)
    
    def apply_shaping_rule(self, ip):
        """Apply traffic shaping rule for an IP"""
        if not ip:
            messagebox.showerror("Error", "Please select an IP address")
            return
            
        try:
            priority = self.priority_var.get()
            bw_limit = self.bw_limit_entry.get()
            latency_threshold = self.latency_threshold_entry.get()
            jitter_threshold = self.jitter_threshold_entry.get()
            
            if bw_limit:
                try:
                    bw_limit = float(bw_limit)
                except ValueError:
                    messagebox.showerror("Error", "Invalid bandwidth limit")
                    return
                    
            try:
                latency_threshold = int(latency_threshold)
                jitter_threshold = int(jitter_threshold)
            except ValueError:
                messagebox.showerror("Error", "Invalid threshold value")
                return
                
            self.traffic_shaping_rules[ip] = {
                'priority': priority,
                'bandwidth_limit': bw_limit if bw_limit else None,
                'latency_threshold': latency_threshold,
                'jitter_threshold': jitter_threshold
            }
            
            self.save_settings()
            self.update_rules_display()
            messagebox.showinfo("Success", f"Traffic shaping rule applied for {ip}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to apply rule: {e}")
    
    def remove_shaping_rule(self, ip):
        """Remove traffic shaping rule for an IP"""
        if not ip:
            messagebox.showerror("Error", "Please select an IP address")
            return
            
        if ip in self.traffic_shaping_rules:
            del self.traffic_shaping_rules[ip]
            self.save_settings()
            self.update_rules_display()
            messagebox.showinfo("Success", f"Traffic shaping rule removed for {ip}")
        else:
            messagebox.showinfo("Info", f"No rules found for {ip}")
    
    def update_rules_display(self):
        """Update the rules display in the traffic shaper window"""
        self.rules_text.delete(1.0, tk.END)
        
        if not self.traffic_shaping_rules:
            self.rules_text.insert(tk.END, "No traffic shaping rules defined")
            return
            
        self.rules_text.insert(tk.END, "IP Address\tPriority\tBW Limit\tLatency\tJitter\n")
        self.rules_text.insert(tk.END, "-"*70 + "\n")
        
        for ip, rules in self.traffic_shaping_rules.items():
            priority = rules.get('priority', 'medium')
            bw_limit = rules.get('bandwidth_limit', 'None')
            latency = rules.get('latency_threshold', 50)
            jitter = rules.get('jitter_threshold', 10)
            
            self.rules_text.insert(tk.END, f"{ip}\t{priority}\t{bw_limit}\t{latency} ms\t{jitter} ms\n")
    
    def show_traffic_logs(self):
        """Show traffic logs window"""
        logs_window = tk.Toplevel(self.root)
        logs_window.title("Traffic Logs")
        logs_window.geometry("800x600")
        logs_window.configure(bg="#1a237e")
        
        logs_text = tk.Text(logs_window, bg="#424242", fg="white")
        logs_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        logs_text.insert(tk.END, "Traffic Logs\n")
        logs_text.insert(tk.END, "="*40 + "\n\n")
        
        for ip, data in self.traffic_data.items():
            logs_text.insert(tk.END, f"IP: {ip}\n")
            logs_text.insert(tk.END, f"  Bytes: {data.get('bytes', 0)}\n")
            logs_text.insert(tk.END, f"  Packets: {data.get('packets', 0)}\n")
            logs_text.insert(tk.END, f"  Latency: {data.get('latency', 0)} ms\n")
            logs_text.insert(tk.END, f"  Jitter: {data.get('jitter', 0)} ms\n")
            logs_text.insert(tk.END, f"  Last Seen: {data.get('last_seen', 'Never')}\n")
            logs_text.insert(tk.END, "-"*40 + "\n")
    
    def show_qos_stats(self):
        """Show QoS statistics window"""
        stats_window = tk.Toplevel(self.root)
        stats_window.title("QoS Statistics")
        stats_window.geometry("600x400")
        stats_window.configure(bg="#1a237e")
        
        stats_text = tk.Text(stats_window, bg="#424242", fg="white")
        stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        stats_text.insert(tk.END, "QoS Statistics\n")
        stats_text.insert(tk.END, "="*40 + "\n\n")
        
        if platform.system() == "Linux":
            try:
                # Show current qdisc
                result = subprocess.run(['tc', 'qdisc', 'show', 'dev', self.interface], 
                                      capture_output=True, text=True)
                stats_text.insert(tk.END, "Current Queue Discipline:\n")
                stats_text.insert(tk.END, result.stdout)
                stats_text.insert(tk.END, "\n")
                
                # Show class stats if available
                result = subprocess.run(['tc', '-s', 'class', 'show', 'dev', self.interface], 
                                      capture_output=True, text=True)
                stats_text.insert(tk.END, "Class Statistics:\n")
                stats_text.insert(tk.END, result.stdout)
                stats_text.insert(tk.END, "\n")
                
                # Show filter stats
                result = subprocess.run(['tc', '-s', 'filter', 'show', 'dev', self.interface], 
                                      capture_output=True, text=True)
                stats_text.insert(tk.END, "Filter Statistics:\n")
                stats_text.insert(tk.END, result.stdout)
            except Exception as e:
                stats_text.insert(tk.END, f"Error getting QoS stats: {e}\n")
        else:
            stats_text.insert(tk.END, "QoS statistics only available on Linux\n")
    
    def show_interface_settings(self):
        """Show network interface settings window"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Interface Settings")
        settings_window.geometry("500x300")
        settings_window.configure(bg="#1a237e")
        
        # Interface selection
        interface_frame = tk.Frame(settings_window, bg="#1a237e")
        interface_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(interface_frame, text="Network Interface:", bg="#1a237e", fg="white").pack(side=tk.LEFT, padx=5)
        
        # Get available interfaces
        interfaces = []
        try:
            if platform.system() == "Linux":
                result = subprocess.run(['ls', '/sys/class/net'], capture_output=True, text=True)
                interfaces = result.stdout.split()
            else:
                interfaces = list(psutil.net_io_counters(pernic=True).keys())
        except Exception:
            interfaces = ["eth0", "wlan0", "eno1"]  # Default suggestions
        
        self.interface_var = tk.StringVar(value=self.interface)
        interface_combo = ttk.Combobox(interface_frame, textvariable=self.interface_var, values=interfaces)
        interface_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Interface info
        info_frame = tk.LabelFrame(settings_window, text="Interface Information", bg="#1a237e", fg="white")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.interface_info = tk.Text(info_frame, height=8, bg="#424242", fg="white")
        self.interface_info.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.update_interface_info()
        
        # Buttons
        btn_frame = tk.Frame(settings_window, bg="#1a237e")
        btn_frame.pack(fill=tk.X, pady=5)
        
        apply_btn = tk.Button(btn_frame, text="Apply", command=self.apply_interface_settings)
        apply_btn.pack(side=tk.LEFT, padx=5)
        
        refresh_btn = tk.Button(btn_frame, text="Refresh", command=self.update_interface_info)
        refresh_btn.pack(side=tk.LEFT, padx=5)
        
        close_btn = tk.Button(btn_frame, text="Close", command=settings_window.destroy)
        close_btn.pack(side=tk.RIGHT, padx=5)
    
    def update_interface_info(self):
        """Update interface information display"""
        interface = self.interface_var.get()
        self.interface_info.delete(1.0, tk.END)
        
        try:
            # Get interface stats
            stats = psutil.net_io_counters(pernic=True).get(interface, None)
            if stats:
                self.interface_info.insert(tk.END, f"Interface: {interface}\n")
                self.interface_info.insert(tk.END, f"Bytes Sent: {stats.bytes_sent}\n")
                self.interface_info.insert(tk.END, f"Bytes Recv: {stats.bytes_recv}\n")
                self.interface_info.insert(tk.END, f"Packets Sent: {stats.packets_sent}\n")
                self.interface_info.insert(tk.END, f"Packets Recv: {stats.packets_recv}\n")
                self.interface_info.insert(tk.END, f"Errors: {stats.errin + stats.errout}\n")
                self.interface_info.insert(tk.END, f"Drops: {stats.dropin + stats.dropout}\n")
            
            # Get IP address
            if platform.system() == "Linux":
                result = subprocess.run(['ip', 'addr', 'show', interface], capture_output=True, text=True)
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if ip_match:
                    self.interface_info.insert(tk.END, f"IP Address: {ip_match.group(1)}\n")
            else:
                addrs = psutil.net_if_addrs().get(interface, [])
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        self.interface_info.insert(tk.END, f"IP Address: {addr.address}\n")
                        break
        except Exception as e:
            self.interface_info.insert(tk.END, f"Error getting interface info: {e}\n")
    
    def apply_interface_settings(self):
        """Apply interface settings"""
        new_interface = self.interface_var.get()
        if new_interface != self.interface:
            self.interface = new_interface
            self.interface_label.config(text=f"Interface: {self.interface}")
            self.save_settings()
            messagebox.showinfo("Success", f"Interface changed to {self.interface}")
    
    def show_documentation(self):
        """Show documentation window"""
        doc_window = tk.Toplevel(self.root)
        doc_window.title("Documentation")
        doc_window.geometry("600x400")
        doc_window.configure(bg="#1a237e")
        
        doc_text = tk.Text(doc_window, bg="#424242", fg="white", wrap=tk.WORD)
        doc_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        doc_text.insert(tk.END, "PreontekQoS Management System Documentation\n")
        doc_text.insert(tk.END, "="*70 + "\n\n")
        
        doc_text.insert(tk.END, "1. Dashboard\n")
        doc_text.insert(tk.END, "   - Displays real-time bandwidth, latency and jitter metrics\n")
        doc_text.insert(tk.END, "   - Shows traffic distribution by IP\n")
        doc_text.insert(tk.END, "   - Provides queue status information\n\n")
        
        doc_text.insert(tk.END, "2. QoS Features\n")
        doc_text.insert(tk.END, "   - CAKE (Common Applications Kept Enhanced) for intelligent queue management\n")
        doc_text.insert(tk.END, "   - FQ-CoDel (Fair Queuing with Controlled Delay) for fair bandwidth distribution\n")
        doc_text.insert(tk.END, "   - TCP optimization for low-latency applications\n\n")
        
        doc_text.insert(tk.END, "3. Traffic Shaping\n")
        doc_text.insert(tk.END, "   - Set priority levels (high, medium, low)\n")
        doc_text.insert(tk.END, "   - Configure bandwidth limits\n")
        doc_text.insert(tk.END, "   - Set latency and jitter thresholds\n\n")
        
        doc_text.insert(tk.END, "4. Command Interface\n")
        doc_text.insert(tk.END, "   - Execute network commands (ping, scan, tracert)\n")
        doc_text.insert(tk.END, "   - Manage QoS settings\n")
        doc_text.insert(tk.END, "   - Type 'help' for available commands\n")
        
        doc_text.config(state=tk.DISABLED)
    
    def show_about(self):
        """Show about window"""
        about_window = tk.Toplevel(self.root)
        about_window.title("About Preontek")
        about_window.geometry("400x300")
        about_window.configure(bg="#1a237e")
        
        about_text = tk.Text(about_window, bg="#424242", fg="white", wrap=tk.WORD)
        about_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        about_text.insert(tk.END, "PreontekQoS Low-Latency Traffic Management System\n")
        about_text.insert(tk.END, "Version 2.0\n\n")
        about_text.insert(tk.END, "A comprehensive tool for monitoring and shaping network traffic with a focus on reducing latency and jitter.\n\n")
        about_text.insert(tk.END, "Features:\n")
        about_text.insert(tk.END, "- Real-time traffic monitoring\n")
        about_text.insert(tk.END, "- Bandwidth, latency and jitter tracking\n")
        about_text.insert(tk.END, "- Advanced QoS with CAKE and FQ-CoDel\n")
        about_text.insert(tk.END, "- Per-IP traffic shaping\n")
        about_text.insert(tk.END, "- Queue management\n")
        about_text.insert(tk.END, "- Command line interface\n\n")
        about_text.insert(tk.END, "© 2025 preontek")
        
        about_text.config(state=tk.DISABLED)
    
    def run(self):
        """Run the application"""
        self.root.mainloop()

if __name__ == "__main__":
    app =  preontekQoS()
    app.run()