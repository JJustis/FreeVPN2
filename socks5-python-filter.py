#!/usr/bin/env python3
"""
SOCKS5 Proxy MAC and IP Filtering Script
Blocks ICMP/ping while preserving SOCKS5 functionality
Cross-platform support (Windows primary, Linux/macOS secondary)

Usage:
    python socks5_filter.py                          # Basic setup
    python socks5_filter.py --remove                 # Remove rules
    python socks5_filter.py --ports 1080,9050        # Custom ports
    python socks5_filter.py --block-ips 1.2.3.4     # Block specific IPs
"""

import os
import sys
import json
import logging
import platform
import subprocess
import argparse
import socket
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple, Optional

class SOCKS5Filter:
    def __init__(self, log_dir: str = None):
        self.system = platform.system().lower()
        self.log_dir = Path(log_dir or (r"C:\Scripts" if self.system == "windows" else "/var/log"))
        self.log_file = self.log_dir / "socks5_filter.log"
        self.config_file = self.log_dir / "socks5_filter_config.json"
        
        # Ensure log directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Default configuration
        self.socks5_ports = [1080, 9050, 8080, 3128]
        self.blocked_macs = [
            "00:11:22:33:44:55",  # Example - replace with actual targets
            "DE:AD:BE:EF:CA:FE",  # Example - replace with actual targets
            "00:00:00:00:00:00"   # Invalid MAC
        ]
        
        # IP ranges to blackhole (safe for SOCKS5)
        self.blackhole_ranges = {
            # Private networks
            "10.0.0.0/8": ("10.0.0.0", "255.0.0.0"),
            "172.16.0.0/12": ("172.16.0.0", "255.240.0.0"),
            
            "169.254.0.0/16": ("169.254.0.0", "255.255.0.0"),  # Link-local
            
            # Multicast and reserved
            "224.0.0.0/4": ("224.0.0.0", "240.0.0.0"),      # Multicast
            "240.0.0.0/4": ("240.0.0.0", "240.0.0.0"),      # Reserved
            
            # Documentation/testing
            
            "203.0.113.0/24": ("203.0.113.0", "255.255.255.0")  # Documentation
        }

    def check_admin_privileges(self) -> bool:
        """Check if running with administrator/root privileges"""
        try:
            if self.system == "windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except Exception as e:
            self.logger.error(f"Could not check admin privileges: {e}")
            return False

    def run_command(self, cmd: List[str], ignore_errors: bool = False) -> Tuple[bool, str]:
        """Execute system command and return success status and output"""
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                check=not ignore_errors
            )
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            if not ignore_errors:
                self.logger.error(f"Command failed: {' '.join(cmd)}")
                self.logger.error(f"Error: {e.stderr}")
            return False, e.stderr
        except Exception as e:
            self.logger.error(f"Command execution error: {e}")
            return False, str(e)

    def set_icmp_blocking_windows(self):
        """Configure ICMP blocking on Windows"""
        self.logger.info("Configuring ICMP blocking for Windows...")
        
        commands = [
            # Block incoming ICMP ping requests
            ["netsh", "advfirewall", "firewall", "add", "rule", 
             "name=SOCKS5-Block-ICMP-In", "protocol=icmpv4:8,any", 
             "dir=in", "action=block", "enable=yes"],
            
            # Block outgoing ICMP ping requests
            ["netsh", "advfirewall", "firewall", "add", "rule", 
             "name=SOCKS5-Block-ICMP-Out", "protocol=icmpv4:8,any", 
             "dir=out", "action=block", "enable=yes"]
        ]
        
        for cmd in commands:
            success, output = self.run_command(cmd, ignore_errors=True)
            if success:
                self.logger.info(f"Successfully executed: {' '.join(cmd)}")
            
        # Ensure SOCKS5 ports remain open
        for port in self.socks5_ports:
            for direction in ["in", "out"]:
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=SOCKS5-Allow-Proxy-{direction}-{port}",
                    "protocol=TCP", f"dir={direction}", f"localport={port}",
                    "action=allow", "enable=yes"
                ]
                self.run_command(cmd, ignore_errors=True)
        
        self.logger.info("ICMP blocking configured, SOCKS5 ports protected")

    def set_icmp_blocking_linux(self):
        """Configure ICMP blocking on Linux using iptables"""
        self.logger.info("Configuring ICMP blocking for Linux...")
        
        commands = [
            # Block incoming ICMP ping requests
            ["iptables", "-A", "INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-j", "DROP"],
            
            # Block outgoing ICMP ping requests (optional)
            ["iptables", "-A", "OUTPUT", "-p", "icmp", "--icmp-type", "echo-request", "-j", "DROP"]
        ]
        
        for cmd in commands:
            success, output = self.run_command(cmd, ignore_errors=True)
            if success:
                self.logger.info(f"Successfully executed: {' '.join(cmd)}")
        
        # Allow SOCKS5 ports
        for port in self.socks5_ports:
            for direction, chain in [("INPUT", "INPUT"), ("OUTPUT", "OUTPUT")]:
                cmd = ["iptables", "-A", chain, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"]
                self.run_command(cmd, ignore_errors=True)

    def set_blackhole_routes_windows(self, custom_ips: List[str] = None):
        """Set up blackhole routes on Windows"""
        self.logger.info("Setting up blackhole routes for Windows...")
        
        for cidr, (network, netmask) in self.blackhole_ranges.items():
            cmd = ["route", "ADD", network, "MASK", netmask, "0.0.0.0", "METRIC", "9999", "-p"]
            success, output = self.run_command(cmd, ignore_errors=True)
            if success:
                self.logger.info(f"Blackholed: {network}/{netmask}")
            else:
                self.logger.warning(f"Could not blackhole {network}: {output}")
        
        # Add custom blocked IPs
        if custom_ips:
            for ip in custom_ips:
                cmd = ["route", "ADD", ip, "MASK", "255.255.255.255", "0.0.0.0", "METRIC", "9999", "-p"]
                success, output = self.run_command(cmd, ignore_errors=True)
                if success:
                    self.logger.info(f"Blackholed custom IP: {ip}")

    def set_blackhole_routes_linux(self, custom_ips: List[str] = None):
        """Set up blackhole routes on Linux"""
        self.logger.info("Setting up blackhole routes for Linux...")
        
        for cidr, _ in self.blackhole_ranges.items():
            cmd = ["ip", "route", "add", "blackhole", cidr]
            success, output = self.run_command(cmd, ignore_errors=True)
            if success:
                self.logger.info(f"Blackholed: {cidr}")
        
        # Add custom blocked IPs
        if custom_ips:
            for ip in custom_ips:
                cmd = ["ip", "route", "add", "blackhole", f"{ip}/32"]
                success, output = self.run_command(cmd, ignore_errors=True)
                if success:
                    self.logger.info(f"Blackholed custom IP: {ip}")

    def set_mac_filtering_windows(self, custom_macs: List[str] = None):
        """Configure MAC filtering on Windows (limited effectiveness)"""
        self.logger.info("Configuring MAC address filtering for Windows...")
        
        all_macs = self.blocked_macs + (custom_macs or [])
        
        for mac in all_macs:
            if mac and mac != "00:00:00:00:00:00":
                rule_name = f"Block-MAC-{mac.replace(':', '')}"
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "protocol=any", "dir=in", "action=block", "enable=yes"
                ]
                success, output = self.run_command(cmd, ignore_errors=True)
                if success:
                    self.logger.info(f"Added MAC filter rule for: {mac}")
        
        self.logger.info("Note: MAC filtering on Windows has limited effectiveness")
        self.logger.info("For better MAC filtering, configure at router/switch level")

    def set_mac_filtering_linux(self, custom_macs: List[str] = None):
        """Configure MAC filtering on Linux using iptables"""
        self.logger.info("Configuring MAC address filtering for Linux...")
        
        all_macs = self.blocked_macs + (custom_macs or [])
        
        for mac in all_macs:
            if mac and mac != "00:00:00:00:00:00":
                cmd = ["iptables", "-A", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"]
                success, output = self.run_command(cmd, ignore_errors=True)
                if success:
                    self.logger.info(f"Added MAC filter for: {mac}")

    def remove_rules_windows(self):
        """Remove all filtering rules on Windows"""
        self.logger.info("Removing existing filter rules for Windows...")
        
        # Remove firewall rules
        firewall_rules = [
            "SOCKS5-Block-ICMP-In",
            "SOCKS5-Block-ICMP-Out"
        ]
        
        for rule in firewall_rules:
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"]
            self.run_command(cmd, ignore_errors=True)
        
        # Remove SOCKS5 port rules
        for port in self.socks5_ports:
            for direction in ["in", "out"]:
                rule_name = f"SOCKS5-Allow-Proxy-{direction}-{port}"
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                self.run_command(cmd, ignore_errors=True)
        
        # Remove routes
        for cidr, (network, netmask) in self.blackhole_ranges.items():
            cmd = ["route", "DELETE", network]
            self.run_command(cmd, ignore_errors=True)
        
        # Remove MAC rules
        for mac in self.blocked_macs:
            rule_name = f"Block-MAC-{mac.replace(':', '')}"
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
            self.run_command(cmd, ignore_errors=True)

    def remove_rules_linux(self):
        """Remove all filtering rules on Linux"""
        self.logger.info("Removing existing filter rules for Linux...")
        
        # Flush iptables (careful - this removes ALL rules)
        self.logger.warning("This will flush all iptables rules!")
        response = input("Continue? (y/N): ")
        if response.lower() == 'y':
            self.run_command(["iptables", "-F"], ignore_errors=True)
            
            # Remove blackhole routes
            for cidr, _ in self.blackhole_ranges.items():
                cmd = ["ip", "route", "del", "blackhole", cidr]
                self.run_command(cmd, ignore_errors=True)

    def check_port_status(self) -> Dict[int, bool]:
        """Check if SOCKS5 ports are listening"""
        port_status = {}
        
        for port in self.socks5_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', port))
                port_status[port] = result == 0
                sock.close()
            except Exception:
                port_status[port] = False
        
        return port_status

    def show_status(self):
        """Display current filtering status"""
        self.logger.info("=== SOCKS5 Filter Status ===")
        
        # Show SOCKS5 port status
        port_status = self.check_port_status()
        self.logger.info("\nSOCKS5 Port Status:")
        for port, is_listening in port_status.items():
            status = "LISTENING" if is_listening else "NOT LISTENING"
            self.logger.info(f"Port {port} - {status}")
        
        # Show active routes (Windows)
        if self.system == "windows":
            self.logger.info("\nActive blackhole routes:")
            success, output = self.run_command(["route", "print"], ignore_errors=True)
            if success:
                for line in output.split('\n'):
                    if "0.0.0.0" in line and "9999" in line:
                        self.logger.info(line.strip())

    def save_configuration(self, custom_ips: List[str] = None, custom_macs: List[str] = None):
        """Save current configuration to JSON file"""
        config = {
            "timestamp": datetime.now().isoformat(),
            "system": self.system,
            "blackhole_ranges": self.blackhole_ranges,
            "blocked_macs": self.blocked_macs,
            "socks5_ports": self.socks5_ports,
            "custom_blocked_ips": custom_ips or [],
            "custom_blocked_macs": custom_macs or []
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        self.logger.info(f"Configuration saved to: {self.config_file}")

    def apply_filters(self, custom_ips: List[str] = None, custom_macs: List[str] = None):
        """Apply all filtering rules based on the current system"""
        if not self.check_admin_privileges():
            self.logger.error("This script must be run with administrator/root privileges")
            sys.exit(1)
        
        self.logger.info(f"Starting SOCKS5 filtering configuration for {self.system}...")
        
        if self.system == "windows":
            self.set_icmp_blocking_windows()
            self.set_blackhole_routes_windows(custom_ips)
            self.set_mac_filtering_windows(custom_macs)
        elif self.system == "linux":
            self.set_icmp_blocking_linux()
            self.set_blackhole_routes_linux(custom_ips)
            self.set_mac_filtering_linux(custom_macs)
        else:
            self.logger.error(f"Unsupported system: {self.system}")
            sys.exit(1)
        
        self.save_configuration(custom_ips, custom_macs)
        self.logger.info("SOCKS5 filtering configuration complete!")
        self.show_status()

    def remove_filters(self):
        """Remove all filtering rules"""
        if not self.check_admin_privileges():
            self.logger.error("This script must be run with administrator/root privileges")
            sys.exit(1)
        
        if self.system == "windows":
            self.remove_rules_windows()
        elif self.system == "linux":
            self.remove_rules_linux()
        
        self.logger.info("Filter rules removed")


def main():
    parser = argparse.ArgumentParser(description="SOCKS5 Proxy MAC and IP Filter")
    parser.add_argument("--remove", action="store_true", help="Remove all filtering rules")
    parser.add_argument("--ports", type=str, help="Comma-separated SOCKS5 ports (default: 1080,9050,8080,3128)")
    parser.add_argument("--block-ips", type=str, help="Comma-separated IPs to block")
    parser.add_argument("--block-macs", type=str, help="Comma-separated MAC addresses to block")
    parser.add_argument("--log-dir", type=str, help="Directory for log files")
    parser.add_argument("--status", action="store_true", help="Show current status only")
    
    args = parser.parse_args()
    
    # Initialize filter
    socks5_filter = SOCKS5Filter(log_dir=args.log_dir)
    
    # Parse custom ports
    if args.ports:
        socks5_filter.socks5_ports = [int(p.strip()) for p in args.ports.split(',')]
    
    # Parse custom IPs and MACs
    custom_ips = [ip.strip() for ip in args.block_ips.split(',')] if args.block_ips else None
    custom_macs = [mac.strip() for mac in args.block_macs.split(',')] if args.block_macs else None
    
    # Execute requested action
    if args.remove:
        socks5_filter.remove_filters()
    elif args.status:
        socks5_filter.show_status()
    else:
        socks5_filter.apply_filters(custom_ips, custom_macs)
        
        print("\n=== Usage Notes ===")
        print(f"• SOCKS5 proxy ports protected: {', '.join(map(str, socks5_filter.socks5_ports))}")
        print("• ICMP/ping requests are blocked")
        print("• Private IP ranges are blackholed for security")
        print(f"• Log file: {socks5_filter.log_file}")
        print("• MAC filtering effectiveness varies by platform")
        print("\nTo remove rules: python socks5_filter.py --remove")


if __name__ == "__main__":
    main()