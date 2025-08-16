#!/usr/bin/env python3
"""
HPTA Security Suite - Production Monitoring and Performance Tool
Advanced monitoring, logging, and performance optimization for production deployment

Team: HPTA Security Research Division - Chennai
Author: System Reliability Team
Date: January 2025
"""

import psutil
import time
import json
import requests
import logging
import os
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Any
import threading
from collections import deque
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class HPTAProductionMonitor:
    """Advanced production monitoring for HPTA Security Suite"""
    
    def __init__(self, config_file='monitoring_config.json'):
        self.config = self.load_config(config_file)
        self.metrics_history = deque(maxlen=1000)  # Keep last 1000 metrics
        self.alerts_sent = {}
        self.setup_logging()
        
    def load_config(self, config_file):
        """Load monitoring configuration"""
        default_config = {
            'app_url': 'http://localhost:5000',
            'check_interval': 60,  # seconds
            'cpu_threshold': 80,   # percentage
            'memory_threshold': 85,  # percentage
            'disk_threshold': 90,  # percentage
            'response_time_threshold': 5,  # seconds
            'email_notifications': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'recipients': []
            },
            'log_retention_days': 30,
            'backup_enabled': True,
            'backup_interval': 3600  # seconds
        }
        
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                # Merge with defaults
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
            else:
                # Create default config file
                with open(config_file, 'w') as f:
                    json.dump(default_config, f, indent=2)
                return default_config
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            return default_config
    
    def setup_logging(self):
        """Setup production logging"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler('hpta_monitor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Collect comprehensive system metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_available = memory.available / (1024**3)  # GB
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            disk_free = disk.free / (1024**3)  # GB
            
            # Network metrics
            net_io = psutil.net_io_counters()
            
            # Process count
            process_count = len(psutil.pids())
            
            # Load average (Unix only)
            try:
                load_avg = os.getloadavg()
            except AttributeError:
                load_avg = [0, 0, 0]  # Windows fallback
            
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'cpu': {
                    'percent': cpu_percent,
                    'count': cpu_count,
                    'load_avg_1m': load_avg[0],
                    'load_avg_5m': load_avg[1],
                    'load_avg_15m': load_avg[2]
                },
                'memory': {
                    'percent': memory_percent,
                    'available_gb': round(memory_available, 2),
                    'total_gb': round(memory.total / (1024**3), 2),
                    'used_gb': round(memory.used / (1024**3), 2)
                },
                'disk': {
                    'percent': disk_percent,
                    'free_gb': round(disk_free, 2),
                    'total_gb': round(disk.total / (1024**3), 2)
                },
                'network': {
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv
                },
                'system': {
                    'process_count': process_count,
                    'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
                }
            }
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error collecting system metrics: {e}")
            return {}
    
    def check_application_health(self) -> Dict[str, Any]:
        """Check HPTA application health and performance"""
        health_data = {
            'status': 'unknown',
            'response_time': 0,
            'error': None
        }
        
        try:
            start_time = time.time()
            response = requests.get(
                f"{self.config['app_url']}/health",
                timeout=10
            )
            response_time = time.time() - start_time
            
            health_data['response_time'] = round(response_time, 3)
            health_data['status_code'] = response.status_code
            
            if response.status_code == 200:
                health_data['status'] = 'healthy'
                try:
                    health_data['app_data'] = response.json()
                except:
                    health_data['app_data'] = {}
            else:
                health_data['status'] = 'unhealthy'
                health_data['error'] = f"HTTP {response.status_code}"
                
        except requests.exceptions.Timeout:
            health_data['status'] = 'timeout'
            health_data['error'] = 'Request timeout'
        except requests.exceptions.ConnectionError:
            health_data['status'] = 'offline'
            health_data['error'] = 'Connection refused'
        except Exception as e:
            health_data['status'] = 'error'
            health_data['error'] = str(e)
        
        return health_data
    
    def check_thresholds(self, metrics: Dict[str, Any]) -> List[str]:
        """Check if any metrics exceed thresholds"""
        alerts = []
        
        # CPU threshold
        if metrics.get('cpu', {}).get('percent', 0) > self.config['cpu_threshold']:
            alerts.append(f"High CPU usage: {metrics['cpu']['percent']:.1f}%")
        
        # Memory threshold  
        if metrics.get('memory', {}).get('percent', 0) > self.config['memory_threshold']:
            alerts.append(f"High memory usage: {metrics['memory']['percent']:.1f}%")
        
        # Disk threshold
        if metrics.get('disk', {}).get('percent', 0) > self.config['disk_threshold']:
            alerts.append(f"High disk usage: {metrics['disk']['percent']:.1f}%")
        
        return alerts
    
    def check_app_thresholds(self, health_data: Dict[str, Any]) -> List[str]:
        """Check application-specific thresholds"""
        alerts = []
        
        # Response time threshold
        if health_data.get('response_time', 0) > self.config['response_time_threshold']:
            alerts.append(f"Slow response time: {health_data['response_time']:.2f}s")
        
        # Application status
        if health_data.get('status') != 'healthy':
            alerts.append(f"Application unhealthy: {health_data.get('error', 'Unknown error')}")
        
        return alerts
    
    def send_alert_email(self, alerts: List[str]):
        """Send alert emails if configured"""
        if not self.config['email_notifications']['enabled']:
            return
        
        try:
            email_config = self.config['email_notifications']
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = email_config['username']
            msg['To'] = ', '.join(email_config['recipients'])
            msg['Subject'] = 'HPTA Security Suite - Production Alert'
            
            body = f"""
HPTA Security Suite Production Alert

Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Alerts:
{chr(10).join(f'• {alert}' for alert in alerts)}

Please investigate immediately.

---
HPTA Production Monitoring System
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
            server.starttls()
            server.login(email_config['username'], email_config['password'])
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Alert email sent to {len(email_config['recipients'])} recipients")
            
        except Exception as e:
            self.logger.error(f"Failed to send alert email: {e}")
    
    def generate_performance_report(self) -> str:
        """Generate performance report from metrics history"""
        if not self.metrics_history:
            return "No metrics data available"
        
        # Calculate averages
        cpu_avg = sum(m.get('system_metrics', {}).get('cpu', {}).get('percent', 0) 
                     for m in self.metrics_history) / len(self.metrics_history)
        memory_avg = sum(m.get('system_metrics', {}).get('memory', {}).get('percent', 0) 
                        for m in self.metrics_history) / len(self.metrics_history)
        response_time_avg = sum(m.get('app_health', {}).get('response_time', 0) 
                               for m in self.metrics_history) / len(self.metrics_history)
        
        # Find peaks
        cpu_peak = max(m.get('system_metrics', {}).get('cpu', {}).get('percent', 0) 
                      for m in self.metrics_history)
        memory_peak = max(m.get('system_metrics', {}).get('memory', {}).get('percent', 0) 
                         for m in self.metrics_history)
        
        report = f"""
HPTA Security Suite - Performance Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Data Points: {len(self.metrics_history)}

=== SYSTEM PERFORMANCE ===
CPU Usage:
  Average: {cpu_avg:.1f}%
  Peak: {cpu_peak:.1f}%

Memory Usage:
  Average: {memory_avg:.1f}%  
  Peak: {memory_peak:.1f}%

=== APPLICATION PERFORMANCE ===
Response Time:
  Average: {response_time_avg:.3f}s

=== HEALTH STATUS ===
Recent Status: {'Healthy' if self.metrics_history[-1].get('app_health', {}).get('status') == 'healthy' else 'Issues Detected'}

=== RECOMMENDATIONS ===
{'• Consider CPU optimization if peak usage > 90%' if cpu_peak > 90 else '✓ CPU usage within normal range'}
{'• Consider memory optimization if peak usage > 95%' if memory_peak > 95 else '✓ Memory usage within normal range'}  
{'• Optimize response times if average > 2s' if response_time_avg > 2 else '✓ Response times acceptable'}
        """
        
        return report
    
    def cleanup_old_logs(self):
        """Clean up old log files based on retention policy"""
        try:
            retention_days = self.config['log_retention_days']
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            
            log_files = ['hpta_monitor.log', 'hpta_security_suite.log']
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    file_stat = os.stat(log_file)
                    file_date = datetime.fromtimestamp(file_stat.st_mtime)
                    
                    if file_date < cutoff_date:
                        os.remove(log_file)
                        self.logger.info(f"Removed old log file: {log_file}")
                        
        except Exception as e:
            self.logger.error(f"Error cleaning up logs: {e}")
    
    def backup_application_data(self):
        """Backup critical application data"""
        if not self.config['backup_enabled']:
            return
        
        try:
            backup_dir = f"backups/{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            os.makedirs(backup_dir, exist_ok=True)
            
            # Backup database files
            db_files = ['HexaWebScanner/hexa_vuln_scanner.db']
            for db_file in db_files:
                if os.path.exists(db_file):
                    subprocess.run(['cp', db_file, backup_dir], check=True)
            
            # Backup configuration files
            config_files = ['hpta_security_suite.py', 'requirements_hpta.txt']
            for config_file in config_files:
                if os.path.exists(config_file):
                    subprocess.run(['cp', config_file, backup_dir], check=True)
            
            self.logger.info(f"Backup completed: {backup_dir}")
            
        except Exception as e:
            self.logger.error(f"Backup failed: {e}")
    
    def monitor_loop(self):
        """Main monitoring loop"""
        self.logger.info("Starting HPTA Production Monitor...")
        
        last_backup = 0
        
        while True:
            try:
                # Collect metrics
                system_metrics = self.get_system_metrics()
                app_health = self.check_application_health()
                
                # Store in history
                monitoring_data = {
                    'timestamp': datetime.now().isoformat(),
                    'system_metrics': system_metrics,
                    'app_health': app_health
                }
                self.metrics_history.append(monitoring_data)
                
                # Check thresholds
                system_alerts = self.check_thresholds(system_metrics)
                app_alerts = self.check_app_thresholds(app_health)
                all_alerts = system_alerts + app_alerts
                
                # Log current status
                self.logger.info(f"System: CPU {system_metrics.get('cpu', {}).get('percent', 0):.1f}%, "
                               f"Memory {system_metrics.get('memory', {}).get('percent', 0):.1f}%, "
                               f"App: {app_health.get('status', 'unknown')} "
                               f"({app_health.get('response_time', 0):.3f}s)")
                
                # Handle alerts
                if all_alerts:
                    for alert in all_alerts:
                        self.logger.warning(f"ALERT: {alert}")
                    
                    # Send email alerts (with rate limiting)
                    alert_key = '|'.join(sorted(all_alerts))
                    now = time.time()
                    if (alert_key not in self.alerts_sent or 
                        now - self.alerts_sent[alert_key] > 3600):  # 1 hour rate limit
                        self.send_alert_email(all_alerts)
                        self.alerts_sent[alert_key] = now
                
                # Periodic maintenance
                current_time = time.time()
                if current_time - last_backup > self.config['backup_interval']:
                    self.backup_application_data()
                    self.cleanup_old_logs()
                    last_backup = current_time
                
                # Wait for next check
                time.sleep(self.config['check_interval'])
                
            except KeyboardInterrupt:
                self.logger.info("Monitoring stopped by user")
                break
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)  # Wait before retrying
    
    def generate_dashboard_data(self):
        """Generate real-time dashboard data"""
        if not self.metrics_history:
            return {}
        
        latest = self.metrics_history[-1]
        
        # Get recent data for charts
        recent_cpu = [m.get('system_metrics', {}).get('cpu', {}).get('percent', 0) 
                     for m in list(self.metrics_history)[-20:]]
        recent_memory = [m.get('system_metrics', {}).get('memory', {}).get('percent', 0) 
                        for m in list(self.metrics_history)[-20:]]
        recent_response = [m.get('app_health', {}).get('response_time', 0) 
                          for m in list(self.metrics_history)[-20:]]
        
        dashboard_data = {
            'current': {
                'cpu_percent': latest.get('system_metrics', {}).get('cpu', {}).get('percent', 0),
                'memory_percent': latest.get('system_metrics', {}).get('memory', {}).get('percent', 0),
                'disk_percent': latest.get('system_metrics', {}).get('disk', {}).get('percent', 0),
                'app_status': latest.get('app_health', {}).get('status', 'unknown'),
                'response_time': latest.get('app_health', {}).get('response_time', 0)
            },
            'trends': {
                'cpu': recent_cpu,
                'memory': recent_memory,
                'response_time': recent_response
            },
            'timestamp': datetime.now().isoformat()
        }
        
        return dashboard_data

def main():
    """Main function for command line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='HPTA Security Suite Production Monitor')
    parser.add_argument('--config', default='monitoring_config.json', 
                       help='Configuration file path')
    parser.add_argument('--report', action='store_true',
                       help='Generate performance report and exit')
    parser.add_argument('--dashboard', action='store_true',
                       help='Generate dashboard data and exit')
    
    args = parser.parse_args()
    
    monitor = HPTAProductionMonitor(args.config)
    
    if args.report:
        print(monitor.generate_performance_report())
        return
    
    if args.dashboard:
        print(json.dumps(monitor.generate_dashboard_data(), indent=2))
        return
    
    # Start monitoring loop
    monitor.monitor_loop()

if __name__ == "__main__":
    main()
