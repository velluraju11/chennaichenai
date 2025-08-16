#!/usr/bin/env python3
"""
HPTA Unified Scanner Interface
Centralized interface for all HPTA security scanners
"""

import sys
import os
import subprocess
import json
import datetime
from pathlib import Path
from typing import Dict, Any, List

class HPTAUnifiedScanner:
    """Unified interface for HPTA security scanners"""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.scanners = {
            "ultra": {
                "script": "ultra_malware_scanner_v3.py",
                "description": "Ultra Malware Scanner V3.0 - Quantum AI Detection",
                "type": "malware"
            },
            "hexa": {
                "script": "run_hexawebscanner.py", 
                "description": "HexaWebScanner - Web Vulnerability Scanner",
                "type": "web"
            },
            "ryha": {
                "script": "run_ryha_malware_analyzer.py",
                "description": "RYHA Malware Analyzer - Advanced Malware Analysis",
                "type": "malware"
            },
            "reverse": {
                "script": "run_reverse_engineering.py",
                "description": "Reverse Engineering Analyzer - Binary Analysis",
                "type": "reverse"
            }
        }
        
        self.file_scanners = ["ultra", "ryha", "reverse"]
        self.url_scanners = ["hexa"]
        
    def run_scanner(self, scanner_name: str, target: str) -> Dict[str, Any]:
        """Run a specific scanner on a target"""
        
        if scanner_name not in self.scanners:
            raise ValueError(f"Unknown scanner: {scanner_name}")
        
        scanner_info = self.scanners[scanner_name]
        script_path = self.base_dir / scanner_info["script"]
        
        if not script_path.exists():
            raise FileNotFoundError(f"Scanner script not found: {script_path}")
        
        print(f">> Running {scanner_name.upper()} scanner...")
        print(f"Target: {target}")
        print(f"Scanner: {scanner_info['description']}")
        print("=" * 60)
        
        # Execute the scanner
        try:
            result = subprocess.run([
                sys.executable, str(script_path), target
            ], capture_output=True, text=True, timeout=300, cwd=str(script_path.parent))
            
            print("Scanner Output:")
            print(result.stdout)
            if result.stderr:
                print("\nScanner Errors:")
                print(result.stderr)
            print("=" * 60)
            
            # Process results - for our scanners, success is indicated by output content
            success_indicators = [
                "completed successfully",
                "analysis completed", 
                "scan completed",
                "threat level:",
                "quantum analysis completed",
                "confidence:",
                "threats detected:",
                "analysis time:"
            ]
            
            success = any(indicator in result.stdout.lower() for indicator in success_indicators)
            
            scan_result = {
                "scanner": scanner_name,
                "target": target,
                "timestamp": datetime.datetime.now().isoformat(),
                "success": success,
                "output": result.stdout,
                "errors": result.stderr,
                "return_code": result.returncode
            }
            
            if success:
                print(f"[SUCCESS] {scanner_name.upper()} scan completed!")
            else:
                print(f"[WARNING] {scanner_name.upper()} - check output for results")
            
            return scan_result
            
        except subprocess.TimeoutExpired:
            print(f"[TIMEOUT] {scanner_name.upper()} scan timed out (5 minutes)")
            return {
                "scanner": scanner_name,
                "target": target,
                "timestamp": datetime.datetime.now().isoformat(),
                "success": False,
                "output": "",
                "errors": "Scanner timed out after 5 minutes",
                "return_code": -1
            }
        except Exception as e:
            print(f"[ERROR] {scanner_name.upper()} scan failed: {e}")
            return {
                "scanner": scanner_name,
                "target": target,
                "timestamp": datetime.datetime.now().isoformat(),
                "success": False,
                "output": "",
                "errors": str(e),
                "return_code": -1
            }

    def run_all_scanners(self, target: str) -> Dict[str, Any]:
        """Run all appropriate scanners based on target type"""
        
        results = {
            "target": target,
            "timestamp": datetime.datetime.now().isoformat(),
            "scanners_run": [],
            "results": {},
            "success": True
        }
        
        # Determine scanner type based on target
        if os.path.isfile(target) or not target.startswith(('http://', 'https://')):
            print("File target detected - running malware scanners")
            scanners_to_run = self.file_scanners
        else:
            print("URL target detected - running web scanners")
            scanners_to_run = self.url_scanners
        
        for scanner_name in scanners_to_run:
            print(f"\nStarting {scanner_name.upper()}...")
            result = self.run_scanner(scanner_name, target)
            results["results"][scanner_name] = result
            results["scanners_run"].append(scanner_name)
            
            if result["success"]:
                print(f"[OK] {scanner_name.upper()} completed successfully")
            else:
                print(f"[WARN] {scanner_name.upper()} completed with warnings")
                results["success"] = False
        
        return results
    
    def save_results(self, results: Dict[str, Any], output_file: str = None):
        """Save scan results to JSON file"""
        
        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"hpta_scan_{timestamp}.json"
        
        output_path = self.base_dir / "reports" / output_file
        output_path.parent.mkdir(exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\nResults saved to: {output_path}")
        return output_path


def print_help():
    """Print help information"""
    print("""
HPTA Unified Scanner Interface
=============================

Usage:
    python unified_scanner.py <scanner> <target>
    python unified_scanner.py all <target>

Scanners:
    ultra   - Ultra Malware Scanner V3.0 (for files)
    hexa    - HexaWebScanner (for URLs)
    ryha    - RYHA Malware Analyzer (for files)
    reverse - Reverse Engineering Analyzer (for files)
    all     - Run all appropriate scanners

Examples:
    python unified_scanner.py ultra malware_sample.exe
    python unified_scanner.py hexa https://example.com
    python unified_scanner.py all suspicious_file.py
    """)


def main():
    if len(sys.argv) < 2:
        print_help()
        return
    
    if sys.argv[1] in ['-h', '--help', 'help']:
        print_help()
        return
    
    if len(sys.argv) < 3:
        print("Error: Target not specified")
        print_help()
        return
    
    command = sys.argv[1].lower()
    target = sys.argv[2]
    
    scanner = HPTAUnifiedScanner()
    
    try:
        if command == "all":
            results = scanner.run_all_scanners(target)
            scanner.save_results(results)
            
            # Print summary
            print(f"\n=== SCAN SUMMARY ===")
            print(f"Target: {target}")
            print(f"Scanners run: {', '.join(results['scanners_run'])}")
            for scanner_name, result in results["results"].items():
                status = "SUCCESS" if result["success"] else "CHECK OUTPUT"
                print(f"{scanner_name.upper()}: {status}")
                
        elif command in scanner.scanners:
            result = scanner.run_scanner(command, target)
            results = {"results": {command: result}, "success": result["success"]}
            scanner.save_results(results)
            status = "SUCCESS" if results["success"] else "CHECK OUTPUT"
            print(f"\n=== {command.upper()} RESULT: {status} ===")
        else:
            print(f"Error: Unknown scanner '{command}'")
            print_help()
            return
            
    except Exception as e:
        print(f"Scanner execution failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
