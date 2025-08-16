#!/usr/bin/env python3
"""
Ultra Malware Scanner Runner V3.0 (Quantum Nexus Edition)
Uses the new ultra-malware-scanner V3.0 with quantum-enhanced threat detection capabilities
Usage: python run_reverse_engineering.py <target_file>
"""

import sys
import os
import json
import subprocess
from datetime import datetime
from pathlib import Path

def run_ultra_malware_scanner(target_file):
    """Run ultra malware scanner with enhanced capabilities"""
    print(f"� Starting Quantum Ultra Malware Analysis V3.0 for: {target_file}")
    print("🚀 Nexus Edition - Quantum AI & Neural Networks Enabled")
    print("=" * 80)
    
    # Check if target file exists
    if not Path(target_file).exists():
        print(f"❌ Target file not found: {target_file}")
        return None
    
    # Change to ultra-malware-scanner directory (go up one level first)
    scanner_dir = Path("../ultra-malware-scanner")
    if not scanner_dir.exists():
        print("❌ ultra-malware-scanner folder not found!")
    
    original_dir = os.getcwd()
    
    try:
        os.chdir(scanner_dir)
        
        # Copy target file to analysis directory if needed
        target_path = Path(target_file)
        if target_path.is_absolute():
            # If absolute path, use directly
            analysis_target = str(target_path)
        else:
            # If relative path, convert to absolute path from original directory
            abs_target_path = os.path.abspath(os.path.join(original_dir, target_file))
            analysis_target = abs_target_path
        
        print("🧬 Running Quantum Ultra Malware Scanner V3.0 with neural networks...")
        print("🌐 APT attribution, AI analysis, and quantum threat detection enabled...")
        
        # Run the ultra malware scanner V3.0
        result = subprocess.run([
            sys.executable, "ultra_malware_scanner_v3.py", analysis_target
        ], capture_output=True, text=True, timeout=300)
        
        print("📊 Analysis Output:")
        print(result.stdout)
        
        if result.stderr:
            print("⚠️ Warnings/Errors:")
            print(result.stderr)
        
        # Look for generated reports
        report_files = list(Path(".").glob("*report*.json"))
        
        # Create unified report
        report_data = {
            "target_file": target_file,
            "timestamp": datetime.now().isoformat(),
            "analyzer": "UltraMalwareScanner",
            "scanner_version": "2.0.0 Elite Edition",
            "status": "completed" if result.returncode == 0 else "error",
            "output": result.stdout,
            "errors": result.stderr if result.stderr else None,
            "generated_reports": [str(f) for f in report_files],
            "capabilities": [
                "Universal file type scanning",
                "APT group attribution", 
                "Hacker geolocation tracking",
                "Advanced behavioral analysis",
                "Real-time threat intelligence"
            ]
        }
        
        # Try to read the latest JSON report if available
        if report_files:
            latest_report = max(report_files, key=lambda x: x.stat().st_mtime)
            try:
                with open(latest_report, 'r', encoding='utf-8') as f:
                    detailed_analysis = json.load(f)
                    report_data["detailed_analysis"] = detailed_analysis
                print(f"✅ Loaded detailed analysis from: {latest_report}")
            except Exception as e:
                print(f"⚠️ Could not read detailed report: {e}")
        
        return report_data
        
    except subprocess.TimeoutExpired:
        print("⚠️ Analysis timeout - process took too long")
        return None
    except Exception as e:
        print(f"❌ Error running ultra scanner: {e}")
        return None
    finally:
        os.chdir(original_dir)

def save_json_report(report_data):
    """Save unified JSON report"""
    if not report_data:
        return None
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ultra_malware_scan_report_{timestamp}.json"
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    print(f"📄 Ultra Scan Report saved: {filename}")
    return filename

def main():
    if len(sys.argv) != 2:
        print("🦠 Ultra Malware Scanner Runner")
        print("Usage: python run_reverse_engineering.py <target_file>")
        print("Example: python run_reverse_engineering.py suspicious_file.exe")
        print("Example: python run_reverse_engineering.py /path/to/malware_sample")
        print("")
        print("🚀 Features:")
        print("  • Universal file type scanning")
        print("  • APT group attribution")
        print("  • Hacker geolocation tracking") 
        print("  • Advanced behavioral analysis")
        print("  • Real-time threat intelligence")
        sys.exit(1)
    
    target_file = sys.argv[1]
    
    try:
        # Run the ultra scanner
        results = run_ultra_malware_scanner(target_file)
        
        if results:
            # Save unified report
            report_file = save_json_report(results)
            
            print("\n" + "=" * 80)
            print("🎉 Ultra Malware Analysis completed successfully!")
            print(f"📊 Detailed report saved to: {report_file}")
            
            # Show summary if detailed analysis available
            if "detailed_analysis" in results:
                analysis = results["detailed_analysis"]
                print("\n📋 Ultra Analysis Summary:")
                
                # Threat assessment
                threat_score = analysis.get("threat_score", {})
                if threat_score:
                    print(f"🚨 Threat Level: {threat_score.get('threat_level', 'UNKNOWN')}")
                    print(f"📊 Threat Score: {threat_score.get('total_score', 0)}/100")
                
                # Detected threats
                malware_families = analysis.get("signature_analysis", {}).get("malware_families", [])
                if malware_families:
                    print(f"🦠 Detected Threats: {len(malware_families)}")
                    for family in malware_families[:3]:  # Top 3
                        print(f"   • {family['family']} ({family['category']}) - {family['confidence']*100:.0f}%")
                
                # APT attribution
                if "threat_intelligence" in analysis:
                    apt_attributions = analysis["threat_intelligence"].get("apt_attribution", [])
                    if apt_attributions:
                        top_apt = apt_attributions[0]
                        print(f"🎯 Top APT Attribution: {top_apt['group']} ({top_apt['country']}) - {top_apt['confidence']*100:.1f}%")
            
            print("=" * 80)
        else:
            print("❌ Ultra Scanner failed to complete")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⚠️ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

if __name__ == "__main__":
    main()