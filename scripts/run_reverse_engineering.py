#!/usr/bin/env python3
"""
Unified Reverse Engineering Analyzer Runner
Uses existing reverseengineering folder capabilities with single command
Usage: python run_reverse_engineering.py <target_file>
"""

import sys
import os
import json
import subprocess
from datetime import datetime
from pathlib import Path

def run_reverse_engineering_analyzer(target_file):
    """Run reverse engineering analyzer with unified command"""
    print(f"🚀 Starting Reverse Engineering Analysis for: {target_file}")
    print("=" * 80)
    
    # Check if target file exists
    if not Path(target_file).exists():
        print(f"❌ Target file not found: {target_file}")
        return None
    
    # Change to reverseengineering directory
    re_dir = Path("reverseengineering")
    if not re_dir.exists():
        print("❌ reverseengineering folder not found!")
        return None
    
    original_dir = os.getcwd()
    
    try:
        os.chdir(re_dir)
        
        # Copy target file to analysis directory
        target_path = Path(target_file)
        if target_path.is_absolute():
            # If absolute path, copy to current directory
            import shutil
            local_target = target_path.name
            shutil.copy2(target_path, local_target)
            analysis_target = local_target
        else:
            # If relative path, adjust for new working directory
            analysis_target = os.path.join("..", target_file)
        
        print("🔍 Running comprehensive reverse engineering analysis...")
        
        # Run the Windows reverse analyzer
        result = subprocess.run([
            sys.executable, "windows_reverse_analyzer.py", analysis_target
        ], capture_output=True, text=True, timeout=300)
        
        print("📊 Analysis Output:")
        print(result.stdout)
        
        if result.stderr:
            print("⚠️ Warnings/Errors:")
            print(result.stderr)
        
        # Look for generated reports
        reports_dir = Path("reports")
        report_files = []
        
        if reports_dir.exists():
            # Find JSON reports
            json_reports = list(reports_dir.glob("*.json"))
            html_reports = list(reports_dir.glob("*.html"))
            
            report_files.extend(json_reports)
            report_files.extend(html_reports)
        
        # Create unified report
        report_data = {
            "target_file": target_file,
            "timestamp": datetime.now().isoformat(),
            "analyzer": "ReverseEngineeringAnalyzer",
            "status": "completed" if result.returncode == 0 else "error",
            "output": result.stdout,
            "errors": result.stderr if result.stderr else None,
            "generated_reports": [str(f) for f in report_files]
        }
        
        # Try to read the latest JSON report if available
        if json_reports:
            latest_report = max(json_reports, key=lambda x: x.stat().st_mtime)
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
        print(f"❌ Error running analyzer: {e}")
        return None
    finally:
        os.chdir(original_dir)

def save_json_report(report_data):
    """Save unified JSON report"""
    if not report_data:
        return None
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reverse_engineering_unified_report_{timestamp}.json"
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    print(f"📄 Unified JSON Report saved: {filename}")
    return filename

def main():
    if len(sys.argv) != 2:
        print("Usage: python run_reverse_engineering.py <target_file>")
        print("Example: python run_reverse_engineering.py suspicious_file.exe")
        print("Example: python run_reverse_engineering.py /path/to/binary")
        sys.exit(1)
    
    target_file = sys.argv[1]
    
    try:
        # Run the analyzer
        results = run_reverse_engineering_analyzer(target_file)
        
        if results:
            # Save unified report
            report_file = save_json_report(results)
            
            print("\n" + "=" * 80)
            print("✅ Reverse Engineering Analysis completed successfully!")
            print(f"📊 Unified report saved to: {report_file}")
            
            # Show summary if detailed analysis available
            if "detailed_analysis" in results:
                analysis = results["detailed_analysis"]
                print("\n📋 Analysis Summary:")
                if "risk_level" in analysis:
                    print(f"🚨 Risk Level: {analysis['risk_level']}")
                if "findings" in analysis:
                    print(f"🔍 Findings: {len(analysis['findings'])}")
                if "file_type" in analysis:
                    print(f"📄 File Type: {analysis['file_type']}")
            
            print("=" * 80)
        else:
            print("❌ Analyzer failed to complete")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⚠️ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()