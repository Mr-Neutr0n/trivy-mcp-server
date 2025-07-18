# server.py
import subprocess
import json
import os
import re
from typing import Any, Dict, List, Optional
from pathlib import Path

from mcp.server import FastMCP

mcp = FastMCP("trivy-security-scanner")

def detect_package_manager(workspace: str) -> Optional[str]:
    """Detect the package manager used in the workspace."""
    workspace_path = Path(workspace)
    
    # Check for common package manager files
    if (workspace_path / "package.json").exists():
        return "npm"
    elif (workspace_path / "requirements.txt").exists() or (workspace_path / "pyproject.toml").exists():
        return "python"
    elif (workspace_path / "go.mod").exists():
        return "go"
    elif (workspace_path / "Cargo.toml").exists():
        return "rust"
    elif (workspace_path / "composer.json").exists():
        return "php"
    elif (workspace_path / "Gemfile").exists():
        return "ruby"
    
    return None

def update_requirements_txt(workspace: str, pkg_name: str, target_version: str) -> bool:
    """Update a package version in requirements.txt file."""
    requirements_path = os.path.join(workspace, "requirements.txt")
    
    if not os.path.exists(requirements_path):
        return False
    
    try:
        with open(requirements_path, 'r') as f:
            lines = f.readlines()
        
        updated = False
        new_lines = []
        
        for line in lines:
            line = line.strip()
            if line.startswith(pkg_name):
                # Handle various requirement formats like pkg==version, pkg>=version, etc.
                new_line = f"{pkg_name}>={target_version}\n"
                new_lines.append(new_line)
                updated = True
            else:
                new_lines.append(line + '\n' if line else '\n')
        
        if updated:
            with open(requirements_path, 'w') as f:
                f.writelines(new_lines)
            return True
        
    except Exception as e:
        print(f"Error updating requirements.txt: {e}")
        return False
    
    return False

@mcp.tool(
    description="Scans a directory for security vulnerabilities using Trivy."
)
async def scan_project(
    workspace: str, 
    severity_filter: str = "", 
    include_fixed: bool = False
) -> Dict[str, Any]:
    """
    Scans a given workspace directory for security vulnerabilities using Trivy.
    
    Args:
        workspace: The directory path to scan
        severity_filter: Comma-separated severity levels to include (e.g., 'HIGH,CRITICAL'). Default: all severities
        include_fixed: Whether to include already fixed vulnerabilities in results
    """
    if not os.path.isdir(workspace):
        return {
            "success": False,
            "error": f"Workspace directory '{workspace}' not found."
        }

    try:
        # Build Trivy command
        command = ["trivy", "fs", "--format", "json"]
        
        # Add severity filter if specified
        if severity_filter:
            command.extend(["--severity", severity_filter])
        
        # Add ignore-unfixed flag if we don't want fixed vulnerabilities
        if not include_fixed:
            command.append("--ignore-unfixed")
        
        command.append(workspace)
        
        # Check if Trivy is installed
        try:
            subprocess.run(["trivy", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            return {
                "success": False,
                "error": "Trivy is not installed or not available in PATH. Please install Trivy first."
            }

        process = subprocess.run(command, capture_output=True, text=True, check=True)

        if not process.stdout.strip():
            return {
                "success": True,
                "message": f"No vulnerabilities found in {workspace}.",
                "vulnerabilities": [],
                "scan_summary": {"total_vulnerabilities": 0}
            }

        trivy_output = json.loads(process.stdout)

        # Extract relevant information
        vulnerabilities = []
        total_vulns = 0
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        
        if trivy_output and "Results" in trivy_output:
            for result in trivy_output["Results"]:
                target = result.get("Target", "Unknown")
                if "Vulnerabilities" in result:
                    for vuln in result["Vulnerabilities"]:
                        severity = vuln.get("Severity", "UNKNOWN")
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                        total_vulns += 1
                        
                        vulnerabilities.append({
                            "target": target,
                            "vulnerability_id": vuln.get("VulnerabilityID"),
                            "package_name": vuln.get("PkgName"),
                            "installed_version": vuln.get("InstalledVersion"),
                            "fixed_version": vuln.get("FixedVersion"),
                            "severity": severity,
                            "title": vuln.get("Title"),
                            "description": vuln.get("Description"),
                            "primary_url": vuln.get("PrimaryURL"),
                            "cvss_score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score") if vuln.get("CVSS") else None
                        })
        
        scan_summary = {
            "total_vulnerabilities": total_vulns,
            "severity_breakdown": severity_counts,
            "workspace": workspace,
            "package_manager": detect_package_manager(workspace)
        }
        
        if not vulnerabilities:
            return {
                "success": True,
                "message": f"No vulnerabilities found in {workspace}.",
                "vulnerabilities": [],
                "scan_summary": scan_summary
            }
        else:
            return {
                "success": True,
                "message": f"{total_vulns} vulnerabilities found in {workspace}",
                "vulnerabilities": vulnerabilities,
                "scan_summary": scan_summary
            }

    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "error": f"Trivy scan failed: {e.stderr}"
        }
    except json.JSONDecodeError:
        return {
            "success": False,
            "error": "Failed to parse Trivy JSON output."
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"An unexpected error occurred: {str(e)}"
        }

@mcp.tool(
    description="Attempts to fix a vulnerability by updating a package to a secure version."
)
async def fix_vulnerability(
    workspace: str, 
    pkg_name: str, 
    target_version: str, 
    dry_run: bool = False
) -> Dict[str, Any]:
    """
    Attempts to fix a vulnerability by updating a package to a secure version.
    
    Args:
        workspace: The directory to modify
        pkg_name: Name of the package to update
        target_version: Version to update to
        dry_run: If true, only simulate the fix without making actual changes
    """
    if not os.path.isdir(workspace):
        return {
            "success": False,
            "error": f"Workspace directory '{workspace}' not found."
        }

    package_manager = detect_package_manager(workspace)
    
    if not package_manager:
        return {
            "success": False,
            "error": f"No supported package manager detected in '{workspace}'."
        }

    if dry_run:
        return {
            "success": True,
            "message": f"DRY RUN: Would update package '{pkg_name}' to version '{target_version}' using {package_manager}",
            "package_name": pkg_name,
            "target_version": target_version,
            "package_manager": package_manager,
            "dry_run": True
        }

    try:
        if package_manager == "python":
            # Update requirements.txt if it exists
            if update_requirements_txt(workspace, pkg_name, target_version):
                # Run pip install to update the package
                command = ["pip", "install", f"{pkg_name}>={target_version}"]
                process = subprocess.run(command, cwd=workspace, capture_output=True, text=True, check=True)
                
                return {
                    "success": True,
                    "message": f"Successfully updated package '{pkg_name}' to version '{target_version}'",
                    "package_name": pkg_name,
                    "target_version": target_version,
                    "package_manager": package_manager,
                    "output": process.stdout
                }
            else:
                return {
                    "success": False,
                    "error": f"Failed to update requirements.txt for package '{pkg_name}'"
                }
                
        elif package_manager == "npm":
            command = ["npm", "install", f"{pkg_name}@{target_version}"]
            process = subprocess.run(command, cwd=workspace, capture_output=True, text=True, check=True)
            
            return {
                "success": True,
                "message": f"Successfully updated package '{pkg_name}' to version '{target_version}'",
                "package_name": pkg_name,
                "target_version": target_version,
                "package_manager": package_manager,
                "output": process.stdout
            }
            
        elif package_manager == "go":
            command = ["go", "get", f"{pkg_name}@v{target_version}"]
            process = subprocess.run(command, cwd=workspace, capture_output=True, text=True, check=True)
            
            return {
                "success": True,
                "message": f"Successfully updated package '{pkg_name}' to version '{target_version}'",
                "package_name": pkg_name,
                "target_version": target_version,
                "package_manager": package_manager,
                "output": process.stdout
            }
            
        else:
            return {
                "success": False,
                "error": f"Automated fix for '{package_manager}' package manager not yet implemented."
            }
            
    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "error": f"Failed to update package: {e.stderr}",
            "stdout": e.stdout if hasattr(e, 'stdout') else None
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"An unexpected error occurred during fix: {str(e)}"
        }

@mcp.tool(
    description="Get detailed information about a specific vulnerability."
)
async def get_vulnerability_details(vulnerability_id: str) -> Dict[str, Any]:
    """
    Get detailed information about a specific vulnerability using Trivy.
    
    Args:
        vulnerability_id: The CVE ID or vulnerability identifier (e.g., CVE-2021-44228)
    """
    try:
        # Note: Trivy doesn't have a direct vulnerability lookup command in all versions
        # This would typically integrate with a vulnerability database API
        # For now, we'll return a helpful message with external resources
        return {
            "success": True,
            "vulnerability_id": vulnerability_id,
            "message": f"Direct vulnerability lookup not available in current Trivy version",
            "external_resources": {
                "nvd": f"https://nvd.nist.gov/vuln/detail/{vulnerability_id}",
                "mitre": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={vulnerability_id}",
                "github_advisory": f"https://github.com/advisories?query={vulnerability_id}",
                "trivy_db": "https://github.com/aquasecurity/trivy-db"
            },
            "suggestion": "Use these external resources to research vulnerability details, or run a scan to see if this vulnerability affects your projects."
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"An unexpected error occurred: {str(e)}"
        }

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Trivy Security Scanner MCP Server")
    parser.add_argument("--port", type=int, default=54321, help="Port to launch the MCP server on.")
    parser.add_argument("--transport", type=str, default="sse", choices=["sse", "stdio"], help="The transport of MCP Server to run (options: sse, stdio).")
    
    args = parser.parse_args()

    # The mcp.run() function handles starting the server based on the transport.
    mcp.run(port=args.port, transport=args.transport)