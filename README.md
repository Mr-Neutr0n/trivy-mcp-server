# Trivy Security Scanner MCP Server

A Model Context Protocol (MCP) server that provides security vulnerability scanning capabilities using [Trivy](https://trivy.dev/), a comprehensive security scanner. This allows you to scan for vulnerabilities and automatically fix them directly from Claude Desktop, Cursor, or any MCP-compatible client.

## Features

- **🔍 Project Scanning**: Scan directories for security vulnerabilities in dependencies
- **🔧 Automatic Fixing**: Automatically update packages to secure versions
- **📦 Multi-Language Support**: Supports Python (pip), Node.js (npm), Go, Rust, PHP, and Ruby
- **📊 Detailed Reporting**: Get comprehensive vulnerability reports with severity levels
- **🤖 AI Integration**: Works seamlessly with Claude Desktop and Cursor

## Prerequisites

### 1. Install Trivy

**macOS:**
```bash
brew install trivy
```

**Linux:**
```bash
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

**Windows:**
Download from [Trivy Releases](https://github.com/aquasecurity/trivy/releases)

### 2. Python 3.8+
Make sure you have Python 3.8 or later installed.

## Installation

1. **Clone this repository:**
   ```bash
   git clone https://github.com/your-username/trivy-mcp-server.git
   cd trivy-mcp-server
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Test the installation:**
   ```bash
   python server.py --help
   ```

## Configuration

### 🖥️ Claude Desktop Setup

1. **Locate your Claude Desktop config file:**
   - **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows**: `~/AppData/Roaming/Claude/claude_desktop_config.json`

2. **Add the Trivy MCP server to your config:**
   ```json
   {
     "mcpServers": {
       "trivy-security-scanner": {
         "command": "python",
         "args": [
           "/full/path/to/trivy-mcp-server/server.py",
           "--transport",
           "stdio"
         ],
         "env": {}
       }
     }
   }
   ```

3. **Replace `/full/path/to/` with the actual path to your cloned repository**

4. **Restart Claude Desktop**

5. **Verify it's working:**
   In Claude Desktop, you should now be able to ask:
   > "Scan my project for security vulnerabilities"

### 🎯 Cursor Setup

1. **Open Cursor Settings** (`Cmd/Ctrl + ,`)

2. **Search for "MCP" in settings**

3. **Add the Trivy MCP server configuration:**
   ```json
   {
     "mcp.servers": {
       "trivy-security-scanner": {
         "command": "python",
         "args": [
           "/full/path/to/trivy-mcp-server/server.py",
           "--transport",
           "stdio"
         ]
       }
     }
   }
   ```

4. **Replace `/full/path/to/` with the actual path to your repository**

5. **Restart Cursor**

6. **Test the integration:**
   You can now use Trivy commands directly in Cursor's AI chat.

## Usage

Once configured with Claude Desktop or Cursor, you can use natural language commands:

### 🔍 Scanning for Vulnerabilities
```
"Scan my current project for security vulnerabilities"
"Check for critical and high severity vulnerabilities only"
"Scan the /path/to/my/project directory for security issues"
```

### 🔧 Fixing Vulnerabilities
```
"Fix the lodash vulnerability in my project"
"Update the vulnerable packages to secure versions"
"Do a dry run to see what packages would be updated"
```

### 📚 Research Vulnerabilities
```
"Get details about CVE-2021-44228"
"Tell me more about this vulnerability: CVE-2021-23337"
```

## Available Tools

The MCP server provides three main tools:

### 1. `scan_project`
- **Purpose**: Scan a directory for security vulnerabilities
- **Parameters**:
  - `workspace` (required): Directory path to scan
  - `severity_filter` (optional): Filter by severity (e.g., "HIGH,CRITICAL")
  - `include_fixed` (optional): Include already fixed vulnerabilities

### 2. `fix_vulnerability`
- **Purpose**: Automatically update packages to secure versions
- **Parameters**:
  - `workspace` (required): Directory containing the project
  - `pkg_name` (required): Name of the package to update
  - `target_version` (required): Version to update to
  - `dry_run` (optional): Simulate the fix without making changes

### 3. `get_vulnerability_details`
- **Purpose**: Get detailed information about specific vulnerabilities
- **Parameters**:
  - `vulnerability_id` (required): CVE ID (e.g., "CVE-2021-44228")

## Example Workflows

### Daily Security Review
1. **Morning scan**: "Scan all my projects for new vulnerabilities"
2. **Review findings**: Check the severity and impact of discovered issues
3. **Apply fixes**: "Fix the critical vulnerabilities found"
4. **Verify**: Re-scan to confirm fixes were applied

### Pull Request Security Check
1. **Before merging**: "Scan this branch for any new security vulnerabilities"
2. **Block if issues found**: Don't merge if critical vulnerabilities are introduced
3. **Auto-fix when possible**: "Update the vulnerable dependencies to secure versions"

### Vulnerability Research
1. **Deep dive**: "Get details about CVE-2021-44228 and check if any of my projects are affected"
2. **Impact assessment**: Understand the scope and severity
3. **Remediation planning**: Plan updates and fixes

## Supported Package Managers

- ✅ **Python**: `requirements.txt`, `pyproject.toml`
- ✅ **Node.js**: `package.json`
- ✅ **Go**: `go.mod`
- 🔄 **Rust**: `Cargo.toml` (detection only)
- 🔄 **PHP**: `composer.json` (detection only)
- 🔄 **Ruby**: `Gemfile` (detection only)

*Note: Automatic fixing is currently supported for Python, Node.js, and Go. Other languages have detection support with manual fixing guidance.*

## Troubleshooting

### Common Issues

**1. "Trivy not found" error**
- Make sure Trivy is installed and in your PATH
- Test with: `trivy --version`

**2. "Permission denied" error**
- Ensure the server.py file has execute permissions
- Try: `chmod +x server.py`

**3. "Module not found" error**
- Install dependencies: `pip install -r requirements.txt`
- Check Python version: `python --version` (should be 3.8+)

**4. Claude Desktop not recognizing the server**
- Check the file path in your config is correct (use absolute paths)
- Restart Claude Desktop after config changes
- Check the Claude Desktop logs for error messages

### Getting Help

1. **Check Trivy installation**: `trivy --version`
2. **Test the server**: `python server.py --help`
3. **Verify MCP connection**: Look for server logs in Claude Desktop/Cursor
4. **Check file paths**: Ensure all paths in config files are absolute and correct

## Development

### Running Standalone
```bash
# Start with default settings (SSE transport on port 54321)
python server.py

# Start with custom settings
python server.py --port 8080 --transport sse

# Start for Claude Desktop (stdio transport)
python server.py --transport stdio
```

### Adding New Package Managers
To add support for additional package managers:
1. Update `detect_package_manager()` function
2. Add fixing logic in `fix_vulnerability()` function
3. Test with sample projects

## Security Considerations

- The server executes system commands (Trivy, package managers)
- Always review changes before applying fixes in production
- Consider running with limited privileges in production environments
- Validate workspace paths to prevent directory traversal attacks

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source. See individual dependencies for their respective licenses.

---

**🔒 Keep your code secure with automated vulnerability scanning!** 