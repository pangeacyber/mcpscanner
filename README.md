# MCPScanner

MCPScanner (formerly known as `mcpry`) is a command-line tool for analyzing MCP
servers. It does the following:

1. **Discovers MCP Servers**: It automatically searches for MCP server
   configuration files in well-known locations on the host system.
2. **Analyzes Tools and Resources**: It connects to each discovered server to
   fetch the list of available tools and resources.
3. **Security Scanning with [Pangea AI Guard][]**: It uses the Pangea AI Guard
   service to scan the tools for malicious entities and prompts.
4. **Generates Reports**: It creates a JSON report (default `mcpscanner.json`)
   containing the analysis results.
5. **Detects Changes**: It can compare the current state of a server's tools
   with a previous report and display a diff if any changes are detected.
6. **Finds Similar Tools**: It can identify tools with similar functionality.

![Sample output](./.github/assets/sample.png)

## Installation

```bash
pip install -U mcpscanner
```

## Configuration

Before using MCPScanner, you need to set the `PANGEA_AI_GUARD_TOKEN` environment
variable to a [Pangea API token][Pangea API token] that has access to the Pangea
AI Guard service.

```bash
export PANGEA_AI_GUARD_TOKEN="pts_your_token_here"
```

### Pangea domain

To use a Pangea domain other than the default `aws.us.pangea.cloud`, set the
`PANGEA_DOMAIN` environment variable.

```bash
export PANGEA_DOMAIN="aws.us-west-2.pangea.cloud"
```

## Usage

The primary command is `scan`, which runs the analysis.

```bash
mcpscanner scan
```

### Options

| Parameter                        | Description                                                                      | Default                                                     |
| -------------------------------- | -------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `--input <PATH>`                 | The input file containing a previous report to compare against.                  | `mcpscanner.json`                                           |
| `--output <PATH>`                | The file where the new report will be saved.                                     | `mcpscanner.json`                                           |
| `--list-tools`                   | If set, the names of all tools for each MCP server will be listed in the output. | `False`                                                     |
| `--mcp-config-files <FILES>`     | A list of files to discover MCP servers from.                                    | A list of well-known paths for different operating systems. |
| `--similarity-threshold <FLOAT>` | The threshold (between 0.0 and 1.0) for two tools to be considered similar.      | `0.96`                                                      |
| `--syntax-theme <THEME>`         | The syntax theme to use for displaying JSON diffs.                               | `github-dark`                                               |
| `--poll-result-timeout`          | Timeout (seconds) for polling AI Guard results.                                  | `30`                                                        |

[Pangea AI Guard]: https://pangea.cloud/docs/ai-guard/
[Pangea API token]: https://pangea.cloud/docs/admin-guide/projects/credentials#service-tokens
