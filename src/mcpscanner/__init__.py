from __future__ import annotations

import datetime
import logging
import os
import sys
from base64 import b64encode
from difflib import unified_diff
from hashlib import sha256
from importlib.metadata import version
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal

import cyclopts
import httpx
import pyjson5
from fastembed import TextEmbedding
from fastembed.common.types import NumpyArray
from fastmcp import Client
from fastmcp.client.transports import StdioTransport
from fastmcp.mcp_config import MCPConfig, RemoteMCPServer, StdioMCPServer
from mcp import McpError
from mcp.types import INTERNAL_ERROR, METHOD_NOT_FOUND, Resource, Tool
from pangea import PangeaConfig
from pangea.exceptions import PangeaAPIException, ValidationException
from pangea.services import AIGuard
from pangea.services.ai_guard import (
    GuardResult,
    MaliciousEntityOverride,
    MaliciousPromptOverride,
    Message,
    Overrides,
    Overrides2,
    PiiEntityOverride,
)
from pydantic import BaseModel, ConfigDict, Field
from pydantic_core import to_json
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text
from scipy import spatial

if TYPE_CHECKING:
    from collections.abc import Generator, Sequence


__version__ = version(__package__)


if sys.platform == "linux" or sys.platform == "linux2":
    _CLIENT_PATHS = {
        "cursor": ["~/.cursor/mcp.json"],
        "windsurf": ["~/.codeium/windsurf/mcp_config.json"],
    }
    _WELL_KNOWN_MCP_PATHS = [path for _client, paths in _CLIENT_PATHS.items() for path in paths]
elif sys.platform == "darwin":
    _CLIENT_PATHS = {
        "claude": ["~/Library/Application Support/Claude/claude_desktop_config.json"],
        "cursor": ["~/.cursor/mcp.json"],
        "windsurf": ["~/.codeium/windsurf/mcp_config.json"],
    }
    _WELL_KNOWN_MCP_PATHS = [path for _client, paths in _CLIENT_PATHS.items() for path in paths]
elif sys.platform == "win32":
    _CLIENT_PATHS = {
        "claude": ["~/AppData/Roaming/Claude/claude_desktop_config.json"],
        "cursor": ["~/.cursor/mcp.json"],
        "windsurf": ["~/.codeium/windsurf/mcp_config.json"],
    }

    _WELL_KNOWN_MCP_PATHS = [path for _client, paths in _CLIENT_PATHS.items() for path in paths]
else:
    _WELL_KNOWN_MCP_PATHS = []


def sri_hash(x: str) -> str:
    return f"sha256-{b64encode(sha256(x.encode('utf-8')).digest()).decode('utf-8')}"


def server_display_name(server: StdioMCPServer | RemoteMCPServer) -> str:
    if isinstance(server, StdioMCPServer):
        return f"{server.command} {' '.join(server.args)}"
    if isinstance(server, RemoteMCPServer):
        return server.url
    raise ValueError(f"Unknown server type: {type(server)}")


class ToolWithEmbedding(Tool):
    embedding: NumpyArray

    model_config = ConfigDict(arbitrary_types_allowed=True)


class McpServerReport(BaseModel):
    transport_type: Literal["stdio", "http", "streamable-http", "sse"] | None = None
    name: str
    tools: list[Tool] = Field(default_factory=list)
    resources: list[Resource] = Field(default_factory=list)
    requires_auth: bool = False
    error_message: str | None = None
    created_at: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC))

    def fingerprint(self) -> str:
        return sri_hash(self.model_dump_json(include={"name", "tools", "resources"}, exclude_none=True))


def ai_guard_tools(tools: Sequence[Tool], ai_guard: AIGuard) -> list[GuardResult]:
    try:
        guard_response = ai_guard.guard(
            input={"messages": [], "tools": [tool.model_dump(exclude_none=True) for tool in tools]},
            overrides=Overrides2(
                ignore_recipe=True,
                malicious_entity=MaliciousEntityOverride(
                    disabled=False, domain="block", ip_address="block", url="block"
                ),
                malicious_prompt=MaliciousPromptOverride(disabled=False, action="block"),
            ),
        )
        return [guard_response.result] if guard_response.result is not None else []
    except ValidationException as error:
        if len(error.errors) == 0 or error.errors[0].code != "IsTooBig":
            raise error

        if len(tools) == 1:
            return []

        midpoint = len(tools) // 2
        return ai_guard_tools(tools[:midpoint], ai_guard) + ai_guard_tools(tools[midpoint:], ai_guard)


def find_entities(tool: Tool, ai_guard: AIGuard) -> list[str]:
    if not tool.description:
        return []

    try:
        guard_response = ai_guard.guard_text(
            messages=[Message(role="user", content=tool.description)],
            overrides=Overrides(
                ignore_recipe=True,
                pii_entity=PiiEntityOverride(disabled=False, email_address="report", ip_address="report", url="report"),
            ),
        )

        if (
            guard_response.result is None
            or guard_response.result.detectors.pii_entity is None
            or guard_response.result.detectors.pii_entity.data is None
            or guard_response.result.detectors.pii_entity.data.entities is None
        ):
            return []

        return [entity.value for entity in guard_response.result.detectors.pii_entity.data.entities]
    except Exception:
        return []


async def analyze(mcp_server: StdioMCPServer | RemoteMCPServer, ai_guard: AIGuard) -> McpServerReport:
    mcp_client = Client(mcp_server.to_transport())
    try:
        async with mcp_client:
            assert mcp_client.initialize_result is not None
            server_info = mcp_client.initialize_result.serverInfo
            maybe_requires_auth = (
                not isinstance(mcp_client.transport, StdioTransport)
                and isinstance(mcp_client.transport.headers, dict)
                and any(header.casefold() == "authorization".casefold() for header in mcp_client.transport.headers)
            )

            try:
                tools = await mcp_client.list_tools()
            except McpError as error:
                if error.error.code in {METHOD_NOT_FOUND, INTERNAL_ERROR}:
                    tools = []
                else:
                    raise error

            try:
                resources = await mcp_client.list_resources()
            except McpError as e:
                if e.error.code in {METHOD_NOT_FOUND, INTERNAL_ERROR}:
                    resources = []
                else:
                    raise e

            try:
                guard_results = ai_guard_tools(tools, ai_guard)
            except PangeaAPIException as error:
                return McpServerReport(
                    transport_type=mcp_server.transport,
                    name=server_info.name,
                    tools=tools,
                    resources=resources,
                    requires_auth=maybe_requires_auth,
                    error_message=f"Pangea AI Guard returned an error when guarding the tools list (HTTP/{error.response.http_status}).",  # noqa: E501
                )

            if any(guard_result.blocked for guard_result in guard_results):
                malicious_prompt = any(
                    guard_result.detectors.malicious_prompt is not None
                    and guard_result.detectors.malicious_prompt.detected
                    for guard_result in guard_results
                )
                malicious_entity = any(
                    guard_result.detectors.malicious_entity is not None
                    and guard_result.detectors.malicious_entity.detected
                    for guard_result in guard_results
                )
                return McpServerReport(
                    transport_type=mcp_server.transport,
                    name=server_info.name,
                    tools=tools,
                    resources=resources,
                    requires_auth=maybe_requires_auth,
                    error_message="Finding: "
                    + (
                        "malicious prompt and malicious entity"
                        if malicious_prompt and malicious_entity
                        else "malicious prompt"
                        if malicious_prompt
                        else "malicious entity"
                    ),
                )
    except httpx.HTTPStatusError as error:
        return McpServerReport(
            transport_type=mcp_server.transport,
            name=server_display_name(mcp_server),
            requires_auth=error.response.status_code == 401,
            error_message=f"An HTTP error occurred when connecting to this server (HTTP/{error.response.status_code}).",
        )
    except Exception:
        return McpServerReport(
            transport_type=mcp_server.transport,
            name=server_display_name(mcp_server),
            error_message="Failed to connect to this server.",
        )

    return McpServerReport(
        transport_type=mcp_server.transport,
        name=server_info.name,
        tools=tools,
        resources=resources,
    )


def pretty_unified_diff(expected_json: str, actual_json: str, syntax_theme: str = "github-dark") -> Syntax:
    expected_lines = expected_json.splitlines(keepends=True)
    actual_lines = actual_json.splitlines(keepends=True)
    difflines = list(unified_diff(expected_lines, actual_lines, lineterm=""))
    diff = "".join(difflines)
    return Syntax(diff, "diff", theme=syntax_theme, line_numbers=False, word_wrap=True)


console = Console()
app = cyclopts.App(name="mcpscanner", version=__version__)


@app.command
async def scan(
    input: Annotated[cyclopts.types.JsonPath, cyclopts.Parameter("--input", help="Input file.")] = Path(
        "mcpscanner.json"
    ),
    output: Annotated[cyclopts.types.JsonPath, cyclopts.Parameter("--output", help="Output file.")] = Path(
        "mcpscanner.json"
    ),
    list_tools: Annotated[
        bool, cyclopts.Parameter("--list-tools", help="Whether or not to list the tools of each MCP server.")
    ] = False,
    mcp_config_files: Annotated[
        list[str], cyclopts.Parameter("--mcp-config-files", help="Files to discover MCP servers from.")
    ] = _WELL_KNOWN_MCP_PATHS,
    similarity_threshold: Annotated[
        cyclopts.types.PositiveFloat,
        cyclopts.Parameter("--similarity-threshold", help="Threshold for two tools to be considered similar."),
    ] = 0.96,
    syntax_theme: Annotated[
        str, cyclopts.Parameter("--syntax-theme", help="Syntax theme for JSON diffs.")
    ] = "github-dark",
    poll_result_timeout: Annotated[
        cyclopts.types.PositiveInt,
        cyclopts.Parameter("--poll-result-timeout", help="Timeout (seconds) for polling AI Guard results."),
    ] = 30,
) -> None:
    pangea_ai_guard_token = os.getenv("PANGEA_AI_GUARD_TOKEN")
    if not pangea_ai_guard_token:
        raise ValueError("Missing `PANGEA_AI_GUARD_TOKEN` environment variable.")

    existing_mcp_config_files = [
        Path(file).expanduser() for file in mcp_config_files if Path(file).expanduser().exists()
    ]

    console.print("Found the following MCP config files:")
    for file in existing_mcp_config_files:
        console.print(f"  - {file}")
    console.print()

    mcp_configs = [MCPConfig.from_dict(pyjson5.loads(file.read_text("utf-8"))) for file in existing_mcp_config_files]
    mcp_servers = [server for mcp_config in mcp_configs for server in mcp_config.mcpServers.values()]

    console.print("Found the following MCP servers:")
    for server in mcp_servers:
        if isinstance(server, StdioMCPServer):
            console.print(f"  - {server_display_name(server)} (stdio)")
        if isinstance(server, RemoteMCPServer):
            console.print(f"  - {server_display_name(server)} (remote)")
    console.print()

    logging.getLogger("mcp").setLevel(logging.CRITICAL)

    logging.getLogger("pangea").setLevel(logging.CRITICAL)
    ai_guard = AIGuard(
        token=pangea_ai_guard_token,
        config=PangeaConfig(
            domain=os.getenv("PANGEA_DOMAIN", "aws.us.pangea.cloud"), poll_result_timeout=poll_result_timeout
        ),
        logger_name="pangea",
    )

    existing_reports = (
        [McpServerReport(**report) for report in pyjson5.loads(input.read_text("utf-8"))] if input.exists() else []
    )

    reports: list[McpServerReport] = []
    for server in mcp_servers:
        report = await analyze(server, ai_guard)
        reports.append(report)

        diff: Syntax | None = None
        if (
            previous_report := next(
                (existing_report for existing_report in existing_reports if existing_report.name == report.name), None
            )
        ) and previous_report.fingerprint() != report.fingerprint():
            expected = previous_report.model_dump_json(
                indent=2, include={"name", "tools", "resources"}, exclude_none=True
            )
            actual = report.model_dump_json(indent=2, include={"name", "tools", "resources"}, exclude_none=True)
            diff = pretty_unified_diff(expected, actual, syntax_theme)

        tool_to_entities = {tool.name: find_entities(tool, ai_guard) for tool in report.tools}
        tool_to_entities = {tool: entities for tool, entities in tool_to_entities.items() if len(entities) > 0}

        def report_generator() -> Generator[RenderableType, None, None]:
            yield Text(report.name, style="bold")
            yield Text(f"Fingerprint: {report.fingerprint()}")
            yield Text(
                f"Tools: {len(report.tools)}"
                + (" (" + ", ".join(tool.name for tool in report.tools) + ")" if list_tools else "")
            )
            yield Text(f"Resources: {len(report.resources)}")

            if report.transport_type != "stdio":
                if report.requires_auth:
                    yield Text.from_markup("Requires authentication :thumbs_up:", style="green")
                else:
                    yield Text("Lacks authentication", style="yellow")

            if len(tool_to_entities) > 0:
                yield Group(
                    Text(),
                    Text("Entities found in tool descriptions:"),
                    *[Text(f"  - {tool}: {', '.join(entities)}") for tool, entities in tool_to_entities.items()],
                )

            if report.error_message:
                yield Text()
                yield Text(report.error_message, style="red")

            if diff:
                yield diff

        console.print(Panel(Group(*report_generator())))
    console.print()

    # If any tools have the same name, print a warning.
    tool_names = [tool.name for report in reports for tool in report.tools]
    if len(tool_names) != len(set(tool_names)):
        console.print("Warning: The following tools have the same name:", style="yellow")
        for name in tool_names:
            if tool_names.count(name) > 1:
                console.print(f"  - {name}", style="yellow")
        console.print()

    console.print("Looking for similar tool descriptions...")
    console.print()
    tools = [tool for report in reports for tool in report.tools]
    embeddings = TextEmbedding().embed([tool.description or "" for tool in tools])
    embeds = [ToolWithEmbedding(**tool.model_dump(), embedding=embedding) for tool, embedding in zip(tools, embeddings)]
    relations = [
        (embeds[i], embeds[j], 1 - spatial.distance.cosine(embeds[i].embedding, embeds[j].embedding))
        for i in range(len(embeds))
        for j in range(i + 1, len(embeds))
    ]

    similar_tools = [(tool1, tool2) for tool1, tool2, similarity in relations if similarity >= similarity_threshold]
    if similar_tools:
        console.print("The following tools appear to be similar:", style="yellow")
        for tool1, tool2 in similar_tools:
            console.print(f"  - [bold]{tool1.name}[/bold] and [bold]{tool2.name}[/bold]", style="yellow")
    else:
        console.print("No similar tools found :thumbs_up:")

    output.write_bytes(
        to_json(
            [
                {
                    **report.model_dump(include={"name", "tools", "resources"}),
                    "fingerprint": report.fingerprint(),
                    "created_at": report.created_at.isoformat(),
                }
                for report in reports
            ]
        )
    )


if __name__ == "__main__":
    app()
