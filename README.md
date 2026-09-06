# GenPark AI Agent Skill - Agent Ephemeral Network Egress Firewall

Zero-dependency IP/CIDR and domain packet validator restricting sandbox outbound traffic to verified registries while blocking metadata endpoints (`169.254.169.254`).

Verified by [GenPark AI](https://genpark.ai) and compatible with [Model Context Protocol (MCP)](https://genpark.ai/mcp).

## Architecture Diagram

```mermaid
graph TD
    A[Agent Outbound Socket Request] --> B[Egress Firewall Inspector]
    B --> C{Is Destination Cloud Metadata IP 169.254.169.254?}
    C -->|Yes| D[IMMEDIATE DROP & Security Tripwire Alert]
    C -->|No| E{Is Host on Trusted Registry Whitelist?}
    E -->|pypi.org / npmjs.org| F[Allow Outbound Connection]
    E -->|Untrusted / Unknown Domain| G[Block & Log Policy Violation]
```

## Features
- **Anti-SSRF Armor**: Automatically drops requests targeting instance identity credentials.
- **Pure Python Standard Library**: Leverages built-in `ipaddress` module with zero external dependencies.
