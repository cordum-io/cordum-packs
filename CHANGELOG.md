# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [v0.6.5] - 2026-01-31

### Changed
- Vendor SDK into repo with `go.work` and local replace directives for reliable CI builds
- Move SDK out of `packs/` to top-level `sdk/` directory

### Fixed
- Suppress gosec G103 warnings in generated SDK code
- Format vendored SDK runtime sources

## [v0.6.4] - 2026-01-31

### Changed
- Add root `go.sum` for CI dependency caching

### Fixed
- Remove reliance on unreleased SDK helpers

## [v0.6.3] - 2026-01-31

### Changed
- Refresh pack runtime environment variable documentation

## [v0.6.2] - 2026-01-31

### Changed
- Upgrade all packs to CAP v2.0.19 runtime SDK
- Generate packs stats on server (cron deployment)

### Fixed
- Add tenant ID to terraform pack config
- Add tenant ID to incident-enricher config

## [v0.6.1] - 2026-01-29

### Added
- Packs stats page with live usage data
- Pack catalog viewer metrics
- Workers for: cron-triggers, datadog, hello-pack, pagerduty, servicenow

### Changed
- Sharpen README positioning and expand documentation
- Align all packs with tenant header and CAP v2.0.16
- Update security policy and dependabot configuration
- Bump go-redis to v9.17.3 across 15+ packs
- Bump PyYAML, trivy-action, actions/setup-go
- Use Go 1.24.11 for publish workflow

### Fixed
- Slack pack: fall back to inline token for secret resolution
- Webhooks pack: fall back to inline secret
- MCP-client: prefer environment secrets over inline
- Pack scaffold: escape braces in README template
- Quality sweep: align risk tags and adapter schemas across packs
- Stabilize tests and build across packs

## [v0.6.0] - 2026-01-26

### Added
- **20+ new packs**: aws, azure, cap, cordum, gcp, github, gitlab, jira, kubernetes-triage, mcp-client, msteams, opentelemetry, pagerduty, pic-standard, prometheus-query, sentry, servicenow, slack, terraform, vault, webhooks
- **Agent adapters** (`integrations/agent-adapters/`): LangChain, CrewAI, AutoGen, OpenAI tools, MCP client
- **Pack audit CLI** (`tools/pack_audit.py`): audit pack bundles for required assets
- **Pack scaffold CLI** (`tools/pack_scaffold.py`): scaffold new pack bundle structure
- Pack catalog images for marketplace display
- Security hardening and runtime operation guides (`docs/`)

### Changed
- Harden terraform apply and webhooks security
- Harden inline auth handling across packs

### Fixed
- Bind tool names correctly in LangChain and AutoGen adapters
- Format all pack worker sources (gofmt)

### Security
- Security hardening for all pack workers
- Bump go-redis across multiple packs

## [v0.1.0] - 2026-01-15

### Added
- Initial release with core pack infrastructure
- **Packs**: hello-pack (reference), mcp-bridge (MCP stdio bridge), incident-enricher (reference pack with workers + workflows)
- CI pipeline for pack publishing
- SECURITY.md security policy
- CODEOWNERS file
- Roadmap documentation

### Fixed
- MCP-bridge: align with MCP 2025-11-25 spec
- MCP-bridge: cancel jobs on MCP cancellation

[v0.6.5]: https://github.com/cordum-io/cordum-packs/compare/v0.6.4...v0.6.5
[v0.6.4]: https://github.com/cordum-io/cordum-packs/compare/v0.6.3...v0.6.4
[v0.6.3]: https://github.com/cordum-io/cordum-packs/compare/v0.6.2...v0.6.3
[v0.6.2]: https://github.com/cordum-io/cordum-packs/compare/v0.6.1...v0.6.2
[v0.6.1]: https://github.com/cordum-io/cordum-packs/compare/v0.6.0...v0.6.1
[v0.6.0]: https://github.com/cordum-io/cordum-packs/compare/v0.1.0...v0.6.0
[v0.1.0]: https://github.com/cordum-io/cordum-packs/releases/tag/v0.1.0
