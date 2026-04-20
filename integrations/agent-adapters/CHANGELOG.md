# Changelog

All notable changes to `cordum-adapters` are logged here. Dates are the
merge date of the change; versions are what setuptools-scm emits from
the matching git tag.

The project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
conventions and [semantic versioning](https://semver.org/).

## Unreleased

### Added
- (nothing yet — add entries here as PRs merge)

### Changed

### Fixed

## 0.2.0 — 2026-04-18

First public PyPI release. Ships four production-quality framework
adapters over a shared MCP stdio client.

### Added

- **Framework adapters.**
  - `cordum_agent_adapters.crewai` — `BaseTool` instances with retry
    policy, async mode, pydantic-v2 args schemas, `build_crew()`
    declarative wiring, policy-denied `AdapterToolCallError` with
    redacted args.
  - `cordum_agent_adapters.autogen` — subpackage with
    `build_ag2_tools` (modern AG2 0.4+, returns `autogen_core.tools.BaseTool`
    with explicit pydantic args_type derived from the MCP inputSchema)
    and `build_autogen_tools` (legacy pyautogen 0.2 `(functions,
    function_map)` shape). `register_cordum_tools(agent, client,
    api='auto')` duck-types the agent and wires the right path;
    on_messages_stream gets wrapped so pure-LLM turns land in the
    audit trail.
  - `cordum_agent_adapters.openai_agents` — `build_openai_agent_tools`
    returning `agents.FunctionTool` instances with strict-mode schema
    normalisation; `run_governed(agent, input, *, client, logger)` wraps
    `Runner.run_streamed` with trace_metadata carrying the Cordum session
    id; `tee_events(streaming_result, logger)` tees each tool-call item
    into `logger.log_turn`.
  - `cordum_agent_adapters.langchain` — `build_langchain_tools` returning
    `langchain_core.tools.BaseTool` instances.

- **Conversation audit.** `cordum_agent_adapters.audit.CordumConversationLogger`
  posts every turn to the `cordum.audit.log_turn` MCP tool (or slog
  stderr as a fallback). Tri-state tool-availability cache so older
  bridges short-circuit after one probe; 8 KiB payload truncation with
  `[TRUNCATED]` marker; session id auto-generates via `uuid4().hex` or
  can be caller-supplied. Re-exported from
  `cordum_agent_adapters.autogen.audit` for framework-flavoured imports.

- **Error mapping.** `cordum_agent_adapters.errors` surfaces
  `CordumPolicyDeniedError`, `CordumToolExecutionError`,
  `AdapterToolCallError`, and friends with stable prefix conventions
  (`[POLICY DENIED]`, `[TOOL ERROR]`, `[TOOL ARG ERROR]`,
  `[INTERNAL ERROR]`) so an LLM can recognise the class on the next
  turn without a runtime parse.

- **Shared schema helper.** `cordum_agent_adapters._schema` /
  `_pydantic_models` — MCP JSON-Schema → pydantic model converter used
  by every adapter so a schema improvement (nested objects, enums,
  formats, nullable) benefits all four framework surfaces at once.
  `normalise_strict_schema` recursively forces
  `additionalProperties: false` for OpenAI Agents strict-mode
  compatibility.

- **Retry policy.** `cordum_agent_adapters.retry.RetryPolicy` +
  `retry_call` / `retry_call_async` with exponential backoff,
  CSPRNG jitter, and a default predicate that retries transient
  `McpError` but not deterministic `McpToolError(isError=True)`.

- **Per-tool invocation auditor hook.** The OpenAI Agents, AG2, and
  CrewAI adapters all accept an optional `logger=` and forward every
  tool invocation (success + failure + policy-deny) through
  `logger.log_tool_invocation` so a run's audit trail doesn't depend
  on the framework's own tracing.

### Packaging

- Distribution name `cordum-adapters` (import name `cordum_agent_adapters`
  preserved; scikit-learn-style dist/import split).
- Extras: `[crewai]`, `[autogen]` (AG2 0.4+), `[autogen-classic]`
  (pyautogen 0.2 — MUTUALLY EXCLUSIVE with `[autogen]`), `[openai]`,
  `[openai-agents]`, `[langchain]`, `[all]` (picks modern AG2 via a
  self-reference extra), `[dev]` for contributors.
- Versioning via setuptools-scm reading `adapters-v*` git tags with
  `version_scheme = post-release`, `local_scheme = no-local-version`
  so TestPyPI / PyPI accept between-tag dev builds.
- `py.typed` marker shipped so mypy/pyright respect the package's
  type hints (PEP 561).
- License: Business Source License 1.1 — see `LICENSE`.

### CI

- `.github/workflows/agent-adapters.yml` ships three jobs: test matrix
  (3 python × 6 extras = 18 legs), build (sdist + wheel + twine check),
  and publish on `adapters-v*.*.*` tag via PyPI Trusted Publishers
  (OIDC, no long-lived PYPI_API_TOKEN).
- Fork-safe publish gated on `github.repository == 'cordum-io/cordum-packs'`.

### Tutorials

- `docs/crewai.md` — full CrewAI walkthrough.
- `docs/tutorials/autogen.md` — AG2 0.4+ governed-agent walkthrough.
- `docs/tutorials/autogen_classic.md` — pyautogen 0.2 walkthrough.
- OpenAI Agents walkthrough at
  `cordum-packs/docs/tutorials/openai_agents.md` (shipped by the
  adapter task's step 10).
- LangChain tutorial tracked for a future release.
