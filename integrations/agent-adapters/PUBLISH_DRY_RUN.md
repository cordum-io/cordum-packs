# Publish dry-run — 2026-04-19

Release operator checklist + most recent evidence from the
cordum-adapters packaging rework.

## PyPI name availability

- `pip index versions cordum-adapters` → **"No matching distribution found"**.
- `curl https://pypi.org/pypi/cordum-adapters/json` → **404 "Not Found"**.

The `cordum-adapters` name is free on PyPI. The first tag push in CI
will claim it via the Trusted Publisher configured per the workflow's
top-comment instructions.

## Local build (no env overrides)

```
$ cd integrations/agent-adapters
$ python -m build
…
Successfully built cordum_adapters-0.2.0.post387.tar.gz
                 and cordum_adapters-0.2.0.post387-py3-none-any.whl
```

No `SETUPTOOLS_SCM_PRETEND_VERSION` needed. `pyproject.toml` pins
`git_describe_command = [..., "--match", "adapters-v*"]` so cordum-packs'
unrelated `v0.6.6` tag is ignored; setuptools-scm either finds an
`adapters-v*` tag (tagged release — clean version) or falls through to
`fallback_version = "0.2.0"` with a `.postN` distance suffix that stays
PEP-440 compliant.

At an `adapters-v0.2.0` tag the version emits as plain `0.2.0`; at a
commit past that tag it becomes `0.2.0.postN` (N = commit count from
the tag). Both are monotonic and PyPI-acceptable.

## twine check

```
$ python -m twine check dist/*.whl dist/*.tar.gz
Checking dist/cordum_adapters-0.2.0.post387-py3-none-any.whl: PASSED
Checking dist/cordum_adapters-0.2.0.post387.tar.gz:           PASSED
```

No metadata warnings; `long_description_content_type` = text/markdown
renders correctly; classifiers parse.

## Release operator: one-time Trusted Publisher setup

Required before the first `adapters-v*.*.*` tag push. Do each on
`pypi.org` AND `test.pypi.org`:

1. Log in with the release-owner account.
2. Account settings → *Publishing* → *Pending publishers* → *Add*.
3. Fields:
   - **PyPI project name:** `cordum-adapters`
   - **Owner:** `cordum-io`
   - **Repository:** `cordum-packs`
   - **Workflow name:** `agent-adapters.yml`
   - **Environment:** `pypi` (PyPI) or `testpypi` (TestPyPI)
4. Save. The pending publisher becomes the real publisher the first
   time CI uploads a distribution for the matching tag.

One-time setup notes live in the workflow's top-comment block at
[.github/workflows/agent-adapters.yml](../../.github/workflows/agent-adapters.yml).

## Release operator: the actual publish

The publish is one git action on a clean main:

```bash
# From a checkout at the commit the operator wants to ship
# (e.g. post-QA-approval merge into main):
git tag adapters-v0.2.0
git push origin adapters-v0.2.0
```

The CI workflow's `publish` job (gated on
`github.repository == 'cordum-io/cordum-packs'` + `startsWith(github.ref,
'refs/tags/adapters-v')`) picks up the tag, requests an OIDC token,
exchanges it with PyPI's Trusted Publisher endpoint, and uploads the
dist artefact produced by the upstream `build` job. No long-lived
token lives anywhere.

## Release operator: smoke-verify the published artefact

After the CI run completes (usually <5 min):

```bash
# 1. Verify PyPI lists the version.
pip index versions cordum-adapters
# Expected: 0.2.0

# 2. Install in a clean venv.
python -m venv .smoke
.smoke/bin/pip install 'cordum-adapters[autogen]==0.2.0'

# 3. Import + 5-line smoke.
.smoke/bin/python - <<'PY'
from cordum_agent_adapters import __version__
from cordum_agent_adapters.mcp_client import McpStdioClient
print(f"cordum-adapters {__version__} installed")
PY
```

## TestPyPI pre-release (optional but recommended for the first cut)

```bash
# 1. Push a release-candidate tag:
git tag adapters-v0.2.0rc1
git push origin adapters-v0.2.0rc1

# 2. CI publishes to TestPyPI using the `testpypi` environment.

# 3. Smoke-install from TestPyPI in a clean venv:
python -m venv .smoke
.smoke/bin/pip install --index-url https://test.pypi.org/simple/ \
    --extra-index-url https://pypi.org/simple/ \
    'cordum-adapters[autogen]==0.2.0rc1'

# 4. Only if the rc1 smoke is clean, push the real release:
git tag adapters-v0.2.0
git push origin adapters-v0.2.0
```

## Why can't the adapter worker publish directly?

Publishing to PyPI is a shared-state action visible to every Cordum
customer. The worker agent does not hold PyPI credentials and does
not have permission to push tags on the upstream repository. The
release operator must run the tag push — the pyproject, workflow,
and Trusted-Publisher wiring are production-ready and gated so the
next human action is a one-liner: `git tag adapters-v0.2.0 && git
push origin adapters-v0.2.0`.
