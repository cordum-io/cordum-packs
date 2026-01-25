# Testing and Validation

This repo does not include a single top-level test suite. Use these steps to validate packs.

## Go pack tests

Run tests per pack module:

```bash
cd packs/<pack>
go test ./...
```

For a full sweep:

```bash
for mod in $(rg --files -g 'go.mod' packs); do
  dir=$(dirname "$mod")
  (cd "$dir" && go test ./...)
done
```

## Build the catalog and bundles

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r tools/requirements.txt
python tools/build.py
```

Validate output in `public/`.

## Manual validation checklist

- Install the pack bundle in a dev instance.
- Start the runtime worker with least-privilege credentials.
- Run a read-only workflow to confirm job routing and policy.
- Validate allowlists/denylists by attempting a blocked resource.
- Confirm logs contain no secrets.

