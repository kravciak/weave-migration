# POLCTL

Weaveworks SaaS Policy management scripts.

## Scripts

1- `scripts/sync/sync.py`

```bash
Usage: sync.py [OPTIONS] COMMAND [ARGS]...

  Sync script that syncs policies, templates, standards, controls and
  categories to Weaveworks SaaS policies service

Options:
  --help  Show this message and exit.

Commands:
  categories  Sync categories
  policies    Sync policies
  standards   Sync standards and controls
  templates   Sync templates
```
Example usage:
```bash
# sync policies/templates/standards/categories
python3 scripts/sync.py policies/templates/standards/categories

# view commands options
python3 scripts/sync.py policies --help

Commands Options:
  -d, --policies-dir           Policies directory  [required]
  -a, --magalix-account        Magalix account ID  [required]
  -s, --policies-service       Policies Service url  [required]
  --new-only                   Sync only new policies
  --sync-deleted               Sync deleted policies
  --help                       Show this message and exit.

# sync policies from custom dir
python3 scripts/sync.py policies --policies-dir <policies dir path>

# sync deleted standards
python3 scripts/sync.py standards --sync-deleted

# sync new and deleted templates
python3 scripts/sync.py templates --new-only --sync-deleted
```

<b>Sync Notes:</b>
- All commands (policies/templates/categories/standards) have same options
- `-d`, `-a` and `-s` options have default values. You can use these options to override the default ones. Otherwise, you don't need to set them.

2- `scripts/test_policies/test_policies`

```bash
cd scripts/test_policies/
go build

# test all policies
./test_policies --root-dir <policies-root-dir>

# test single policy
./test_policies --policy-path <policy-path>
```

3- `scripts/generate_policies_doc.py`

```bash
python3 scripts/generate_policies_doc.py -d <policies-dir> -p <output-path>
```

This generates a policies.md file in `output-path` with all the policies data

4- `scripts/generate_datastudio_csv.py`

```bash
python3 scripts/generate_policies_doc.py -d <policies-dir> -p <output-path>
```

This generates a datastudio.csv file in `output-path` with the following format:
| Category | Entities | Policy Name | Auto-Remedy | Exclusions | Default Tag | PCI | CIS | MITRE ATT&CK | NIST800 | HIPAA | SOC2 TYPE I | GDPR |
|----------|----------|-------------|-------------|------------|-------------|-----|-----|--------------|---------|-------|-------------|------|
| String   | String   | String      | Bool        | Bool       | Bool        | Bool| Bool| Bool         | Bool    | Bool  | Bool        | Bool |
>>>>>>> Init commit
