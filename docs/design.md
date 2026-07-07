# MCD Pydantic Graph + Ledger Rebuild Design

Status: design spec

Audience: implementers rebuilding the MCD tool as a durable, graph-driven
analysis system rather than a harness-local auto-loop.

Primary decision: build MCD around a Pydantic Graph workflow whose durable source
of truth is a SQLite work ledger. The graph controls phases. The ledger controls
coverage and resumability. Pydantic AI agents perform bounded judgment. The
existing deterministic MCD scanner and report shape remain the quality bar.

## Executive Summary

The current MCD report is the part worth preserving. It already has the right
product model:

* static observations first;
* BP-* malicious-code compositions over those observations;
* severity and confidence kept separate;
* disposition as a deterministic recommendation, not a model verdict;
* evidence, disproof criteria, verification steps, reachability, enrichment,
  coverage notes, and HTML/Markdown/JSON output;
* optional agentic adjudication layered over the deterministic scan.

The rebuild should not turn this into "ask an agent if the code is malicious".
The rebuild should make the existing MCD idea more capable:

* discover targets, containers, binaries, and follow-up work incrementally;
* unpack and decompile when tools are available;
* ask a model to review bounded evidence instead of a whole repository;
* fetch limited remote content only with explicit policy;
* resume after crashes;
* prove coverage from ledger state;
* produce the same quality report, with better coverage and review provenance.

The recommended shape is:

```text
Pydantic Graph
  controls the workflow:
  discover -> unpack/decompile -> scan -> compose -> review -> follow up -> report

SQLite Ledger
  controls truth:
  runs, artifacts, work items, evidence refs, findings, judgments, approvals,
  tool runs, network fetches, graph events, reports

Vendored Parallax Taxonomy
  controls meaning:
  ontology atoms, MCD indicators, BP-* compositions, verification guidance,
  response tiers, enrichment signals

Sandbox Provider
  controls execution:
  static read-only by default, isolated tool execution for untrusted inputs,
  optional dynamic/network work only by policy

Reporter
  controls the product:
  preserve the current assessment/report contract and add coverage/review sections
```

This is not a normal agent loop. The graph can loop, branch, fan out, and return
to earlier phases, but every return is driven by structured state. The model
does not decide completion. The ledger does.

## Goals

1. Preserve the existing report quality.
2. Make coverage durable, auditable, resumable, and externally inspectable.
3. Let discovery add new work while the run is already in progress.
4. Use Pydantic Graph for explicit workflow shape and visualization.
5. Use Pydantic AI agents only for bounded review tasks with typed outputs or
   record tools.
6. Vendor the Parallax taxonomy as data, not as monolithic engine logic.
7. Support sandboxed unpacking, decompilation, byte inspection, and optional
   dynamic verification.
8. Support limited network retrieval for evidence, especially cases like
   `curl ... | sh`, without executing fetched content.
9. Package or locate external tools in a predictable, policy-aware way.
10. Keep the default run static, offline, and safe.
11. Expose a CLI and MCP-compatible tool surface.

## Non-Goals

* No free-form "run until the agent says done" loop.
* No model-authored maliciousness verdict.
* No target code execution by default.
* No unbounded network.
* No silent best-effort decompilation. Missing tool coverage must be reported.
* No large binary toolchain bundled into the core package by default.
* No requirement that every host have Docker, Ghidra, Java, .NET, npm, or uv
  installed before a basic static scan works.
* No re-baking of Parallax taxonomy rules into a monolithic scanner.

## Current MCD Contract To Preserve

The current `mcd-report` pipeline is:

```text
engine.observe(target)
  -> observations + inventory
mcd_lens.mcd_reading(observations, inventory)
  -> MCD findings
engine.report.build(...)
  -> scan report
mcd_lens.build_assessment(...)
  -> assessment
render_html / render_markdown / to_json
  -> report.html, report.md, report.json
```

The new system should preserve these concepts even if implementation modules
move:

* `observations`: judgment-free atoms with paths, evidence, confidence, method.
* `findings`: BP-* compositions, severity, confidence, evidence ids, disproof,
  verification, response tier.
* `assessment`: target, summary, disposition, executive summary, review leads,
  enrichment, reachability, correlations, dynamic verification status, coverage.
* `adjudication`: optional agent review overlay with verdicts, confidence moves,
  response tiers, reviewed disposition, and reviewer metadata.
* report outputs: self-contained HTML, Markdown, and JSON.

The report should add, not replace:

* ledger coverage summary;
* sandbox policy summary;
* toolchain availability and blind spots;
* network fetch policy and fetched artifacts;
* graph execution timeline;
* per-reviewer model/provider metadata and usage/cost when available.
* optional QA notes for suppressed/deescalated findings and rule tuning
  candidates.

## Taxonomy And Rule Pack Vendoring

The Parallax taxonomy folder is now the source of truth for the rules and
interpretive material MCD should use. The rebuild should treat it as versioned
data, not implementation code. This is the clean break from the older monolith:
the scanner owns mechanics, evidence extraction, graph scheduling, proof
accounting, and report rendering; the taxonomy owns vocabulary and meaning.

The vendored taxonomy should include, at minimum:

* ontology atoms and idioms under `ontology/`;
* MCD indicators under `lenses/mcd/indicators/`;
* BP-* MCD compositions under `lenses/mcd/compositions/`;
* MCD verification guidance under `lenses/mcd/verification/`;
* MCD response tiers under `lenses/mcd/response/`;
* MCD enrichment signals under `lenses/mcd/signals/`;
* shared enrichment and investigation method docs where the report references
  them.

The vendoring process must use an allowlist. The local taxonomy checkout
contains development files such as `.git`, `.venv`, caches, and local test
state. Those must never be copied into a distributed package or report bundle.

`scripts/vendor_taxonomy.py` should:

* copy only allowlisted roots and file extensions;
* reject `.git`, `.venv`, `__pycache__`, `.pytest_cache`, and local scratch;
* compute per-file sha256 values;
* record source commit and dirty status when the source is a Git checkout;
* fail if required MCD roots are absent;
* write `taxonomy-manifest.json`;
* support `--check` so CI can fail when vendored taxonomy is stale.

Recommended vendored package shape:

```text
src/prlx_mcd/taxonomy/vendored/
  taxonomy-manifest.json
  ARCHITECTURE.md
  README.md
  ontology/
  enrichment/
  investigation/
  lenses/mcd/
```

The manifest should be generated during packaging or release:

```json
{
  "schemaVersion": "0.1.0",
  "taxonomyId": "parallax-taxonomy",
  "sourcePath": "parallax-taxonomy",
  "sourceGitCommit": "...",
  "sourceGitDirty": false,
  "generatedAt": "...",
  "includedRoots": [
    "ontology",
    "enrichment",
    "investigation",
    "lenses/mcd"
  ],
  "files": [
    {
      "path": "lenses/mcd/compositions/BP-SUPPLY.md",
      "sha256": "..."
    }
  ]
}
```

Runtime should resolve taxonomy through a provider interface:

```python
class TaxonomyProvider(Protocol):
    def manifest(self) -> TaxonomyManifest: ...
    def atom(self, atom_id: str) -> TaxonomyDoc: ...
    def idiom(self, idiom_id: str) -> TaxonomyDoc: ...
    def mcd_indicator(self, family: str) -> TaxonomyDoc: ...
    def mcd_composition(self, composition_id: str) -> TaxonomyDoc: ...
    def mcd_verification(self, family: str) -> TaxonomyDoc: ...
    def mcd_response_tier(self, tier: int) -> TaxonomyDoc: ...
    def mcd_signal(self, signal_id: str) -> TaxonomyDoc: ...
```

Provider order:

1. Explicit `--taxonomy-root` CLI option.
2. `PRLX_TAXONOMY_ROOT` for development.
3. Packaged vendored taxonomy.

This gives developers fast iteration against the live taxonomy checkout while
normal users get reproducible packaged behavior.

The taxonomy module should stay modular:

* `manifest.py` loads and validates `taxonomy-manifest.json`;
* `provider.py` resolves roots and exposes the provider interface;
* `loaders.py` reads Markdown/JSON taxonomy entries into typed records;
* `mcd.py` exposes MCD-specific lookups and composition metadata;
* `references.py` maps findings, observations, verification items, and response
  tiers back to source taxonomy paths.

Scanner code should not hardcode BP-* prose, response language, or verification
guidance. It may hardcode detector mechanics and stable rule identifiers, but it
should read human-facing definitions and interpretation metadata from taxonomy.
For example:

```text
Detector emits:
  atom = "PKGM.INSTALL"
  rule_id = "js.npm.install-script"
  evidence = package.json scripts.install

MCD composition reader supplies:
  BP-SUPPLY title
  BP-SUPPLY description
  BP-SUPPLY required/supporting indicators
  verification prompts
  disproof criteria
  response tier guidance
```

Reports should record the taxonomy manifest used for the run. That makes old
reports reproducible even when the taxonomy later changes. A finding should also
carry references back to the taxonomy docs that produced its interpretation:

```json
{
  "composition": "BP-SUPPLY",
  "taxonomyRefs": [
    "lenses/mcd/compositions/BP-SUPPLY.md",
    "lenses/mcd/indicators/PKGM.md",
    "lenses/mcd/verification/PKGM.md",
    "lenses/mcd/response/tier-4-active-monitoring.md"
  ]
}
```

The key design rule: taxonomy data can evolve without editing the graph runner.
The graph runner can evolve without rewriting the taxonomy. The only shared
contract is typed references: atom ids, indicator families, composition ids,
verification families, response tiers, and enrichment signal ids.

## Core Architectural Decision

Use Pydantic Graph for workflow, not coverage.

Pydantic Graph gives us typed nodes, explicit branching, graph rendering,
manual/stepwise execution, dependencies, decisions, fanout, joins, and state.
Those are useful for MCD because MCD is naturally a workflow:

```text
inventory target
  -> expand containers
  -> scan source
  -> classify binaries
  -> decompile selected artifacts
  -> rescan recovered source
  -> compose MCD findings
  -> review uncertain/high-risk findings
  -> fetch limited remote content when approved
  -> add follow-up work
  -> recompute disposition
  -> render report
```

But graph state is not the coverage oracle. A graph run can crash, a node can be
retried, and parallel execution makes native state snapshots hard. The durable
coverage oracle is the SQLite ledger.

Therefore:

* Graph state holds transient run context: `run_id`, config, current batch,
  sandbox provider, model profile, and counters.
* SQLite holds durable run truth: artifacts, work items, statuses, findings,
  judgments, approvals, tool runs, fetched content, report metadata.
* Every node starts by reading ledger state and ends by recording events.
* Completion is allowed only when the ledger coverage gate says terminal.

## Why Not A Harness Loop

A harness loop is an adapter behavior: "when the agent goes idle, inject another
prompt". It can work for Pi or OpenCode. It is not the best core for MCD.

For MCD, the core needs:

* deterministic coverage math;
* structured dependencies between target x operation work items;
* resumability independent of an agent session;
* bounded review tasks;
* explicit sandbox and network policy;
* repeatable report generation from persisted evidence.

A harness loop gives continuation. It does not, by itself, give coverage.

The graph-plus-ledger model gives continuation and coverage:

```text
Graph asks: what phase should run next?
Ledger answers: what work exists, what is actionable, and can we finish?
Agent answers: what is the judgment for this bounded item?
Reporter answers: what should the user do?
```

## Package Shape

Recommended package layout for the Python rebuild:

```text
packages/mcd-graph/
  pyproject.toml
  scripts/
    vendor_taxonomy.py
  src/prlx_mcd/
    __init__.py
    cli.py
    config.py
    graph.py
    nodes/
      initialize.py
      inventory.py
      expand.py
      scan.py
      decompile.py
      compose.py
      review.py
      network.py
      approvals.py
      report.py
      coverage.py
    ledger/
      schema.sql
      store.py
      models.py
      migrations.py
    storage/
      project_id.py
      paths.py
      index.py
      retention.py
    inventory/
      tree.py
      filters.py
      summaries.py
    taxonomy/
      provider.py
      manifest.py
      loaders.py
      mcd.py
      references.py
      vendored/
        taxonomy-manifest.json
        ontology/
        enrichment/
        investigation/
        lenses/mcd/
    sandbox/
      base.py
      local_readonly.py
      monty_provider.py
      openshell_provider.py
      subprocess_provider.py
      network_policy.py
    tools/
      manifest.py
      doctor.py
      resolver.py
      install.py
      manifests/
        jadx.json
        ghidra.json
        ilspy.json
        dex2jar.json
        rizin.json
        unicorn.json
        ripgrep.json
        tree.json
        uv.json
        node.json
    scanner/
      observe.py
      readings.py
      assessment.py
      report_contract.py
    reviewers/
      prompts.py
      schemas.py
      agents.py
    qa/
      schemas.py
      rule_tuning.py
      reviewer.py
    mcp_server.py
  tests/
    fixtures/
    test_storage_paths.py
    test_ledger.py
    test_vendor_taxonomy.py
    test_taxonomy_provider.py
    test_tree_view.py
    test_rule_tuning_qa.py
    test_graph_static_path.py
    test_report_compat.py
    test_network_policy.py
    test_tool_doctor.py
```

If this lives in the existing TypeScript `stonefish-labs` workspace, keep it as a
separate package rather than forcing Pydantic AI into the TS packages. The TS
packages can remain thin OpenCode/Pi adapters or future scanner ports. The
Pydantic graph runner is naturally Python.

## Public Surfaces

CLI:

```text
mcd run <target>
  --storage-root .mcd
  --run-id auto
  --taxonomy-root auto
  --tree on|off
  --post-report-qa off|rules|full
  --model anthropic:claude-sonnet-4-6
  --sandbox auto|monty|openshell|subprocess|none
  --network offline|registry|fetch-only|dynamic
  --auto-approve network-fetch:referenced-public-http
  --tool-profile static|source|binary|full
  --max-review-items 100
  --max-iterations 50

mcd resume --run-dir .mcd/projects/<project>/runs/<run>
mcd resume --run-id <id>
mcd status --run-id <id>
mcd report --run-id <id> --format html|md|json
mcd qa --run-id <id> --mode rules
mcd tree <target>
mcd tree --run-id <id>
mcd approve --run-id <id> <approval-id>
mcd list --storage-root .mcd
mcd clean --storage-root .mcd --older-than 30d --keep-reports
mcd tools doctor
mcd tools install <tool>
mcd tools list
mcd tools cache
```

Advanced overrides:

```text
mcd run <target> --run-dir <path>
mcd run <target> --project-id <slug-or-id>
mcd run <target> --db <path-to-run.db>
mcd run <target> --shared-db experimental
```

`--db` is an escape hatch, not the default user experience. The normal output of
`mcd run` should print the run id, project id, run directory, report paths, and
the command needed to resume.

Python API:

```python
from prlx_mcd import MCDConfig, run_mcd, resume_mcd

result = run_mcd(
    target=".",
    config=MCDConfig(
        storage_root=".mcd",
        sandbox="auto",
        network="fetch-only",
        model="anthropic:claude-sonnet-4-6",
    ),
)
print(result.report_html)
```

MCP-compatible tools:

```text
mcd_scan(target, options) -> run_id, project_id, run_dir, summary, report paths
mcd_resume(run_id | run_dir) -> status
mcd_status(run_id | run_dir) -> coverage, pending approvals, report paths
mcd_approve(run_id, approval_id, decision) -> status
mcd_report(run_id, format) -> artifact path/content
mcd_tree(target | run_id, options) -> tree text/json, summary, artifact path
mcd_qa(run_id, options) -> rule tuning suggestions and QA artifact path
mcd_tools_doctor() -> tool availability and blind spots
```

The MCP surface should be a controller over the same ledger. It should not hold
separate state in the MCP server process.

## Tree View Tool

Most agents need a fast structural view before they can reason well about a
target. MCD should provide that directly instead of making every harness shell
out to `find`, `tree`, or ad hoc recursive listing code.

The tree view has three jobs:

* orient agents and humans to the target shape;
* make report navigation easier;
* create a stable inventory artifact for follow-up review and QA.

The implementation should prefer an internal Python tree generator over a hard
dependency on the external `tree` command. External `tree` can be used when
present, but the internal implementation must always exist and must apply the
same ignore, size, depth, and redaction policy as inventory.

CLI:

```text
mcd tree <target>
  --max-depth 4
  --max-entries 2000
  --include-hidden false
  --format text|json
  --respect-gitignore true

mcd tree --run-id <id>
```

MCP:

```text
mcd_tree(target, options) -> {
  text: "...",
  json: {...},
  summary: {...},
  truncated: true|false,
  artifactPath: "artifacts/tree/target-tree.json"
}
```

The graph should generate a target tree during inventory and store it as:

```text
artifacts/tree/target-tree.txt
artifacts/tree/target-tree.json
```

Tree JSON should preserve enough structure for agents to filter without reading
the filesystem again:

```json
{
  "root": ".",
  "generatedAt": "...",
  "policy": {
    "maxDepth": 4,
    "maxEntries": 2000,
    "respectGitignore": true,
    "includeHidden": false
  },
  "summary": {
    "files": 0,
    "directories": 0,
    "truncated": false,
    "largestFiles": [],
    "interestingPaths": []
  },
  "children": []
}
```

Tree output must be bounded. It should collapse high-volume directories such as
`node_modules`, `.git`, build outputs, virtual environments, caches, and vendor
trees unless the user explicitly expands them. The report should include a
compact tree summary and link to the full tree artifact.

## Run Storage And SQLite UX

MCD should assume users may run many scans at once. The default should avoid a
single shared SQLite database that every scan writes to. The simplest reliable
model is one SQLite database per run, stored next to the reports and artifacts
that database describes.

Default storage layout:

```text
.mcd/
  projects/
    index.db
    <project-id>/
      project.json
      runs/
        <started-at>-<run-hash>/
          run.json
          run.db
          reports/
            report.html
            report.md
            report.json
            qa.json
            qa.md
          artifacts/
            tree/
          fetched/
          tool-output/
          logs/
          tmp/
```

`run.db` is the authoritative ledger for that run. Reports are rendered
artifacts. `run.json` is a small status file for cheap discovery and recovery:

```json
{
  "runId": "run_20260707_153012_ab12cd34ef56",
  "projectId": "target-repo_91b3f6a412d0",
  "status": "running",
  "dbPath": "run.db",
  "startedAt": "...",
  "completedAt": null,
  "targetPath": "/abs/path/to/target",
  "reportPaths": {
    "html": "reports/report.html",
    "markdown": "reports/report.md",
    "json": "reports/report.json"
  }
}
```

Project identity should be stable enough to group repeated scans of the same
target without leaking unnecessary path detail into global indexes:

```text
project_slug = sanitize(basename(git_root or target_root))
project_hash = sha256(
  realpath(target_root)
  + "\n" + realpath(git_root or "")
  + "\n" + git_remote_origin_url_or_empty
)[:12]

project_id = project_slug + "_" + project_hash
```

Run identity should be unique per invocation:

```text
run_seed = sha256(realpath(target_path) + target_kind + selected_fast_metadata)
config_hash = sha256(normalized_config_without_secrets)[:12]
run_hash = sha256(project_id + run_seed + config_hash + started_at + nonce)[:12]
run_id = "run_" + started_at_compact + "_" + run_hash
```

The heavier `target_fingerprint` can be computed during inventory and stored in
the ledger after the run directory already exists.

The first implementation should use per-run databases:

* no write contention between scans;
* no accidental cross-run state mutation;
* easy archival and cleanup;
* report bundles can be copied as a directory;
* resume is just `mcd resume --run-dir <dir>`.

SQLite settings for each `run.db`:

```sql
pragma journal_mode = wal;
pragma synchronous = normal;
pragma busy_timeout = 5000;
pragma foreign_keys = on;
```

The optional `.mcd/projects/index.db` is only an index for UX commands such as
`mcd list`, `mcd status --run-id`, and `mcd clean`. It should contain project id,
run id, status, timestamps, target path, run dir, and report paths. The run must
not depend on this index for correctness. If the index is missing or corrupt,
MCD can rebuild it by walking `.mcd/projects/*/runs/*/run.json`.

Concurrency rules:

* many scans can run concurrently because they each own a run directory;
* the project index uses WAL and short transactions only;
* run-local temporary files stay under `tmp/`;
* tool outputs are written under `tool-output/<work-item-id>/`;
* fetched content is written under `fetched/<network-fetch-id>/`;
* final reports are written to temporary names and atomically renamed.

The shared project database idea can be revisited later, but it should not be
the first build. If a shared DB is added, it must use explicit worker leases,
WAL, `busy_timeout`, stale lease recovery, and run ownership ids. That is useful
for a service, not necessary for the local tool.

UX requirements:

```text
$ mcd run .
Run:      run_20260707_153012_ab12cd34ef56
Project:  my-repo_91b3f6a412d0
Dir:      .mcd/projects/my-repo_91b3f6a412d0/runs/20260707-153012-ab12cd34ef56
Report:   .mcd/projects/my-repo_91b3f6a412d0/runs/20260707-153012-ab12cd34ef56/reports/report.html
Resume:   mcd resume --run-dir .mcd/projects/my-repo_91b3f6a412d0/runs/20260707-153012-ab12cd34ef56
```

Useful commands:

```text
mcd list
mcd list --project my-repo_91b3f6a412d0
mcd status --run-id run_20260707_153012_ab12cd34ef56
mcd status --run-dir .mcd/projects/.../runs/...
mcd report --run-id run_20260707_153012_ab12cd34ef56 --format html
mcd clean --failed --older-than 7d
mcd clean --completed --older-than 30d --keep-reports
```

Retention should be explicit. The tool should not silently delete run databases,
fetched artifacts, or reports. `mcd clean` should show what it will remove unless
`--yes` is supplied.

## Ledger Model

Use SQLite first. It is enough for local runs, durable resumption, and later
service migration. JSON files are tempting but become painful once we have leases,
parallel review, tool-run provenance, approvals, and report history.

### Tables

`runs`

```text
id text primary key
project_id text not null
target_path text not null
target_root text not null
target_hash text
target_fingerprint text
storage_root text not null
run_dir text not null
status text not null
created_at text not null
updated_at text not null
completed_at text
config_json text not null
taxonomy_manifest_json text not null
model_profile_json text
sandbox_profile_json text
network_policy_json text
coverage_json text
summary_json text
error text
```

Statuses:

```text
queued -> running -> completed
                  -> partial
                  -> blocked
                  -> failed
                  -> canceled
```

`artifacts`

```text
id text primary key
run_id text not null
kind text not null
path text not null
logical_path text not null
parent_artifact_id text
sha256 text
size_bytes integer
media_type text
language text
container_member text
origin text not null
metadata_json text not null
created_at text not null
```

Example artifact kinds:

```text
source-file
manifest
target-tree
archive
asar
jar
apk
dex
class
dotnet-assembly
native-binary
script
decompiled-source
fetched-content
report
qa-report
```

`work_items`

```text
id text primary key
run_id text not null
stable_key text not null
target_artifact_id text
target text not null
operation text not null
category text not null
title text not null
status text not null
priority integer not null default 100
depends_on_json text not null
payload_json text not null
attempts integer not null default 0
lease_owner text
lease_expires_at text
created_at text not null
updated_at text not null
terminal_at text
result_json text
error text
unique(run_id, stable_key)
```

Statuses:

```text
queued -> leased -> done
                 -> failed
                 -> needs_review
                 -> needs_evidence
                 -> deferred
                 -> blocked
```

Terminal states:

```text
done, failed, needs_review, deferred, blocked
```

`needs_review` is terminal for the automated run but not a success. It means the
report can be generated honestly with an open review requirement.

Operations:

```text
inventory
expand-container
scan-source
scan-binary
decompile
rescan-derived-source
compose-mcd
review-finding
review-lead
fetch-remote-content
decode-payload
dynamic-plan
dynamic-execute
network-capture
render-report
```

`observations`

```text
id text primary key
run_id text not null
artifact_id text
atom text not null
confidence real not null
method text not null
rule_id text
taxonomy_refs_json text
location_json text not null
evidence_json text not null
relationships_json text not null
created_at text not null
```

`findings`

```text
id text primary key
run_id text not null
lens text not null
composition text
title text not null
claim text not null
severity text not null
confidence real not null
confidence_label text
evidence_json text not null
disproof_json text not null
verification_json text not null
response_json text not null
amplifiers_json text
attenuators_json text
taxonomy_refs_json text not null
created_at text not null
```

`taxonomy_refs`

```text
id text primary key
run_id text not null
ref_type text not null
ref_id text not null
taxonomy_path text not null
taxonomy_sha256 text
owner_kind text not null
owner_id text not null
created_at text not null
```

Example `ref_type` values:

```text
atom
idiom
mcd-indicator
mcd-composition
mcd-verification
mcd-response
mcd-signal
investigation-method
```

`evidence_refs`

```text
id text primary key
run_id text not null
work_item_id text
finding_id text
observation_id text
artifact_id text
path text
start_line integer
end_line integer
snippet text
snippet_sha256 text
redaction_json text
created_at text not null
```

`judgments`

```text
id text primary key
run_id text not null
work_item_id text not null
finding_id text
reviewer text not null
model text
verdict text not null
reviewed_confidence real
response_tier integer
excluded_from_disposition integer not null default 0
justification text not null
disproof_checked_json text not null
references_json text not null
usage_json text
created_at text not null
```

Verdicts:

```text
confirm
escalate
deescalate
refute
suppress
needs_evidence
needs_human
```

`qa_suggestions`

```text
id text primary key
run_id text not null
source_report_id text
kind text not null
status text not null
finding_ids_json text not null
rule_ids_json text not null
taxonomy_refs_json text not null
suggestion text not null
rationale text not null
evidence_json text not null
estimated_noise_reduction text
risk_json text not null
created_by text not null
created_at text not null
```

QA suggestion kinds:

```text
raise-threshold
add-attenuator
add-disproof
split-rule
merge-rule
add-allowlist-pattern
improve-evidence-requirement
update-taxonomy-guidance
needs-human-rule-review
```

Statuses:

```text
suggested
accepted
rejected
deferred
implemented-outside-run
```

QA suggestions are advisory. They never mutate scanner rules, taxonomy docs, or
prior findings during the same scan.

`approvals`

```text
id text primary key
run_id text not null
kind text not null
status text not null
request_json text not null
policy_json text not null
decision_json text
created_at text not null
decided_at text
```

Approval kinds:

```text
network-fetch
registry-query
tool-install
decompile-large-artifact
dynamic-execution
network-capture
send-evidence-to-model
```

`tool_runs`

```text
id text primary key
run_id text not null
work_item_id text
tool_id text not null
tool_version text
command_json text not null
sandbox_provider text
policy_json text not null
started_at text not null
completed_at text
exit_code integer
stdout_ref text
stderr_ref text
outputs_json text not null
error text
```

`network_fetches`

```text
id text primary key
run_id text not null
work_item_id text
url text not null
method text not null
status_code integer
content_type text
sha256 text
artifact_id text
policy_json text not null
approval_id text
created_at text not null
```

`graph_events`

```text
id text primary key
run_id text not null
node text not null
event text not null
payload_json text not null
created_at text not null
```

`reports`

```text
id text primary key
run_id text not null
format text not null
path text not null
sha256 text
created_at text not null
```

Optional `index.db` tables:

`projects_index`

```text
project_id text primary key
project_slug text not null
project_hash text not null
target_root text not null
git_root text
git_remote text
created_at text not null
updated_at text not null
```

`runs_index`

```text
run_id text primary key
project_id text not null
run_dir text not null
db_path text not null
status text not null
target_path text not null
created_at text not null
updated_at text not null
completed_at text
report_html_path text
report_md_path text
report_json_path text
summary_json text
```

These index tables are convenience caches. The run-local database remains the
source of truth.

### Work Item Stable Keys

Stable keys must be derived from durable identity:

```text
sha256(run_id-neutral target identity + operation + payload identity)
```

Examples:

```text
source:src/install.js:scan-source
artifact:sha256:<hash>:scan-binary
finding:mcd-007:review-finding
url:https://example.com/install.sh:fetch-remote-content
jar:sha256:<hash>:jadx
```

Never derive stable keys from list index or model output order.

## Graph Design

Use Pydantic Graph as the phase controller. The graph state is intentionally
small:

```python
from dataclasses import dataclass
from pathlib import Path

@dataclass
class MCDGraphState:
    run_id: str
    project_id: str
    run_dir: Path
    db_path: Path
    target_path: Path
    iteration: int = 0
    max_iterations: int = 50
```

Dependencies carry heavy objects:

```python
@dataclass
class MCDGraphDeps:
    ledger: LedgerStore
    scanner: Scanner
    taxonomy: TaxonomyProvider
    sandbox: SandboxProvider
    tool_resolver: ToolResolver
    reviewer: Reviewer | None
    reporter: Reporter
```

### High-Level Flow

```text
InitializeRun
  -> LoadTaxonomy
  -> PrepareSandbox
  -> InventoryTarget
  -> ExpandContainers
  -> ResolveToolchain
  -> ProcessWorkQueue
  -> ComposeFindings
  -> EnqueueReviews
  -> ReviewBatch
  -> HandleFollowups
  -> CoverageGate
      -> ProcessWorkQueue
      -> RenderReport
          -> PostReportQA
          -> Completed
      -> HumanBlocked
      -> Failed
```

### Node Responsibilities

`InitializeRun`

* Resolve or create project id and run id.
* Create or resume run directory.
* Create or open run-local `run.db`.
* Create or update optional project `index.db`.
* Create or resume `runs`.
* Validate target path.
* Persist config and model profile.
* Create initial `inventory` work item.
* Record `graph_events`.

`LoadTaxonomy`

* Resolve taxonomy provider from `--taxonomy-root`, `PRLX_TAXONOMY_ROOT`, or
  packaged vendored taxonomy.
* Validate required MCD roots exist.
* Persist taxonomy manifest in `runs.taxonomy_manifest_json`.
* Record graph event with manifest id, source commit, and file hash summary.

`PrepareSandbox`

* Select sandbox provider.
* Validate read/write mounts.
* Validate network policy.
* Validate run-scoped writable directories.
* Record sandbox capabilities and limits in `runs.sandbox_profile_json`.

`InventoryTarget`

* Walk files without executing target code.
* Classify source, manifest, archive, bytecode, native binary, packed artifact.
* Insert `artifacts`.
* Generate bounded target tree artifacts for agent/report orientation.
* Enqueue scan, expansion, and binary triage work items.

`ExpandContainers`

* Expand supported source containers: zip, tar, tgz, asar, jar/apk when safe.
* Record extracted files as child artifacts with stable `container!member`
  logical paths.
* Enqueue `scan-source`, `scan-binary`, or `decompile` work as applicable.
* Never execute extracted content.

`ResolveToolchain`

* Run `mcd tools doctor` internally.
* Record available tools and missing capabilities.
* Convert missing tools into coverage notes and optional `tool-install`
  approvals.

`ProcessWorkQueue`

* Lease a bounded batch of actionable non-terminal work.
* Dispatch operation-specific workers.
* Record every tool run, failure, output artifact, and new work item.
* Keep concurrency bounded and policy-aware.

`StaticScan`

* Run source scanner on source artifacts.
* Insert observations.
* Avoid duplicate observations using stable observation keys.

`BinaryTriage`

* Identify format, strings, imports, sections, embedded paths, entropy, magic.
* Enqueue decompilation if the artifact and policy support it.
* Emit observations with method `binary-strings`, `binary-imports`, etc.
* Attenuate confidence for string-only evidence.

`Decompile`

* Use tool resolver to select provider:
  * JADX for APK/DEX/JAR where appropriate.
  * dex2jar plus Java decompiler when useful.
  * Ghidra or rizin/radare2 for native binaries.
  * ILSpy for .NET assemblies.
  * CFR/Procyon/Fernflower for Java bytecode if JADX is not the best fit.
* Run tools in sandbox.
* Record outputs as `decompiled-source` artifacts.
* Enqueue `rescan-derived-source`.
* Record blind spots when tools are missing or fail.

`ComposeFindings`

* Apply MCD BP-* readings over observations and inventory.
* Load composition, verification, disproof, response, and signal metadata from
  the taxonomy provider.
* Persist `taxonomy_refs` for produced findings.
* Build or update scan report.
* Build assessment draft.
* Preserve deterministic disposition.

`EnqueueReviews`

* Select findings that need review:
  * high/critical severity;
  * confidence near disposition thresholds;
  * binary-string-only findings;
  * dynamic/network verification requested;
  * decompiler failures near suspicious artifacts;
  * user-requested review budget.
* Create `review-finding` work items.

`ReviewBatch`

* Invoke Pydantic AI reviewer on one finding or a small batch.
* Use typed output for single-item review.
* Use record tools for batch review so coverage is not limited by final output.
* Reviewers may propose follow-up work, but the graph validates and enqueues it.
* Record judgments and usage.

`NetworkFetch`

* Fetch approved remote content as evidence.
* Save body as `fetched-content` artifact.
* Enqueue scan/decode work for fetched content.
* Never execute fetched content.

`HandleFollowups`

* Convert review output, fetch results, decompiler outputs, and new observations
  into additional work items.
* Deduplicate by stable key.

`CoverageGate`

* Ask the ledger:
  * Are non-terminal actionable items left?
  * Are only blocked or human-review items left?
  * Did this iteration make progress?
  * Have we hit iteration, cost, item, or time limits?
* Return the next graph node:
  * `ProcessWorkQueue` if more work is actionable.
  * `RenderReport` if all automated work is terminal.
  * `HumanBlocked` if approvals or human review are required.
  * `Failed` for invariant failures.

`RenderReport`

* Rebuild the assessment from persisted observations/findings/judgments.
* Include taxonomy manifest and taxonomy references in JSON.
* Render HTML, Markdown, and JSON.
* Write reports under `run_dir/reports/`.
* Persist reports as artifacts and rows in `reports`.
* Update `run.json` and optional `index.db` with final report paths.

`PostReportQA`

* Optional node controlled by `--post-report-qa`.
* Read the rendered report plus ledger rows for suppressed, refuted, and
  deescalated findings.
* Cluster repeated suppress/deescalate reasons by rule id, taxonomy ref, atom,
  detector, artifact type, and evidence shape.
* Suggest rule or taxonomy changes that may reduce future noise.
* Persist suggestions in `qa_suggestions`.
* Render `reports/qa.json` and `reports/qa.md`.
* Never alter findings, judgments, rule packs, or taxonomy files in-place.

### Graph Loop Semantics

The graph may loop. That is intentional.

But every loop must satisfy at least one condition:

* new work item inserted;
* existing work item moved to terminal;
* approval requested;
* report rendered;
* post-report QA rendered;
* explicit terminal stop reached.

If no progress occurs for `idle_rounds` iterations, the run becomes `blocked` or
`partial`, not "complete".

## Pydantic AI Reviewer Design

Reviewer outputs should be typed and narrow.

Single finding review:

```python
from typing import Literal
from pydantic import BaseModel, Field

class FindingReview(BaseModel):
    finding_id: str
    verdict: Literal[
        "confirm",
        "escalate",
        "deescalate",
        "refute",
        "suppress",
        "needs_evidence",
        "needs_human",
    ]
    reviewed_confidence: float = Field(ge=0.0, le=1.0)
    response_tier: int = Field(ge=0, le=5)
    excluded_from_disposition: bool = False
    justification: str
    disproof_checked: list[str] = []
    references: list[str] = []
    followups: list["FollowupRequest"] = []
```

Follow-up request:

```python
class FollowupRequest(BaseModel):
    kind: Literal[
        "fetch_remote_content",
        "decode_payload",
        "decompile_artifact",
        "dynamic_plan",
        "human_review",
    ]
    target: str
    rationale: str
    evidence_ids: list[str] = []
```

Batch review should use a record tool:

```python
@agent.tool_plain(name="record_finding_review", sequential=True)
def record_finding_review(note: FindingReview) -> dict:
    ledger.record_judgment(note)
    return {"recorded": note.finding_id}
```

Rules for reviewers:

* Reviewers may only judge existing finding ids.
* Reviewers may not create final report text.
* Reviewers may not change severity directly. Severity is a shape property.
* Reviewers may move confidence through the deterministic adjudication policy.
* Reviewers may propose follow-up work; the graph validates policy and enqueues.
* Unknown, malformed, or incomplete model output becomes `needs_review`, not
  silent absence.

## Post-Report QA Design

The optional QA pass is a rule-quality review, not a finding review. It runs
after the report exists so it can inspect the final disposition, suppressed
findings, deescalated findings, reviewer judgments, coverage notes, and report
language as a whole.

Primary question:

```text
Are we seeing repeated noise patterns that suggest the rule, threshold,
attenuator, disproof criteria, or taxonomy guidance should be adjusted?
```

Inputs:

* final `report.json`;
* `findings` rows;
* `judgments` rows with verdicts `deescalate`, `refute`, or `suppress`;
* observation and evidence refs for those findings;
* taxonomy refs and rule ids;
* target tree summary;
* coverage and toolchain blind spots.

Typed QA output:

```python
from typing import Literal
from pydantic import BaseModel, Field

class RuleTuningSuggestion(BaseModel):
    kind: Literal[
        "raise-threshold",
        "add-attenuator",
        "add-disproof",
        "split-rule",
        "merge-rule",
        "add-allowlist-pattern",
        "improve-evidence-requirement",
        "update-taxonomy-guidance",
        "needs-human-rule-review",
    ]
    finding_ids: list[str]
    rule_ids: list[str] = []
    taxonomy_refs: list[str] = []
    suggestion: str
    rationale: str
    evidence: list[str] = []
    estimated_noise_reduction: str | None = None
    risk: str = Field(description="What could become a false negative")
```

QA rules:

* Only review findings already deescalated, refuted, or suppressed.
* Require at least one concrete finding id for every suggestion.
* Prefer clusters over one-off suggestions.
* Call out false-negative risk for every proposed noise reduction.
* Never suggest suppressing a high-severity composition solely because it is
  common.
* Never mutate rules automatically.
* Treat missing decompiler, missing network fetch, and missing dynamic evidence
  as coverage problems, not noise problems.

Example output:

```json
{
  "kind": "add-attenuator",
  "finding_ids": ["finding-12", "finding-19", "finding-21"],
  "rule_ids": ["js.exec.shell.literal"],
  "taxonomy_refs": ["lenses/mcd/indicators/EXEC.md"],
  "suggestion": "Consider attenuating install-script shell findings when the command is a package-manager lifecycle wrapper with no network, decode, write-outside-project, or credential atoms.",
  "rationale": "Three suppressed findings had the same shell wrapper shape and no supporting malicious-code indicators.",
  "evidence": ["judgment-7", "judgment-13", "judgment-18"],
  "estimated_noise_reduction": "Would remove three low-confidence findings from this run.",
  "risk": "Could hide simple shell-based droppers if supporting network or file-write atoms are missed."
}
```

The generated QA artifact should be clearly labeled as engineering feedback:
useful for maintaining rule quality, not part of the target disposition.

## Sandboxing Strategy

MCD handles hostile inputs. Sandboxing is not optional for anything that runs
tools over untrusted bytes, and especially not for dynamic execution.

Use explicit execution tiers:

### Tier 0: Static Read-Only

Default.

* Read target files.
* Parse source.
* Extract strings and metadata.
* No target code execution.
* No network except model provider if the user enabled agentic review.

### Tier 1: Trusted Tools Over Untrusted Input

Examples:

* archive extraction;
* decompilers;
* strings/import extraction;
* hex/binary inspection;
* tree-sitter parsing.

Policy:

* target mounted read-only;
* writable output only in run directory;
* no network;
* CPU, memory, output, file count, and time limits;
* tool stdout/stderr captured;
* tool version recorded.

### Tier 2: Limited Network Evidence Retrieval

Examples:

* source contains `curl https://example/install.sh | sh`;
* source downloads a second-stage script;
* package references a registry artifact;
* verification requires package metadata.

Policy:

* HTTP(S) GET/HEAD only by default;
* no execution of fetched content;
* no credentials;
* no POST/PUT/DELETE;
* block private IP ranges, link-local, localhost, Unix sockets, and metadata
  endpoints;
* redirect limit;
* size limit;
* content saved as artifact;
* approval event recorded;
* fetched content becomes new work.

### Tier 3: Dynamic Execution

Examples:

* run selected branch in a VM/container to observe behavior;
* network capture with sinkholed DNS/proxy;
* emulate a native code fragment.

Policy:

* explicit user approval;
* isolated environment;
* no real credentials;
* no write access to host target;
* network sinkhole or allowlisted proxy;
* full audit log;
* not required for default disposition.

## Monty vs OpenShell

### Monty

Monty is a good fit for sandboxing model-written orchestration code and Pydantic
AI CodeMode style tool batching. It is not a full replacement for an OS sandbox.

Use Monty for:

* letting a reviewer write small Python snippets that call approved MCD tools as
  host functions;
* batching calls like `get_evidence`, `search_observations`, `record_review`;
* filtering and ranking evidence without extra model turns;
* low-latency, resource-limited code execution where third-party libraries and
  full CPython are not needed.

Do not use Monty for:

* running Ghidra, JADX, ILSpy, npm, uv, shell scripts, or target code;
* decompiling large binaries directly;
* third-party Python libraries;
* anything that needs full filesystem or process semantics.

The Monty provider should expose only host functions:

```python
class MontySandboxProvider(SandboxProvider):
    def run_reviewer_code(self, code: str, allowed_functions: dict) -> MontyResult:
        ...
```

The host functions enforce ledger and policy:

```text
get_finding(finding_id)
get_evidence(evidence_id)
search_evidence(query)
request_followup(...)
record_review(...)
```

### OpenShell

OpenShell should be treated as an optional full-command sandbox provider if it
has stable public APIs and installable releases when implementation starts.

Use OpenShell for:

* cross-platform command execution policies;
* decompiler/tool execution over untrusted inputs;
* filesystem and network guardrails;
* user approval integration, if exposed.

Do not hard-depend on OpenShell until the API is verified. The design should
define a provider interface and implement OpenShell behind it.

Provider interface:

```python
class SandboxProvider(Protocol):
    id: str
    capabilities: SandboxCapabilities

    def prepare(self, run: RunRecord, policy: SandboxPolicy) -> SandboxSession: ...
    def run_tool(self, session: SandboxSession, request: ToolRunRequest) -> ToolRunResult: ...
    def fetch_url(self, session: SandboxSession, request: NetworkFetchRequest) -> NetworkFetchResult: ...
    def close(self, session: SandboxSession) -> None: ...
```

Required capabilities:

```text
read_only_mounts
writable_run_dir
deny_network
allowlisted_network
resource_limits
stdout_stderr_capture
exit_code_capture
env_scrubbing
process_timeout
```

Optional capabilities:

```text
packet_capture
dns_sinkhole
snapshot_restore
nested_sandbox
interactive_approval
```

### Fallback Providers

`local_readonly`

* No command execution.
* Static scanner only.
* Always available.

`subprocess_provider`

* Last-resort local subprocess wrapper.
* Disabled for dynamic execution.
* May run trusted tools over untrusted files only when user opts in.
* Must still enforce timeouts, output limits, env scrubbing, and run-dir writes.

`container_provider`

* Future optional provider using Docker/Podman.
* Better for full dynamic execution.
* Not a core requirement.

## Network Policy

Default is offline.

Network mode values:

```text
offline
  No target-derived network access. Registry/enrichment unavailable.

registry
  Allow package-registry metadata queries through built-in clients only.

fetch-only
  Allow approved HTTP(S) GET/HEAD of URLs discovered in evidence.

dynamic
  Allow approved dynamic sandbox network through sinkhole/proxy only.
```

Approval policy:

```yaml
network:
  mode: fetch-only
  autoApprove:
    - kind: network-fetch
      when:
        source: referenced-in-target
        scheme: [https]
        method: [GET, HEAD]
        destination: public-internet
        maxBytes: 1048576
      actions:
        - save-artifact
        - scan-fetched-content
      forbidden:
        - execute
        - send-credentials
        - post
        - private-address
```

The important `curl | sh` behavior:

* Detect the pipe-to-shell shape.
* Create a `fetch-remote-content` work item for the URL.
* If policy allows, fetch the script as bytes/text.
* Store the script as `fetched-content`.
* Scan it as a new artifact.
* If the script downloads more content, create more work.
* Never run it.

Registry metadata:

* npm, PyPI, crates.io, Maven, NuGet, GitHub release metadata should use
  specific clients, not arbitrary browser access.
* Responses are cached with TTL and recorded in the ledger.
* Offline absence should attenuate confidence or produce a coverage note, not
  silently remove a finding.

## Toolchain Strategy

The toolchain needs two modes:

1. Basic static scan works with only the Python package.
2. Rich binary/decompilation scan can locate or install external tools.

### Tool Profiles

`static`

* source scanner;
* manifest parser;
* archive/source-container expansion;
* strings/imports where available from Python.

`source`

* static plus:
* ripgrep;
* tree-sitter grammars;
* package metadata clients;
* uv/npm for metadata inspection only, not install execution by default.

`binary`

* source plus:
* file/magic detection;
* strings/xxd/hexdump or Python equivalents;
* rizin/radare2 optional;
* JADX/dex2jar/Java decompiler;
* ILSpy;
* Ghidra.

`full`

* binary plus:
* Unicorn engine for controlled emulation experiments;
* dynamic sandbox provider;
* network capture tooling.

### Tool Manifest

Each external tool has a manifest:

```json
{
  "id": "jadx",
  "name": "JADX",
  "capabilities": ["decompile-dex", "decompile-apk", "decompile-jar"],
  "version": "1.5.x",
  "license": "Apache-2.0",
  "platforms": {
    "darwin-arm64": {
      "url": "...",
      "sha256": "...",
      "bin": "bin/jadx"
    }
  },
  "requires": ["java>=17"],
  "sandboxTier": 1,
  "notes": "Runs trusted decompiler code over untrusted input; no network."
}
```

Tool resolver order:

1. Explicit config path.
2. Run-local tool cache.
3. User tool cache.
4. PATH.
5. Managed install if allowed.
6. Missing capability note.

Suggested cache:

```text
~/.cache/prlx-mcd/tools/<tool>/<version>/<platform>/
```

The cache must store:

* manifest;
* sha256;
* license;
* install timestamp;
* provenance URL;
* verification status.

### Tool List

Core utilities:

* `rg` for fast text search.
* internal tree generator for bounded target structure views.
* external `tree` optional for familiar CLI formatting.
* `uv` for controlled Python dependency metadata and isolated helper execution.
* `npm` and `node` for package metadata and JS parsing helpers.
* `python` for the runner itself.
* `java` for Java decompilers and Ghidra.
* `dotnet` where ILSpy requires it.
* `file`, `strings`, `xxd`, `hexdump` where available, with Python fallbacks.

Archive/source expansion:

* Python stdlib zip/tar/gzip where possible.
* ASAR extractor implementation.
* 7zip optional for broad archive support.

Java/Android:

* JADX for APK/DEX/JAR source recovery.
* dex2jar for DEX -> JAR when useful.
* CFR, Procyon, or Fernflower as Java bytecode fallback.

.NET:

* ILSpy command-line decompiler.

Native:

* Ghidra headless analyzer for decompilation.
* rizin/radare2 for lighter inspection.
* objdump/llvm-objdump where present.
* LIEF or equivalent Python package for structured binary metadata if acceptable.

Emulation:

* Unicorn as optional advanced provider.
* Use only for narrow, explicit emulation tasks, never broad arbitrary execution.

Hex/binary inspection:

* Python binary preview fallback.
* `xxd`/`hexdump` if present.
* `hexyl` optional for nicer CLI output.
* Report should include offsets and snippets, not require an interactive hex UI.

### Packaging Policy

Do not bundle huge third-party tools in the core wheel.

Use:

* small core package;
* `mcd tools doctor`;
* optional managed downloads with checksum pinning;
* optional "full lab" container image later;
* documented BYO paths.

Managed install must require approval unless configured:

```text
mcd tools install jadx --yes
mcd tools install ghidra --yes
mcd run target --allow-tool-install jadx,ilspy
```

Reports must state:

* which tools were available;
* which tools ran;
* which tools were missing;
* which artifacts were not deeply analyzed because a tool was missing or denied.

## Report Design

Keep the current report structure. Add sections.

### JSON Additions

Top-level additions:

```json
{
  "ledger": {
    "runId": "...",
    "projectId": "...",
    "runDir": "...",
    "dbSchemaVersion": "0.1.0",
    "coverage": {
      "workItemsTotal": 0,
      "done": 0,
      "failed": 0,
      "blocked": 0,
      "needsReview": 0,
      "deferred": 0
    }
  },
  "taxonomy": {
    "id": "parallax-taxonomy",
    "sourceGitCommit": "...",
    "manifestSha256": "...",
    "includedRoots": [
      "ontology",
      "enrichment",
      "investigation",
      "lenses/mcd"
    ]
  },
  "sandbox": {
    "provider": "openshell",
    "networkMode": "fetch-only",
    "dynamicExecution": "not-run",
    "executedUntrustedCode": false
  },
  "toolchain": {
    "profile": "binary",
    "available": [],
    "missing": [],
    "ran": []
  },
  "networkFetches": [],
  "tree": {
    "textPath": "artifacts/tree/target-tree.txt",
    "jsonPath": "artifacts/tree/target-tree.json",
    "summary": {
      "files": 0,
      "directories": 0,
      "truncated": false
    }
  },
  "graph": {
    "iterations": 0,
    "nodesRun": [],
    "stoppedReason": "completed"
  },
  "postReportQa": {
    "enabled": false,
    "suggestions": [],
    "artifactPaths": []
  }
}
```

### Markdown/HTML Additions

Add near the top:

* Coverage summary.
* Taxonomy version and source summary.
* Compact target tree summary.
* Sandbox/network policy summary.
* Toolchain coverage.

Add after findings:

* Taxonomy references for findings and verification guidance.
* Review/adjudication details.
* Network fetches.
* Decompilation and binary blind spots.
* Optional post-report QA suggestions for rule tuning.
* Graph timeline, collapsed in HTML.

Keep the current strengths:

* disposition banner;
* executive summary;
* independent severity/confidence;
* evidence and disproof;
* verification tasks;
* correlations;
* reachability;
* enrichment;
* coverage notes.

Post-report QA should be visually separate from target assessment. It should use
language such as "Rule tuning candidates" rather than "Additional findings" so
users do not confuse scanner-maintenance feedback with evidence about the target.

## Approval UX

Approvals are ledger rows, not prompts hidden in model context.

Example pending approval:

```json
{
  "id": "appr-123",
  "kind": "network-fetch",
  "status": "pending",
  "request": {
    "url": "https://example.com/install.sh",
    "reason": "Referenced by curl|sh in setup.py",
    "action": "GET and save only",
    "maxBytes": 1048576
  },
  "policy": {
    "executeFetchedContent": false,
    "sendCredentials": false
  }
}
```

CLI:

```text
mcd status --run-id run-123
mcd approve --run-id run-123 appr-123 --yes
mcd approve --run-id run-123 appr-123 --deny "external network not allowed for this run"
```

Auto approval is allowed only when the config is explicit and narrow. Every
auto-approved action still records an approval row with `status=auto-approved`.

## Error Handling

All per-item failures become ledger state.

Examples:

* Decompiler crashes on one APK: item `failed`, report notes blind spot, run can
  continue.
* Reviewer returns malformed JSON: item `needs_review`, report notes open review.
* Network fetch denied: item `blocked` or `deferred`, report notes content was not
  fetched.
* Tool missing: item `blocked` if necessary for requested depth, otherwise
  coverage note.

The run fails only for system invariants:

* target unreadable;
* ledger corruption;
* schema migration failure;
* report cannot be rendered;
* configured policy impossible to satisfy.

## Security Invariants

1. Target code is never executed in the default path.
2. Fetched remote content is never executed by the fetch node.
3. Model output never directly selects final completion.
4. Model output never directly mutates the ledger except through validated
   record tools.
5. Every external command is recorded as a `tool_runs` row.
6. Every network access is recorded as a `network_fetches` row.
7. Every approval is recorded as an `approvals` row.
8. Missing coverage is visible in the report.
9. Severity is not changed by reviewer whim.
10. Confidence changes are policy-derived and auditable.
11. Post-report QA suggestions never mutate findings, rules, or taxonomy files
    automatically.
12. Noise-reduction suggestions must state false-negative risk.

## Implementation Plan

### Milestone 0: Report And Taxonomy Contract Lock

* Capture current MCD JSON/Markdown/HTML fixtures.
* Capture current Parallax taxonomy roots needed by MCD:
  * ontology atoms and idioms;
  * MCD indicators;
  * BP-* compositions;
  * verification guidance;
  * response tiers;
  * enrichment signals.
* Define vendored taxonomy manifest schema.
* Add compatibility tests for:
  * disposition;
  * confidence/severity separation;
  * review overlay;
  * binary coverage notes;
  * dynamic verification "not run" contract.
* Define report schema version.

Acceptance:

* New renderer can reproduce current fixture semantics.
* Vendored taxonomy resolves BP-* compositions and required indicator families.
* No `.git`, `.venv`, cache, or local test residue appears in vendored taxonomy.

### Milestone 1: Run Storage And SQLite Ledger

* Implement project id and run id generation.
* Implement `.mcd/projects/<project>/runs/<run>/` layout.
* Implement `run.json`.
* Implement optional project `index.db`.
* Implement schema and migrations.
* Implement work item enqueue/lease/transition.
* Implement artifact, observation, finding, judgment, approval, tool run, report
  storage.
* Implement coverage summary.
* Store taxonomy manifest and taxonomy references.

Acceptance:

* Crash/reopen test proves run can resume.
* Duplicate enqueue test proves stable keys work.
* Many concurrent scans create separate run directories and do not contend on a
  shared run database.
* `mcd list` can rebuild its index from run directories.

### Milestone 2: Graph Skeleton

* Implement graph state/deps.
* Implement `InitializeRun`, `InventoryTarget`, `StaticScan`,
  `ComposeFindings`, `CoverageGate`, `RenderReport`.
* Implement `LoadTaxonomy` and fail early when required taxonomy data is absent.
* Generate bounded target tree artifacts during inventory.
* Run static source-only MCD with no model and no network.

Acceptance:

* `mcd run fixture/evil-npm` produces report from ledger state.
* Report includes project id, run id, run directory, and taxonomy manifest.
* `mcd tree fixture/evil-npm` and `mcd tree --run-id <id>` return bounded
  text/JSON views.

### Milestone 3: Sandbox Provider Interface

* Implement `local_readonly`.
* Implement subprocess provider for trusted tools with timeouts and output caps.
* Add Monty provider for reviewer code/tool batching.
* Add OpenShell provider stub behind feature flag until API is verified.

Acceptance:

* Tool execution policy is recorded.
* Default scan uses no command execution unless needed.

### Milestone 4: Tool Doctor And Tool Resolver

* Implement manifests.
* Implement `mcd tools doctor`.
* Implement BYO/PATH/cache resolution.
* Implement missing-tool coverage notes.

Acceptance:

* Report states decompilation coverage accurately on a host with no decompilers.

### Milestone 5: Container Expansion And Binary Triage

* Implement archive/asar/source-container expansion.
* Implement binary metadata and string triage.
* Enqueue derived source rescans.

Acceptance:

* ASAR/zip fixture reveals nested malicious JS and scans it.

### Milestone 6: Decompiler Integration

* Add JADX/dex2jar/Java decompiler.
* Add ILSpy.
* Add Ghidra/rizin optional providers.
* Add strict sandbox and output limits.

Acceptance:

* Missing decompiler gives coverage note.
* Available decompiler produces derived source artifact and rescan.

### Milestone 7: Agentic Review

* Implement Pydantic AI reviewer schemas.
* Implement one-finding review.
* Implement batch record-tool review.
* Fold judgments into adjudication overlay.
* Define post-report QA schemas, but keep QA disabled by default.

Acceptance:

* Reviewer cannot drop findings silently.
* Reviewed disposition recomputes from judgment state.

### Milestone 8: Network Fetch Policy

* Implement approval table and CLI.
* Implement `fetch-only` mode.
* Implement auto-approval for narrow public HTTP(S) fetches.
* Rescan fetched content.

Acceptance:

* `curl URL | sh` fixture fetches and scans URL content when policy allows.
* Same fixture reports blocked fetch when policy denies.
* Fetched content is never executed.

### Milestone 9: MCP Surface

* Implement MCP server over same CLI/API.
* Add tools: scan, resume, status, approve, report, tools_doctor.

Acceptance:

* MCP scan and CLI scan produce the same ledger/report outputs.

### Milestone 10: Full Report Polish

* Add ledger coverage section.
* Add taxonomy version and references section.
* Add target tree summary and links to tree artifacts.
* Add sandbox/network/toolchain sections.
* Add optional post-report QA section.
* Add graph timeline.
* Keep current visual quality.

Acceptance:

* Report remains at least as useful as current MCD report and adds no noisy
  agent meta-commentary.

### Milestone 11: Optional Post-Report QA

* Implement `PostReportQA`.
* Cluster suppressed, refuted, and deescalated findings.
* Generate rule-tuning suggestions with false-negative risk.
* Persist `qa_suggestions`.
* Render `reports/qa.json` and `reports/qa.md`.

Acceptance:

* QA never changes findings, dispositions, scanner rules, or taxonomy files.
* QA suggestions reference concrete finding ids and rule/taxonomy refs.
* Repeated suppressions produce a tuning candidate; one-off suppressions do not
  create noisy recommendations by default.

## Testing Strategy

Unit tests:

* project id and run id generation;
* run directory path construction;
* index DB rebuild from `run.json`;
* ledger transitions;
* stable keys;
* graph coverage gate;
* tree filtering and truncation;
* taxonomy manifest validation;
* taxonomy provider lookup;
* taxonomy reference recording;
* post-report QA suggestion schema validation;
* post-report QA clustering;
* approval policy;
* network URL blocking;
* reviewer schema validation;
* adjudication confidence rules;
* tool manifest parsing.

Fixture tests:

* benign package -> no MCD findings, honest coverage.
* evil npm package -> BP-SUPPLY/BP-DROPPER as appropriate.
* taxonomy fixture -> resolves BP-* docs, indicator docs, verification docs,
  response tiers, and enrichment signals.
* large tree fixture -> bounded target tree with collapsed dependency/cache
  directories.
* curl-pipe-sh -> fetch-only workflow.
* ASAR nested source -> expansion and scan.
* binary string-only suspicious artifact -> attenuated confidence and blind spot.
* APK/JAR/.NET fixture -> decompiler path if tool available, skip/coverage note
  if missing.

Golden tests:

* current report JSON shape compatibility;
* JSON includes run storage metadata and taxonomy manifest;
* Markdown important sections;
* HTML contains disposition, evidence, disproof, review, coverage, taxonomy
  version, and run directory metadata.
* QA report labels rule-tuning suggestions separately from target findings.

Concurrency tests:

* two scans of the same project create distinct run directories;
* scans of different projects create distinct project ids;
* `index.db` can be updated while independent `run.db` files are active;
* deleting `index.db` and running `mcd list --rebuild-index` recovers prior
  runs from `run.json`;
* report writes are atomic and never expose partial final files.

Security tests:

* private IP fetch blocked;
* localhost fetch blocked;
* metadata endpoint blocked;
* fetched script not executed;
* target write denied in sandbox;
* env secrets not exposed to tool runs.
* QA suggestions cannot write rule or taxonomy files.
* Tree view does not include ignored secret files when policy excludes them.

## Configuration

Example config:

```yaml
run:
  storageRoot: .mcd
  runId: auto
  projectId: auto
  maxIterations: 50
  maxReviewItems: 100
  maxWallSeconds: 1800

taxonomy:
  root: auto
  requireVendoredManifest: true

tree:
  enabled: true
  maxDepth: 4
  maxEntries: 2000
  respectGitignore: true
  includeHidden: false

sandbox:
  provider: auto
  writableOutput: run-dir
  defaultNetwork: deny
  resourceLimits:
    cpuSeconds: 120
    memoryMb: 4096
    outputBytes: 10485760

network:
  mode: fetch-only
  autoApprove:
    - kind: network-fetch
      publicHttpOnly: true
      methods: [GET, HEAD]
      maxBytes: 1048576
      sourceMustBeReferencedInTarget: true

tools:
  profile: binary
  allowManagedInstall: false
  paths:
    ghidra: /opt/ghidra/support/analyzeHeadless

review:
  enabled: true
  model: anthropic:claude-sonnet-4-6
  sendEvidenceToModel: require-approval
  batchSize: 5

postReportQa:
  enabled: false
  mode: rules
  minClusterSize: 2
  includeOneOffs: false
```

## Open Questions

1. Does OpenShell have a stable public API and install story suitable for a first
   implementation? If not, keep it behind the provider interface and ship Monty
   plus local/container providers first.
2. Should the first package live inside `stonefish-labs` or a Python-first repo?
3. Should managed tool installs be implemented before or after decompiler support?
4. Which Java decompiler should be the default fallback behind JADX?
5. Should registry metadata be `registry` mode or part of `fetch-only` mode?
6. How much of the existing Python `parallax-goalpacks` scanner should be
   imported directly versus copied into a new package?
7. Should the TS scanner port remain a separate product path, or eventually feed
   the same ledger schema?
8. Should the vendored taxonomy live inside the Python package, the existing
   `@stonefish-labs/rules` package, or both with a shared manifest generator?
9. Should reports embed excerpts from taxonomy docs, or only references and
   short generated summaries?
10. What retention policy should `mcd clean` encourage for large binary analysis
    outputs and fetched artifacts?
11. Should project hashes include Git remote URL by default, given that it helps
    grouping but may expose repository identity in local indexes?
12. Should post-report QA suggestions be exported as patch-ready taxonomy/rule
    change proposals, or remain report-only until the maintenance workflow is
    clearer?
13. What default tree depth gives agents enough context without bloating every
    prompt or report?

## Recommended First Build Cut

Build the smallest version that proves the architecture:

```text
Python package
vendored Parallax taxonomy manifest
project/run storage layout
SQLite ledger
Pydantic Graph
current MCD scanner/report reused
static source scan
bounded tree view
no network
no decompilers
report rendered from ledger state
```

Then add:

```text
taxonomy-driven verification and response rendering
Monty reviewer batching
post-report rule QA
fetch-only network
tool doctor
container expansion
decompilers
OpenShell provider
MCP surface
```

This keeps the valuable report intact while replacing the fragile loop shape
with explicit, resumable execution.

## External References

* Pydantic Graph overview and graph builder docs:
  <https://pydantic.dev/docs/ai/graph/graph/> and
  <https://pydantic.dev/docs/ai/graph/builder/>
* Pydantic durable execution overview:
  <https://pydantic.dev/docs/ai/integrations/durable_execution/overview/>
* Pydantic AI Harness and CodeMode:
  <https://pydantic.dev/docs/ai/harness/overview/> and
  <https://pydantic.dev/docs/ai/harness/code-mode/>
* Monty:
  <https://github.com/pydantic/monty>
* Local Parallax taxonomy source:
  `parallax-taxonomy`
* Current local MCD report skill:
  `parallax-goalpacks/skills/mcd-report/SKILL.md`
* Current local ledger-harness note:
  `agent-harness-pattern.md`
