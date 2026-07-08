# unmask Design

Status: design spec

Audience: contributors working on unmask, a malicious-code detector.

unmask answers one question: is this code doing something malicious, and can you prove it?
It reads a target (source, packages, and, with the RE add-on, binaries), records
judgment-free observations, composes them into deterministic BP-* malicious-code shapes,
and produces a report that keeps severity and confidence separate, states a disposition
(clear / review / quarantine), and shows its evidence, disproof criteria, verification
steps, and coverage blind spots. It runs offline and executes no target code by default.

The deterministic scanner and its report are the quality bar. Bounded model steps assist
(reviewing evidence, proposing follow-ups) but never author a verdict or a coverage claim.
The durable, coverage-gated, resumable runtime is provided by muster (see "Built on
muster" below); this document is about detection.

## Executive Summary

The report is the part worth preserving. It already has the right product model:

* static observations first;
* BP-* malicious-code compositions over those observations;
* severity and confidence kept separate;
* disposition as a deterministic recommendation, not a model verdict;
* evidence, disproof criteria, verification steps, reachability, enrichment, coverage
  notes, and HTML/Markdown/JSON output;
* optional agentic adjudication layered over the deterministic scan.

unmask does not turn this into "ask an agent if the code is malicious". It makes the
deterministic MCD idea more capable:

* discover targets, containers, binaries, and follow-up work incrementally;
* unpack and decompile when tools are available;
* ask a model to review bounded evidence instead of a whole repository;
* fetch limited remote content only with explicit policy;
* resume after crashes and prove coverage from ledger state;
* produce the same quality report, with better coverage and review provenance.

The layers:

* Detection (unmask's core): observations -> BP-* compositions -> disposition -> report.
* Meaning (vendored Parallax taxonomy): ontology atoms, MCD indicators, BP-* compositions,
  verification guidance, response tiers, enrichment signals.
* RE transform seam (unmask-re): unpack / deobfuscate / decompile untrusted input under a
  sandbox policy, then rescan what it recovers.
* Runtime (muster): the phase graph, the SQLite coverage/resume ledger, the work-queue
  drain. The ledger's coverage gate, not the model, decides when a run is done.

## Goals

1. Preserve the existing report quality.
2. Make coverage durable, auditable, resumable, and externally inspectable (provided by muster).
3. Let discovery add new work while the run is already in progress.
4. Use bounded model steps only for review-style tasks with typed outputs.
5. Vendor the Parallax taxonomy as data, not as monolithic engine logic.
6. Support sandboxed unpacking, decompilation, byte inspection, and optional dynamic verification.
7. Support limited network retrieval for evidence, especially cases like `curl ... | sh`,
   without executing fetched content.
8. Package or locate external tools in a predictable, policy-aware way.
9. Keep the default run static, offline, and safe.
10. Expose a CLI and MCP-compatible tool surface.

## Non-Goals

* No free-form "run until the agent says done" loop.
* No model-authored maliciousness verdict.
* No target code execution by default.
* No unbounded network.
* No silent best-effort decompilation. Missing tool coverage must be reported.
* No large binary toolchain bundled into the core package by default.
* No requirement that every host have Docker, Ghidra, Java, .NET, npm, or uv installed
  before a basic static scan works.
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
src/unmask/taxonomy/vendored/
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

## Built on muster

unmask does not design its own runtime. It runs on muster
(github.com/batteryshark/muster), a ledgered investigation runtime that owns the phase
graph, the per-run SQLite ledger (the coverage and resume oracle), the work-queue drain,
and run identity/layout. The ledger's coverage gate, not the model, decides when a run is
complete. See the muster repo for that runtime design.

unmask is a muster consumer: it registers its own domain on top of the shared spine.

* Domain tables: observations (atoms) and findings (BP-* compositions), plus judgments and
  rule-tuning suggestions, layered onto muster's spine (runs, artifacts, work items,
  events, reports, questions/answers).
* Work operations and handlers: scan-source, scan-binary, deobfuscate/decompile
  transforms, fetch, and adaptive leads.
* A coverage predicate: taxonomy rules across artifacts, enumerated and worked off.

Everything below is unmask's domain: what it detects, how it decides, and how it proves it.


## Package Shape

Recommended package layout for the Python rebuild:

```text
packages/mcd-graph/
  pyproject.toml
  scripts/
    vendor_taxonomy.py
  src/unmask/
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
unmask run <target>
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

unmask resume --run-dir .mcd/projects/<project>/runs/<run>
unmask resume --run-id <id>
unmask status --run-id <id>
unmask report --run-id <id> --format html|md|json
mcd qa --run-id <id> --mode rules
unmask tree <target>
unmask tree --run-id <id>
mcd approve --run-id <id> <approval-id>
unmask list --storage-root .mcd
mcd clean --storage-root .mcd --older-than 30d --keep-reports
unmask tools doctor
unmask tools install <tool>
unmask tools list
unmask tools cache
```

Advanced overrides:

```text
unmask run <target> --run-dir <path>
unmask run <target> --project-id <slug-or-id>
unmask run <target> --db <path-to-run.db>
unmask run <target> --shared-db experimental
```

`--db` is an escape hatch, not the default user experience. The normal output of
`unmask run` should print the run id, project id, run directory, report paths, and
the command needed to resume.

Python API:

```python
from unmask import MCDConfig, run_mcd, resume_mcd

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
target. unmask provides that directly instead of shelling out to `find`, `tree`,
or ad hoc recursive listing code.

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
unmask tree <target>
  --max-depth 4
  --max-entries 2000
  --include-hidden false
  --format text|json
  --respect-gitignore true

unmask tree --run-id <id>
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
~/.cache/unmask/tools/<tool>/<version>/<platform>/
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
* `unmask tools doctor`;
* optional managed downloads with checksum pinning;
* optional "full lab" container image later;
* documented BYO paths.

Managed install must require approval unless configured:

```text
unmask tools install jadx --yes
unmask tools install ghidra --yes
unmask run target --allow-tool-install jadx,ilspy
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
unmask status --run-id run-123
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
* deleting `index.db` and running `unmask list --rebuild-index` recovers prior
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

## External References

* muster, the runtime unmask is built on:
  <https://github.com/batteryshark/muster>
* Monty (sandbox provider):
  <https://github.com/pydantic/monty>
* Local Parallax taxonomy source:
  `parallax-taxonomy`
