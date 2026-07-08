-- unmask run ledger (per-run SQLite database).
--
-- This is the durable source of truth for coverage and resumability. The phase
-- graph reads ledger state to decide what runs next and when a run may finish;
-- the model never decides completion. See docs/design.md "Ledger Model".
--
-- The first build cut writes a subset of the full design schema. Tables/columns
-- are named to match the design so later milestones (approvals, tool_runs,
-- network_fetches, judgments, taxonomy_refs, qa_suggestions) add cleanly.

pragma journal_mode = wal;
pragma synchronous = normal;
pragma busy_timeout = 5000;
pragma foreign_keys = on;

create table if not exists meta (
    key   text primary key,
    value text not null
);

create table if not exists runs (
    id                     text primary key,
    project_id             text not null,
    target_path            text not null,
    target_root            text not null,
    storage_root           text not null,
    run_dir                text not null,
    status                 text not null,          -- queued|running|completed|partial|blocked|failed|canceled
    created_at             text not null,
    updated_at             text not null,
    completed_at           text,
    config_json            text not null,
    coverage_json          text,
    summary_json           text,
    error                  text
);

create table if not exists artifacts (
    id                 text primary key,
    run_id             text not null,
    kind               text not null,             -- source-file|manifest|target-tree|archive|native-binary|dotnet-assembly|jar|apk|dex|script|report|...
    path               text not null,
    logical_path       text not null,
    parent_artifact_id text,
    sha256             text,
    size_bytes         integer,
    media_type         text,
    language           text,
    origin             text not null,             -- inventory|expand|decompile|fetch|report
    metadata_json      text not null default '{}',
    created_at         text not null
);
create index if not exists idx_artifacts_run on artifacts(run_id);

create table if not exists work_items (
    id             text primary key,
    run_id         text not null,
    stable_key     text not null,
    target         text not null,
    operation      text not null,                 -- inventory|scan-source|scan-binary|decompile|compose-mcd|render-report|...
    category       text not null,
    title          text not null,
    status         text not null,                 -- queued|leased|done|failed|needs_review|needs_evidence|deferred|blocked
    priority       integer not null default 100,
    depends_on_json text not null default '[]',
    payload_json   text not null default '{}',
    attempts       integer not null default 0,
    created_at     text not null,
    updated_at     text not null,
    terminal_at    text,
    result_json    text,
    error          text,
    unique(run_id, stable_key)
);
create index if not exists idx_work_run_status on work_items(run_id, status);

create table if not exists observations (
    id                  text primary key,
    run_id              text not null,
    artifact_id         text,
    atom                text not null,
    confidence          real not null,
    method              text not null,            -- source-ast|source-callee|content-regex|binary-strings|...
    rule_id             text,
    location_json       text not null default '{}',
    evidence_json       text not null default '{}',
    relationships_json  text not null default '[]',
    created_at          text not null
);
create index if not exists idx_obs_run on observations(run_id);

create table if not exists findings (
    id                text primary key,
    run_id            text not null,
    lens              text not null,
    composition       text,                       -- BP-SUPPLY|BP-DROPPER|BP-BACKDOOR|...
    title             text not null,
    claim             text not null default '',
    severity          text not null,
    confidence        real not null,
    confidence_label  text,
    evidence_json     text not null default '[]',
    disproof_json     text not null default '[]',
    verification_json text not null default '[]',
    response_json     text not null default '{}',
    amplifiers_json   text,
    attenuators_json  text,
    created_at        text not null
);
create index if not exists idx_findings_run on findings(run_id);

create table if not exists judgments (
    id                        text primary key,
    run_id                    text not null,
    finding_id                text,
    reviewer                  text not null,
    model                     text,
    verdict                   text not null,       -- confirm|escalate|deescalate|refute|suppress|needs_evidence|needs_human
    reviewed_confidence       real,
    response_tier             integer,
    excluded_from_disposition integer not null default 0,
    justification             text not null,
    followups_json            text,
    created_at                text not null
);
create index if not exists idx_judgments_run on judgments(run_id);

create table if not exists qa_suggestions (
    id                        text primary key,
    run_id                    text not null,
    kind                      text not null,       -- raise-threshold|add-attenuator|split-rule|...
    finding_ids_json          text not null,
    rule_ids_json             text not null default '[]',
    suggestion                text not null,
    rationale                 text not null,
    risk                      text not null,       -- false-negative risk of applying it
    estimated_noise_reduction text,
    created_at                text not null
);
create index if not exists idx_qa_run on qa_suggestions(run_id);

create table if not exists graph_events (
    id           text primary key,
    run_id       text not null,
    node         text not null,
    event        text not null,                   -- enter|exit|note|error
    payload_json text not null default '{}',
    created_at   text not null
);
create index if not exists idx_events_run on graph_events(run_id);

create table if not exists reports (
    id         text primary key,
    run_id     text not null,
    format     text not null,
    path       text not null,
    sha256     text,
    created_at text not null
);

-- Durable questions a node could not answer itself. The run finishes `needs_input`
-- with these pending; the orchestrator answers and resumes. Regenerated per drive
-- (re-asked when the graph re-runs), so it IS reset on resume.
create table if not exists questions (
    id           text primary key,               -- content-addressed (prompt+kind+node)
    run_id       text not null,
    node         text not null,
    kind         text not null,                  -- fetch-consent|lead-decision|...
    prompt       text not null,
    options_json text not null default '[]',
    created_at   text not null
);
create index if not exists idx_questions_run on questions(run_id);

-- Answers injected on resume. Keyed by the question's content-addressed id and NOT
-- reset on re-drive, so a resumed run's re-asked question finds its answer.
create table if not exists answers (
    id          text primary key,                -- the question id it answers
    run_id      text not null,
    answer      text not null,
    answered_at text not null
);
create index if not exists idx_answers_run on answers(run_id);
