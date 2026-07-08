-- unmask DOMAIN ledger tables — layered onto muster's core spine.
--
-- muster owns the generic spine (runs, artifacts, work_items, graph_events,
-- reports, questions, answers) and applies it first; this file adds only the
-- malicious-code-detection domain: what we OBSERVED (atoms), what those COMPOSED
-- into (findings), how those were JUDGED (agentic review), and advisory rule-
-- tuning suggestions. Registered via LedgerStore(extra_schema=...). Pragmas and
-- schema-version bookkeeping live in the core spine, not here.

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
