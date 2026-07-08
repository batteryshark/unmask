"""The MCD reading: compose judgment-free atoms into BP-* malicious-code findings.

Ported from the reference `mcd_lens.readings.mcd`, running over native
Observations. Meaning (which atom combinations mean which malicious-code shape)
is preserved exactly; this is the interpretive layer above observe.
"""

from __future__ import annotations

from unmask.scanner.compose.common import *  # noqa: F401,F403 (shared finding/proof helpers)
from unmask.scanner.compose.common import (
    _cooccurrence_disproof, _dataflow_status, _direct_remote_exec, _finding,
    _group_by_file, _has, _ids, _low_reach_path, _mcd_response, _proof_att,
    _reachable_sink_amplifiers, _strong_agent_steering, _uniq, confidence_label,
)


def _mcd_strong_agent_steering(o) -> bool:
    # A bare tool/MCP declaration is an agent surface, not manipulation by itself.
    return o.atom != "AITM.TOOL" and _strong_agent_steering(o)


def _dataflow_proves_dropper(inv, path) -> bool:
    """True if intra-file taint traced a fetched value into an exec/eval/shell sink
    in `path` (a `dropper`-kind dataflow path)."""
    return any(p.get("kind") == "dropper"
               for p in (getattr(inv, "dataflow", None) or {}).get(path, []))


def _attenuate_binary_string_only_findings(findings: list, obs: list) -> list:
    by_id = {o.id: o for o in obs if o.id}
    note = (
        "Binary-string-only evidence: strings prove bytes are present in the artifact, "
        "not that the code path is active; decompilation or dynamic review is required."
    )
    for f in findings:
        evidence = [by_id.get(eid) for eid in f.get("evidence", [])]
        evidence = [o for o in evidence if o is not None]
        if not evidence or not all(o.method == "binary-strings" for o in evidence):
            continue
        f["confidence"] = min(f.get("confidence", 0), 0.54)
        f["confidenceLabel"] = confidence_label(f["confidence"])
        atts = list(f.get("attenuators") or [])
        if note not in atts:
            atts.append(note)
        f["attenuators"] = atts
    return findings


def mcd(obs, inv=None) -> list:
    findings = []
    groups = _group_by_file(obs)
    n = 0

    # BP-SUPPLY: install hook reaches a payload file
    installs = [o for o in obs if o.atom == "PKGM.INSTALL"]
    for inst in installs:
        files = [inst.path] + [r["target"] for r in inst.relationships
                               if r.get("type") == "manifest-entrypoint"]
        payload = []
        for t in files:
            grp = groups.get(t, [])
            payload += _has(grp, "NETW")
            if _has(grp, "LOAD.EVAL") and _has(grp, "XFRM"):  # install-time decode-and-execute
                payload += _has(grp, "LOAD.EVAL")
        if payload:
            n += 1
            ev = [inst.id] + [o.id for o in payload]
            findings.append(_finding(
                f"mcd-{n}", "mcd", "Install-time payload path",
                "A package install hook (npm lifecycle script or Python setup.py) runs network, "
                "shell, or decode-and-execute behavior before any user code is invoked.",
                "high", 0.7, ev,
                disproof=[
                    "The install code is a documented, reproducible build step.",
                    "Fetched/decoded content is version-pinned with integrity (hash/signature) checks.",
                ],
                verification=[
                    {"question": "What does the install hook fetch, decode, or execute, and from where?",
                     "method": "static-source", "reason": "Confirm the payload behavior and destination."},
                    {"question": "Is the destination maintainer-controlled and documented?",
                     "method": "osint", "reason": "Destination reputation changes interpretation."},
                    {"question": "Does behavior differ under CI/sandbox?",
                     "method": "dynamic", "reason": "Install-time gating is a strong malicious signal."},
                ],
                response={"tier": 3, "summary": "Engineering referral + passive monitoring until verified.",
                          "actions": ["Block auto-install in CI until reviewed", "Pin and vendor the dependency"]},
                composition="BP-SUPPLY",
                amplifiers=["Behavior triggers at install, not at explicit use."],
            ))

    # BP-TYPOSQUAT: package name is a near-miss of a popular package (slopsquatting).
    typo = [o for o in obs if o.atom == "PKGM.TYPOSQUAT"]
    phantom = [o for o in obs if o.atom == "PKGM.UNDECLARED"]
    payload_present = bool(installs) or bool(_has(obs, "EXEC", "LOAD.EVAL", "NETW", "XFRM.ENCRYPT"))
    for t in typo:
        n += 1
        amps = []
        if installs:
            amps.append("Ships an install-time hook on top of the look-alike name.")
        if payload_present and not installs:
            amps.append("Carries execution / network / decrypt behavior behind the look-alike name.")
        if phantom:
            amps.append(f"Also imports {len(phantom)} undeclared "
                        f"dependenc{'y' if len(phantom) == 1 else 'ies'}, which a squatter can supply.")
        claim = (t.summary[:1].upper() + t.summary[1:]) if t.summary else \
            "The package name resembles a popular package."
        findings.append(_finding(
            f"mcd-{n}", "mcd", "Typosquat / slopsquat name", claim,
            "high" if payload_present else "medium", t.confidence,
            [t.id] + [o.id for o in phantom[:5]],
            disproof=[
                "The name is an intentional, owned variant or fork of the popular package.",
                "The registry shows an established maintainer, package age, and download history.",
            ],
            verification=[
                {"question": "Does the registry show an established, owned package rather than a recent squat?",
                 "method": "osint", "reason": "Squats are usually newly created with few downloads."},
                {"question": "Does the package's behavior match the popular package it resembles?",
                 "method": "static-source", "reason": "A squat often differs or adds a payload."},
            ],
            response={"tier": 3, "summary": "Verify the package identity against the registry before trusting it.",
                      "actions": ["Confirm the intended package name with the requester",
                                  "Pin the verified package and version"]},
            composition="BP-TYPOSQUAT",
            amplifiers=amps or None,
        ))

    # BP-DROPPER: fetch + write + execute/load in one file
    for path, group in groups.items():
        net = _has(group, "NETW")
        write = _has(group, "FSYS.WRITE")
        run_ = _has(group, "EXEC", "LOAD")
        direct = _direct_remote_exec(group)
        if net and direct and not write:
            n += 1
            ev = _ids(_uniq(net + direct, 8))
            findings.append(_finding(
                f"mcd-{n}", "mcd", "Download-and-execute (direct remote exec)",
                "Code fetches remote content and passes it directly into a shell or dynamic evaluator. "
                "That is the direct remote-execution variant of the dropper shape; no intermediate "
                "file write is required.",
                "high", 0.68, ev,
                disproof=[
                    "The downloaded content is fixed, maintainer-controlled, documented, and integrity-checked before execution.",
                    "The shell/eval sink receives only a trusted local constant, not network content.",
                    _cooccurrence_disproof(),
                ],
                verification=[
                    {"question": "What remote content is executed and who controls it?",
                     "method": "static-source", "reason": "Remote control of the executed bytes is the key risk."},
                    {"question": "Is the downloaded script pinned by hash/signature before execution?",
                     "method": "static-source", "reason": "Integrity verification can disprove the malicious shape."},
                ],
                response={"tier": 4, "summary": "Block or sandbox until the remote payload and integrity story are verified.",
                          "actions": ["Do not pipe remote content to a shell", "Vendor or pin the script with integrity checks"]},
                composition="BP-DROPPER",
                amplifiers=["Remote content is executed directly rather than written and inspected first."],
            ))
        if net and write and run_:
            n += 1
            ev = [o.id for o in (net + write + run_)]
            conf, suffix, extra, amps, atts = _dataflow_status(inv, path, {"dropper"}, 0.65, 0.9)
            findings.append(_finding(
                f"mcd-{n}", "mcd", "Download-and-execute (dropper) path",
                "Code fetches remote content, writes it to disk, and executes or loads code: "
                "the canonical dropper shape." + suffix,
                "high", conf, ev,
                disproof=[
                    "The downloaded content is data, not code, and is never executed/loaded.",
                    "The fetch target and written path are fixed, documented, and integrity-checked.",
                ] + extra,
                verification=[
                    {"question": "Is the written artifact later executed, imported, or loaded?",
                     "method": "static-source", "reason": "Distinguishes a dropper from a normal downloader."},
                    {"question": "What is actually delivered at runtime?",
                     "method": "dynamic", "reason": "Static analysis cannot see the served payload."},
                ],
                response={"tier": 3, "summary": "Treat as suspicious capability until the payload is identified.",
                          "actions": ["Capture the fetched artifact in a sandbox", "Review write path and exec linkage"]},
                composition="BP-DROPPER",
                amplifiers=amps or None,
                attenuators=atts or None,
            ))
        # Dataflow-proven dropper the text heuristics miss: intra-file taint traced a
        # fetched value into an exec/eval/shell sink (e.g. `p = requests.get(u).text;
        # exec(p)`) — a connected path, not co-occurrence — but the sink wasn't a
        # literal curl-pipe/iex string, so branch 1 (direct) didn't fire. Guarded to
        # not duplicate branches 1/2.
        if net and run_ and not write and not direct and _dataflow_proves_dropper(inv, path):
            n += 1
            conf, suffix, extra, amps, atts = _dataflow_status(inv, path, {"dropper"}, 0.7, 0.9)
            ev = _ids(_uniq(net + run_, 8))
            findings.append(_finding(
                f"mcd-{n}", "mcd", "Download-and-execute (dataflow-proven dropper)",
                "Intra-file dataflow traces remote-fetched content into a code-execution sink "
                "(exec/eval/shell) in this file — the download-and-execute dropper shape, proven "
                "by a connected value path rather than mere co-occurrence." + suffix,
                "high", conf, ev,
                disproof=[
                    "The traced value is inert data (config/text), not code, and the sink treats it as data.",
                    "The fetched source is fixed, documented, and integrity-checked before it reaches the sink.",
                ] + extra,
                verification=[
                    {"question": "What is fetched and then executed, and who controls it?",
                     "method": "static-source", "reason": "Remote control of the executed bytes is the key risk."},
                    {"question": "Is the fetched payload pinned by hash/signature before execution?",
                     "method": "static-source", "reason": "Integrity verification can disprove the malicious shape."},
                ],
                response={"tier": 4, "summary": "Block or sandbox until the fetched payload and integrity story are verified.",
                          "actions": ["Do not execute fetched content", "Pin/vendor the payload with integrity checks"]},
                composition="BP-DROPPER",
                amplifiers=amps or None,
                attenuators=atts or None,
            ))

    # BP-CREDTHEFT: credential read + network egress in one file
    for path, group in groups.items():
        cred = _has(group, "CRED")
        net = _has(group, "NETW")
        if cred and net:
            n += 1
            ev = [o.id for o in (cred + net)]
            conf, suffix, extra, amps, atts = _dataflow_status(inv, path, {"exfil"}, 0.6, 0.85)
            findings.append(_finding(
                f"mcd-{n}", "mcd", "Credential access + egress path",
                "Code reads credential-like material and has an outbound network channel in the "
                "same scope, the collection+transmission half of a theft chain." + suffix,
                "high", conf, ev,
                disproof=[
                    "Credentials are user-supplied at call time and sent only to the documented API they authenticate.",
                    "The network call and credential read are not reachable from one another.",
                ] + extra,
                verification=[
                    {"question": "Does the credential value flow into the network request body/headers?",
                     "method": "static-source", "reason": "Reachability separates theft from coincidence."},
                    {"question": "Is the destination the credential's legitimate service?",
                     "method": "osint", "reason": "Destination identity is decisive."},
                ],
                response={"tier": 4, "summary": "Active monitoring; rotate exposed secrets if confirmed.",
                          "actions": ["Trace credential dataflow to the destination", "Rotate any real secrets touched"]},
                composition="BP-CREDTHEFT",
                amplifiers=amps or None,
                attenuators=atts or None,
            ))

    # BP-OBFEXEC: decode/decrypt then execute (the decode-and-execute idiom)
    for path, group in groups.items():
        ev_eval = _has(group, "LOAD.EVAL")
        ev_xfrm = _has(group, "XFRM.ENCODE", "XFRM.ENCRYPT")
        if ev_eval and ev_xfrm:
            n += 1
            ev = [o.id for o in (ev_eval + ev_xfrm)]
            conf, suffix, extra, amps, atts = _dataflow_status(inv, path, {"decode-exec"}, 0.6, 0.85)
            findings.append(_finding(
                f"mcd-{n}", "mcd", "Obfuscated code execution (decode-and-execute)",
                "Code decodes or decrypts a blob and then executes it. The payload is hidden "
                "from static review until it runs." + suffix,
                "high", conf, ev,
                disproof=[
                    "The decoded content is data (config/templates), not code, and is never executed.",
                    "The transform is a documented packaging step over trusted, in-repo content.",
                ] + extra,
                verification=[
                    {"question": "Decode the blob: what does the executed payload do?",
                     "method": "static-source", "reason": "The hidden payload is the whole point."},
                    {"question": "Where does the encoded/encrypted blob originate?",
                     "method": "static-source", "reason": "A local constant vs a fetched blob changes severity."},
                ],
                response={"tier": 3, "summary": "Decode and review the payload before trusting the package.",
                          "actions": ["Statically decode the blob", "Treat as untrusted until the payload is understood"]},
                composition="BP-OBFEXEC",
                amplifiers=amps or None,
                attenuators=atts or None,
            ))

    # BP-BACKDOOR: command channel + execution, or embedded auth bypass material.
    for path, group in groups.items():
        listen = _has(group, "NETW.LISTEN")
        poll = _has(group, "NETW.HTTP", "NETW.WS", "NETW.SOCKET", "NETW.DECENTRAL")
        exec_ = _has(group, "EXEC.SHELL", "EXEC.PROC", "LOAD.EVAL")
        support = _has(group, "PRST", "ENVI", "XFRM")
        if exec_ and (listen or (poll and support)):
            n += 1
            ev = _ids(_uniq((listen or poll) + exec_ + support, 12))
            reach_amps = _reachable_sink_amplifiers(inv, path, {"exec"})
            base_conf = 0.58 if support else 0.52
            conf = round(min(base_conf + 0.07, 0.72), 2) if reach_amps else base_conf
            atts = ["Static rule is a command-channel shape; authorization is not proven."]
            if not reach_amps:
                atts.append(_proof_att("same-file co-occurrence",
                                       "channel and execution atoms share a file; channel-to-exec flow is not proven."))
            findings.append(_finding(
                f"mcd-{n}", "mcd", "Backdoor command channel",
                "Code exposes or polls a command channel and can execute commands or dynamic code "
                "from the same scope. This is the remote-access backdoor shape; static analysis "
                "does not prove the channel is unauthorized.",
                "critical", conf, ev,
                disproof=[
                    "The listener or polling loop is a documented administrative interface with authentication.",
                    "The execution sink cannot be influenced by messages from the channel.",
                    _cooccurrence_disproof(),
                ],
                verification=[
                    {"question": "Can data received from the listener or polling channel reach the execution sink?",
                     "method": "static-source", "reason": "Separates a backdoor from a normal server with local commands."},
                    {"question": "Is the command channel documented, authenticated, and expected for this component?",
                     "method": "osint", "reason": "Authorization and intent are decisive for a backdoor."},
                ],
                response=_mcd_response(5, "Immediate response if reachable or unauthorized; otherwise active review.",
                                       ["Trace channel-to-exec dataflow", "Block exposed listener/polling endpoint until reviewed"]),
                composition="BP-BACKDOOR",
                amplifiers=reach_amps or None,
                attenuators=atts,
            ))

        auth = _has(group, "ARTF.CREDENTIAL", "ARTF.CMD")
        bypass_context = _has(group, "NETW.LISTEN", "PRIV.ACCOUNT", "PRIV.TOKEN", "LOAD", "EXEC")
        if auth and bypass_context:
            n += 1
            findings.append(_finding(
                f"mcd-{n}", "mcd", "Backdoor authentication bypass",
                "Embedded credential or command material sits alongside an access, privilege, load, or "
                "execution surface. This is the hardcoded-bypass variant of a backdoor.",
                "critical", 0.56, _ids(_uniq(auth + bypass_context, 12)),
                disproof=[
                    "The credential is a documented test fixture or public example that grants no access.",
                    "The embedded material is never used in an authentication or privileged path.",
                    _cooccurrence_disproof(),
                ],
                verification=[
                    {"question": "What does the embedded credential or command grant access to?",
                     "method": "static-source", "reason": "A bypass depends on the credential being live and privileged."},
                    {"question": "Is this material a fixture/example excluded from release artifacts?",
                     "method": "osint", "reason": "Fixture credentials are common benign explanations."},
                ],
                response=_mcd_response(5, "Immediate response if the credential is live or privileged.",
                                       ["Invalidate embedded secrets", "Remove hidden account or bypass path"]),
                composition="BP-BACKDOOR",
                attenuators=["Embedded material may be an inert fixture unless use is proven."],
            ))

    # BP-EXFIL: sensitive data collection + outbound channel.
    for path, group in groups.items():
        collect = _has(group, "FSYS.SENSITIVE", "FSYS.CLIPBOARD", "SYSI.PROCMEM")
        net = _has(group, "NETW.HTTP", "NETW.WEBHOOK", "NETW.WS", "NETW.EMAIL", "NETW.FTP", "NETW.SOCKET",
                   "NETW.DNS", "NETW.BROKER", "NETW.DECENTRAL")
        if collect and net:
            n += 1
            conf, suffix, extra, amps, atts = _dataflow_status(inv, path, {"exfil"}, 0.55, 0.82)
            reach_amps = _reachable_sink_amplifiers(inv, path, {"egress"})
            if reach_amps and not amps:
                conf = round(min(conf + 0.04, 0.7), 2)
            findings.append(_finding(
                f"mcd-{n}", "mcd", "Data collection + egress path",
                "Code collects host, process, clipboard, or sensitive-file data and has an outbound "
                "network channel in the same scope: the general exfiltration shape." + suffix,
                "high", conf, _ids(_uniq(collect + net, 12)),
                disproof=[
                    "Collected data is limited telemetry documented by the project and sent to its own service.",
                    "The collected data does not flow into the network request.",
                    _cooccurrence_disproof(),
                ] + extra,
                verification=[
                    {"question": "Does collected host or file data flow into the outbound request payload?",
                     "method": "static-source", "reason": "Reachability separates exfiltration from adjacent telemetry."},
                    {"question": "Is the destination documented and controlled by the project?",
                     "method": "osint", "reason": "Destination identity changes interpretation."},
                ],
                response=_mcd_response(4, "Active monitoring; block egress if sensitive data flow is confirmed.",
                                       ["Trace dataflow from collection to egress", "Add egress allowlist and payload logging"]),
                composition="BP-EXFIL",
                amplifiers=(amps + reach_amps) or None,
                attenuators=(atts + ["Same-file collection and egress is not proof that data is transmitted."]) or None,
            ))

    # BP-RANSOM: enumerate files, encrypt + mutate them.
    for path, group in groups.items():
        enum = _has(group, "FSYS.ENUM", "FSYS.SENSITIVE")
        crypto = _has(group, "CRPT.SYMENC", "CRPT.ASYMENC", "XFRM.ENCRYPT")
        mutate = _has(group, "FSYS.WRITE", "FSYS.DELETE", "FSYS.PERM")
        if enum and crypto and mutate:
            n += 1
            conf, suffix, extra, amps, atts = _dataflow_status(inv, path, {"ransom"}, 0.6, 0.82)
            findings.append(_finding(
                f"mcd-{n}", "mcd", "Ransomware file-encryption path",
                "Code enumerates files and combines encryption with file mutation. That is the "
                "structural precondition for ransomware, though static analysis has not proven intent." + suffix,
                "critical", conf, _ids(_uniq(enum + crypto + mutate, 12)),
                disproof=[
                    "The code is a documented backup, archive, or encryption utility operating only on user-selected files.",
                    "File writes are not derived from enumerated paths.",
                    _cooccurrence_disproof(),
                ] + extra,
                verification=[
                    {"question": "Do enumerated paths feed encryption and overwrite/delete operations?",
                     "method": "static-source", "reason": "The enumerated-path flow is the ransomware mechanism."},
                    {"question": "Are backups, extensions, or ransom-note artifacts modified?",
                     "method": "dynamic", "reason": "Runtime behavior distinguishes bulk encryption from a library."},
                ],
                response=_mcd_response(5, "Immediate response if path flow is confirmed.",
                                       ["Do not execute", "Run only in an isolated sandbox with disposable files"]),
                composition="BP-RANSOM",
                amplifiers=amps or None,
                attenuators=(atts + ["Could be a legitimate encryption/archive tool even when path flow is present."]) or None,
            ))

    # BP-TIMEBOMB: time/environment trigger gates a payload.
    for path, group in groups.items():
        trigger = _has(group, "TIME.CMP", "TIME.SCHED", "ENVI.ENVCHECK", "ENVI.SANDBOX")
        payload = _has(group, "EXEC", "LOAD", "NETW", "FSYS.WRITE", "FSYS.DELETE", "PRST")
        if trigger and payload:
            n += 1
            conf, suffix, extra, amps, atts = _dataflow_status(inv, path, {"gated-payload"}, 0.52, 0.75)
            findings.append(_finding(
                f"mcd-{n}", "mcd", "Logic bomb / gated payload",
                "Code checks time or environment conditions near execution, loading, network, filesystem, "
                "or persistence behavior. This is the dormant/gated payload shape." + suffix,
                "high", conf, _ids(_uniq(trigger + payload, 12)),
                disproof=[
                    "The gate is a documented scheduler, feature flag, CI check, or cache/timeout condition.",
                    "Both gated and ungated branches are benign and disclosed.",
                    _cooccurrence_disproof(),
                ] + extra,
                verification=[
                    {"question": "What behavior is gated by the time or environment check?",
                     "method": "static-source", "reason": "A logic bomb is the trigger plus the hidden branch."},
                    {"question": "Does behavior diverge under the gated condition?",
                     "method": "dynamic", "reason": "Static source can miss dormant runtime branches."},
                ],
                response=_mcd_response(4, "Active monitoring; exercise gated and ungated branches before trusting.",
                                       ["Run branch-diff tests under trigger conditions", "Document or remove hidden gates"]),
                composition="BP-TIMEBOMB",
                amplifiers=amps or None,
                attenuators=(atts + ["Time and environment gates are common in benign scheduling and CI logic."]) or None,
            ))

    # BP-MINER: resource hijack markers plus network/payout evidence.
    for path, group in groups.items():
        mining = _has(group, "RSRC.CPU", "RSRC.GPU")
        payout = _has(group, "NETW.HTTP", "NETW.SOCKET", "NETW.WS", "NETW.DECENTRAL", "ARTF.CRYPTO_ADDR")
        evasion = _has(group, "ENVI", "TIME.DELAY")
        if mining and payout:
            n += 1
            findings.append(_finding(
                f"mcd-{n}", "mcd", "Resource hijacking / miner",
                "Cryptomining or proof-of-work resource markers appear with network or payout indicators. "
                "That is the resource-hijacking miner shape.",
                "high", 0.62, _ids(_uniq(mining + payout + evasion, 12)),
                disproof=[
                    "The project is explicitly a benchmark, miner, wallet, or proof-of-work tool.",
                    "Resource-intensive code is user-initiated and documented.",
                ],
                verification=[
                    {"question": "Is the mining/pool marker reachable during install, startup, or normal execution?",
                     "method": "static-source", "reason": "Reachability separates a shipped miner from an inert string."},
                    {"question": "Does runtime behavior consume CPU/GPU or contact a pool?",
                     "method": "dynamic", "reason": "Resource hijacking is ultimately runtime behavior."},
                ],
                response=_mcd_response(4, "Active monitoring; block pool egress if unexpected.",
                                       ["Block mining-pool destinations", "Apply CPU/GPU resource limits"]),
                composition="BP-MINER",
            ))

    # BP-ROOTKIT: system hooks/injection/kernel + concealment.
    for path, group in groups.items():
        system = _has(group, "LOAD.KERNEL_MODULE", "EXEC.INJECT", "EXEC.SYSCALL", "PRIV.EXPLOIT")
        conceal = _has(group, "PRST.BOOTKIT", "PRST.HOOK", "ENVI.SECDISABLE", "ENVI.FORENSIC",
                       "ENVI.LOG", "ENVI.MASQ", "FSYS.HIDDEN", "SYSI.PROCMEM")
        if system and conceal:
            n += 1
            findings.append(_finding(
                f"mcd-{n}", "mcd", "Rootkit / concealment path",
                "System-level loading, injection, syscall, or kernel-memory access appears with "
                "persistence, concealment, or security-disablement behavior. This is the rootkit shape.",
                "critical", 0.6, _ids(_uniq(system + conceal, 12)),
                disproof=[
                    "The code is a documented security, driver, EDR, debugger, or forensic tool.",
                    "The system-level operation is not reachable with the concealment behavior.",
                    _cooccurrence_disproof(),
                ],
                verification=[
                    {"question": "Does the system-level operation install, hide, or protect a durable component?",
                     "method": "static-source", "reason": "Rootkits combine privileged hooks with concealment."},
                    {"question": "What kernel/module/process artifacts appear at runtime?",
                     "method": "dynamic", "reason": "Static source cannot prove kernel-level effects."},
                ],
                response=_mcd_response(5, "Immediate response if reachable outside an explicit security tool.",
                                       ["Do not run on a host system", "Review only in an isolated VM"]),
                composition="BP-ROOTKIT",
                attenuators=["Security tools and low-level system utilities can legitimately use these atoms."],
            ))

    # BP-WORM: discover targets, then deliver/execute across a network.
    for path, group in groups.items():
        discover = _has(group, "SYSI.NET")
        channel = _has(group, "NETW.SOCKET", "NETW.HTTP", "NETW.WS", "NETW.DNS", "NETW.BROKER", "NETW.DECENTRAL")
        deliver = _has(group, "EXEC", "FSYS.WRITE", "PKGM.PUBLISH", "PRIV", "CRED")
        if discover and channel and deliver:
            n += 1
            conf, suffix, extra, amps, atts = _dataflow_status(inv, path, {"propagation"}, 0.54, 0.78)
            findings.append(_finding(
                f"mcd-{n}", "mcd", "Worm / propagation path",
                "Code discovers systems or accounts, has a network channel, and can write, execute, "
                "publish, or use credentials. That is the propagation shape for a worm." + suffix,
                "critical", conf, _ids(_uniq(discover + channel + deliver, 12)),
                disproof=[
                    "Discovery and network use are documented administration behavior scoped to explicit user input.",
                    "No payload or credential/action flows to discovered targets.",
                    _cooccurrence_disproof(),
                ] + extra,
                verification=[
                    {"question": "Can discovered hosts/accounts influence where payloads or commands are sent?",
                     "method": "static-source", "reason": "Propagation requires target discovery feeding action."},
                    {"question": "Does execution copy itself or another payload to remote systems?",
                     "method": "dynamic", "reason": "Runtime target expansion distinguishes worming from admin tooling."},
                ],
                response=_mcd_response(5, "Immediate response if autonomous propagation is confirmed.",
                                       ["Block network propagation", "Inspect credential and remote-exec paths"]),
                composition="BP-WORM",
                amplifiers=amps or None,
                attenuators=(atts + ["Admin and test tools can combine discovery and remote action legitimately."]) or None,
            ))

    # BP-TROJAN: concealed payload in a component whose stated purpose doesn't suggest it.
    purpose = (getattr(inv, "purpose", "") or "") if inv else ""
    benign_purpose = bool(purpose) and not any(k in purpose for k in (
        "security", "malware", "agent", "miner", "backup", "encrypt", "service", "daemon",
        "installer", "build", "shell", "network", "server", "driver", "forensic",
        "detection", "fixture", "sample", "scanner", "coverage", "test"))
    if benign_purpose:
        for path, group in groups.items():
            if _low_reach_path(path) and not _has(group, "PKGM.INSTALL", "PRST"):
                continue
            concealed = _has(group, "XFRM.PACK", "XFRM.UNICODE", "XFRM.STRCON", "ENVI", "PRST", "LOAD.EVAL")
            payload = _has(group, "EXEC", "NETW", "CRED", "FSYS.SENSITIVE", "PRIV")
            if concealed and payload:
                n += 1
                findings.append(_finding(
                    f"mcd-{n}", "mcd", "Trojan / disguised payload",
                    "The project's stated purpose does not suggest high-risk behavior, yet concealed or "
                    "environment-aware code sits next to execution, network, credential, or privilege capability.",
                    "high", 0.48, _ids(_uniq(concealed + payload, 12)),
                    disproof=[
                        "The documentation explicitly explains the high-risk behavior as part of the real purpose.",
                        "The concealed marker is an inert test/example or standard packaging artifact.",
                        _cooccurrence_disproof(),
                    ],
                    verification=[
                        {"question": "Does the concealed code implement behavior outside the documented purpose?",
                         "method": "static-source", "reason": "Trojan interpretation depends on mismatch plus payload."},
                        {"question": "Would a normal user invoke this path through the advertised interface?",
                         "method": "dynamic", "reason": "Concealed activation matters."},
                    ],
                    response=_mcd_response(3, "Review as a disguised payload candidate.",
                                           ["Compare docs/README to behavior", "Decode concealed strings and review activation"]),
                    composition="BP-TROJAN",
                    attenuators=[
                        _proof_att("same-file co-occurrence",
                                   "concealment and payload atoms share a file; activation is not proven."),
                        "Purpose inference is heuristic; documentation review may explain the behavior.",
                    ],
                ))

    # BP-AGENTMANIP: agent-directed manipulation next to a damaging payload surface.
    damaging = [o for o in obs if o.atom.startswith(("EXEC", "LOAD", "CRED", "PRIV", "PRST"))
                or o.atom in ("FSYS.SENSITIVE", "FSYS.CLIPBOARD")
                or o.atom.startswith(("NETW.WEBHOOK", "NETW.HTTP", "NETW.WS"))]
    same_file_agent = []
    for path, group in groups.items():
        a = [o for o in _has(group, "AITM") if _mcd_strong_agent_steering(o)]
        d = [o for o in group if o in damaging]
        if a and d:
            same_file_agent = _uniq(a + d, 16)
            break
    tool_and_steering = []
    for path, group in groups.items():
        t = _has(group, "AITM.TOOL")
        s = [o for o in _has(group, "AITM.INJECT", "AITM.INVISIBLE") if _strong_agent_steering(o)]
        if t and s:
            tool_and_steering = _uniq(t + s, 10)
            break
    component_agent_evidence = (
        tool_and_steering and damaging and _uniq(tool_and_steering + damaging, 16)
    )
    agent_evidence = same_file_agent or component_agent_evidence
    if agent_evidence:
        same_file_proof = bool(same_file_agent)
        atts = [
            _proof_att(
                "same-file co-occurrence" if same_file_proof else "component-level co-location",
                "agent steering and payload surface share a file, but tool routing is not proven."
                if same_file_proof else
                "tool-bound steering and payload surface share a component, but agent-to-tool reachability is not proven.",
            )
        ]
        n += 1
        findings.append(_finding(
            f"mcd-{n}", "mcd", "Agent manipulation with payload surface",
            "Agent-directed or hidden content is present in the same component as execution, loading, "
            "credential, persistence, or network egress capability. This is an MCD agent-manipulation "
            "candidate: steering text plus a payload surface.",
            "high", 0.52 if same_file_proof else 0.5, _ids(agent_evidence),
            disproof=[
                "No agent ingests the content as instructions.",
                "The agent-facing content cannot reach the payload-capable code or tool.",
                "High-reach tools require human approval and run sandboxed.",
            ],
            verification=[
                {"question": "Can an agent that reads the content invoke the payload-capable path?",
                 "method": "static-source", "reason": "Agent manipulation requires steerability into capability."},
                {"question": "Does injected content alter tool calls at runtime?",
                 "method": "dynamic", "reason": "Static analysis sees the surface, not the agent's behavior."},
            ],
            response=_mcd_response(4, "Active monitoring and approval gates for any agent-reachable payload path.",
                                   ["Sanitize agent-ingested content", "Require approval for high-reach tools"]),
            composition="BP-AGENTMANIP",
            attenuators=atts + ["This is same-file or explicit tool-surface co-location unless tool routing proves reachability."],
        ))

    # BP-LATERAL: internal discovery + credential/privilege + action on new targets.
    for path, group in groups.items():
        discover = _has(group, "SYSI.NET", "SYSI.USER", "SYSI.PROC", "SYSI.SW")
        authority = _has(group, "CRED", "PRIV")
        action = _has(group, "NETW.SOCKET", "NETW.HTTP", "NETW.WS", "EXEC", "FSYS.WRITE", "PRST")
        if discover and authority and action:
            n += 1
            conf, suffix, extra, amps, atts = _dataflow_status(inv, path, {"propagation"}, 0.54, 0.76)
            findings.append(_finding(
                f"mcd-{n}", "mcd", "Lateral movement path",
                "Code discovers local/internal context, accesses credential or privilege material, and "
                "can act over a network, execution, filesystem, or persistence surface. That is the "
                "lateral-movement shape." + suffix,
                "critical", conf, _ids(_uniq(discover + authority + action, 12)),
                disproof=[
                    "The behavior is a documented administrative workflow scoped to explicit operator input.",
                    "Credentials/privileges are not used to act on discovered systems.",
                    _cooccurrence_disproof(),
                ] + extra,
                verification=[
                    {"question": "Do discovered internal hosts/users feed network actions or command execution?",
                     "method": "static-source", "reason": "Lateral movement requires discovery feeding action."},
                    {"question": "Are credentials scoped to the component's own service rather than new targets?",
                     "method": "osint", "reason": "Credential scope distinguishes admin clients from movement."},
                ],
                response=_mcd_response(5, "Immediate response if internal target expansion is confirmed.",
                                       ["Block internal scanning and remote action", "Audit credential scope"]),
                composition="BP-LATERAL",
                amplifiers=amps or None,
                attenuators=(atts + ["Admin tools often combine discovery, credentials, and action legitimately."]) or None,
            ))

    # BP-MITM: trust weakening plus traffic interception/redirection.
    for path, group in groups.items():
        trust = _has(group, "CRPT.CERT", "NETW.DNS", "ENVI.SECDISABLE")
        traffic = _has(group, "NETW.HTTP", "NETW.SOCKET", "NETW.LISTEN", "NETW.WS", "NETW.IPC")
        redirect = _has(group, "FSYS.WRITE", "ARTF.PATH", "SYSI.REGISTRY", "PRIV.CAP")
        mitm_proven = bool([p for p in (getattr(inv, "dataflow", None) or {}).get(path, [])
                            if p.get("kind") == "mitm"])
        if trust and traffic and (redirect or _has(group, "NETW.LISTEN") or mitm_proven):
            n += 1
            conf, suffix, extra, amps, atts = _dataflow_status(inv, path, {"mitm"}, 0.53, 0.76)
            reach_amps = _reachable_sink_amplifiers(inv, path, {"egress"})
            if reach_amps and not amps:
                conf = round(min(conf + 0.05, 0.62), 2)
            findings.append(_finding(
                f"mcd-{n}", "mcd", "Traffic interception / MITM setup",
                "Trust verification is weakened or traffic routing is manipulated near network traffic "
                "handling. This is the man-in-the-middle setup shape." + suffix,
                "high", conf, _ids(_uniq(trust + traffic + redirect, 12)),
                disproof=[
                    "TLS/certificate changes are test-only or explicitly scoped to a local development proxy.",
                    "Traffic redirection does not affect user or credential-bearing traffic.",
                    _cooccurrence_disproof(),
                ] + extra,
                verification=[
                    {"question": "Does the code disable certificate verification, alter DNS/proxying, or write trust/routing config?",
                     "method": "static-source", "reason": "MITM setup requires trust degradation or traffic redirection."},
                    {"question": "Which traffic is intercepted or redirected at runtime?",
                     "method": "network", "reason": "Runtime capture shows whether real traffic is affected."},
                ],
                response=_mcd_response(4, "Active monitoring; fail closed on trust degradation.",
                                       ["Reject TLS verification disablement", "Audit proxy/DNS/cert-store changes"]),
                composition="BP-MITM",
                amplifiers=(amps + reach_amps) or None,
                attenuators=(atts + ["Development proxies and test TLS bypasses are common benign explanations."]) or None,
            ))

    return _attenuate_binary_string_only_findings(findings, obs)
