# Risk Navigator — coding-agent kickoff prompt

> **Use this when**: you want a fresh coding agent (Claude Code, Cursor,
> Aider, Codeium, whichever) to bootstrap a working open-source
> implementation of Risk Navigator from the SPEC + README in this folder.
>
> **How to use**: paste the entire **"Prompt"** section below into a new
> agent session, then attach (or paste) `README.md` and `SPEC.md` from this
> same folder. The agent will scaffold the project layout, implement the
> data pipeline, build the HTML viewer, and produce a working v0.
>
> If you want a phased build (recommended), the prompt also includes a
> "Phase plan" the agent can follow — just say "start with Phase 1" after
> pasting.

---

## Prompt

```
You are helping me bootstrap an open-source implementation of "Risk
Navigator" — a decision-enablement HTML tool for supply-chain CVE
exposure analysis. I will attach two reference documents:

  1. README.md - the product / data-flow overview (with Mermaid diagrams)
  2. SPEC.md   - the build spec (data model, computational rules, UI design,
                 phases, performance budget, testing strategy)

Treat both as authoritative. The schema in SPEC §4.1 is the contract
between the data pipeline and the HTML viewer; everything else is
implementation latitude.

Your job
========
Produce a working v0 that matches SPEC.md's "Phase 1 + Phase 2" scope
(MVP):

  Phase 1 — Data pipeline
    - Ingest a public CVE↔package catalogue (OSV.dev recommended primary;
      NVD / GHSA optional supplements). Persist as a queryable internal
      vuln table (SQLite or DuckDB).
    - Fetch CISA KEV (small JSON, weekly) and FIRST.org EPSS (per-CVE via
      the public API, batched) into data/external/{kev,epss}.json.
    - Define the 6 raw-CSV shapes for the per-scope org data (see SPEC §4.3).
    - Implement build_dataset.py that joins everything into
      data/<scope>.json matching the schema in SPEC §4.1 EXACTLY.

  Phase 2 — HTML viewer v0
    - Single-file tool/risk-navigator.html, vanilla JS, no build step,
      no framework, ~70 KB target.
    - Filter bar (CVSS slider, upgrade-class chips, department dropdown,
      namespace dropdown, Project reference typeahead+chips, free-text search,
      KEV-only checkbox, Direct-only checkbox, EPSS ≥ slider in 0.000..1.000).
    - Libraries table (default mode) with the columns listed in SPEC §6.1,
      sortable, with row-click → detail pane on the right.
    - Detail pane: impact banner (All / Direct / Transitive tap-to-filter
      tiles), metadata KV, version chain, CVEs list (top 50), consumer
      projects (filtered by impact banner).
    - Add a top-right Help button that opens a modal documentation view.
      Documentation is authored in markdown and rendered in the page.
    - Inline tranche pills in the header showing
      Patch / Minor / Major / Dead-end / Unknown counts of the filtered set.
    - Light/dark theme via :root + :root[data-theme="light"] CSS tokens,
      persisted to localStorage, prefers-color-scheme on first load.

Constraints (these are not negotiable)
======================================
- **Vanilla JS only.** No React/Vue/Svelte/bundler/transpiler. A single
  ~70 KB self-contained HTML file is part of the product. CSS lives in
  one inline <style>; JS lives in one inline <script>.
- **Performance budget** (SPEC §11): 120 ms debounce on text-input
  re-renders; in-memory dataset cache for switching; no full table
  rebuild on row-click (use data-id attributes and direct classList
  toggling).
- **The dataset JSON shape in SPEC §4.1 is the contract.** Match every
  field name and shape. The HTML reads it directly.
- **Decouple the universal-signals path (KEV/EPSS/vuln catalogue) from
  the org-data path.** They are separate ingestion scripts that converge
  in build_dataset.py. This boundary is the reason the tool can be
  open-sourced — only the org-data extract is implementer-specific.
- **GA-only safe-version walker** per SPEC §5.1. Vendor rebuilds,
  pre-releases, snapshots are NOT valid upgrade targets even when their
  version-tuple compares higher.
- **ASCII-sanitize generated YAML and LLM prompt output** per SPEC §8.

Out of scope for this first pass
================================
- Phases 3, 4, 5 (Amplifiers / Frameworks / Top fixes / What-if simulators /
  OpenRewrite cart / impact-analysis prompt / multi-dataset manifest). You
  may stub mode-toggle slots for them but do not implement.
- Authentication, server-side anything, an API. The tool is a static file.
- A vector DB / RAG / LLM call from inside the HTML.

Sample data
===========
I will provide sample inputs as I have them. If I don't supply any:

  - For the vuln catalogue: synthesize a tiny OSV.dev-shaped JSON for
    ~10 well-known CVEs (log4shell, spring4shell, snakeyaml YAML deserial,
    a few RHEL RPMs).
  - For the org data: synthesize ~20 consumer projects each consuming
    3–10 deps with a mix of direct + transitive flags.

Aim for the smallest dataset that exercises every code path in the viewer
end-to-end.

Deliverables for this pass
==========================
  scripts/ingest_vulns.py          # OSV-shaped JSON → normalized internal vuln table
  scripts/fetch_external.py        # KEV + EPSS → data/external/{kev,epss}.json
  scripts/extract_org.py           # synthetic generator (until I provide real inputs)
  scripts/build_dataset.py         # joins all 5 inputs → data/<scope>.json
  tool/risk-navigator.html         # the viewer (Phase 1 + 2 scope)
  tool/manifest.json               # ONE entry pointing at the sample scope
  data/<scope>.json                # built sample dataset
  data/raw/<scope>/*.csv           # raw extracts retained for audit
  README.md                         # how to run locally
  tests/                            # at minimum: schema validator + safe-version walker unit tests

Ground rules for our conversation
=================================
- **Read SPEC.md carefully before writing code.** If you find ambiguity,
  prefer the simpler interpretation.
- **Ask before guessing** about anything that affects the dataset shape or
  the recipe-name structure.
- **Show your plan first** — produce a 1-screen file layout and a 5-line
  description of each script before generating code. I'll OK it and then
  you can write.
- **Don't introduce dependencies I haven't agreed to.** The pipeline
  scripts can use the Python standard library only (sqlite3, json, csv,
  urllib). If you want pandas / requests / pydantic, ask first.
- **Tests use pytest, kept in tests/ — no test framework dependencies in
  the pipeline scripts themselves.**
- **All YAML output from the future cart must be ASCII-sanitized.**

Now: respond with the proposed file layout + plan only. Wait for me to
say "go" before writing any code.
```

---

## Phase plan (what comes next, after the agent ships Phase 1+2)

After the agent delivers the MVP, paste this to expand scope:

```
Now extend to SPEC.md Phases 3, 4, 5:

Phase 3 — Value-add views
  - Amplifiers mode (parent-cluster grouping)
  - Frameworks mode (upstream family grouping; rule list in JS, editable)
  - Dead-ends mode (no GA safe exists)
  - Projects mode (consumer-side reverse view)
  - Top Fixes mode (unified ranked action list with effort weights; per
    SPEC §6.2 formula including KEV ×3 and EPSS (1+epss_max) multipliers)
  - What-if simulators (lib / amplifier / framework) per SPEC §7

Phase 4 — OpenRewrite cart
  - Maven-only "Add Maven lib to cart" in the lib detail pane
  - Cart sidebar with editable FROM/TO ranges, persisted to localStorage
  - Yellow banner: "best for direct deps"
  - "▶ Generate OpenRewrite YAML" multi-document output per SPEC §8 — sub-recipes
    first, aggregator last, FindDependency precondition per item, NO
    versionPattern on UpgradeDependencyVersion, ASCII-sanitized
  - "📝 Impact-analysis prompt" modal with the LLM prompt
  - Direct vs Transitive surfacing per SPEC §4.1 + impact banner

Phase 5 — Polish
  - Multi-dataset manifest dropdown + ?data=URL query param
  - In-memory dataset cache for instant back-and-forth
  - Horizontal scroll when grid exceeds column width
  - Collapsible right pane (›› hide → 24px handle to re-expand)

Same ground rules apply. Ship Phase 3 fully before starting Phase 4. Pause
after each phase for review.
```

---

## Notes for the human driving the agent

- **Hand the agent BOTH `README.md` and `SPEC.md` at the start.** The
  README sets context; the SPEC is the build instructions. Without the
  SPEC, the agent will under-specify the data shape.
- **Bring sample data.** The agent will scaffold synthetic data, but the
  closer to your real inputs you can get, the less rework when you swap
  in production data.
- **Resist scope creep in Phase 1.** The MVP (Phases 1+2) is genuinely
  useful by itself. Get that working and load it with realistic data
  before adding amplifiers / frameworks / cart.
- **If the SPEC doesn't answer a question, open an issue rather than
  guessing.** The dataset schema in SPEC §4.1 is the contract between
  the data pipeline and the HTML viewer — silent drift between the two
  breaks the tool in confusing ways. Worked input examples are in
  SPEC §14.
- **Run the agent on a feature branch.** It will write a lot of code at
  once; you want the diff isolated.
