# Netlify PR previews

Tracking issue: [#45](https://github.com/finos-osera/risk-navigator/issues/45).

## Repository configuration

The root `netlify.toml` builds the Docusaurus website from `website/` and publishes `website/build/`. The prebuild step copies the tool, data and OSS-risk assets from the repository into the site. Docusaurus also reads the root `docs/` directory.

Deploy Previews explicitly use Node 24 and `GITHUB_PAGES=false`. The website uses Netlify's `DEPLOY_PRIME_URL` for its URL and `/` as its base path.

The preview `ignore` command exits 1 to continue every PR preview build. This intentionally overrides Netlify's default check of changes inside the base directory: a change confined to `tool/`, `data/`, `oss-risk/` or `docs/` must also produce a new preview. Even unrelated PR changes will build; this simple policy trades some build usage for reliable previews. The existing production and standalone branch ignore commands still exit 0 to skip those builds.

## One-time account setup

A Netlify team/site administrator must:

1. Connect the intended site to `finos-osera/risk-navigator` and grant the Netlify GitHub App access to the repository.
2. Enable automatic builds and Deploy Previews under **Project configuration → Developer settings → Continuous deployment → Branches and deploy contexts**.
3. Verify the build settings resolve to the repository configuration and that preview URLs/statuses appear on GitHub PRs.
4. For stacked PRs, enable the base branch for branch deploys. For example, PR #44 targets `codex/patch-feed-coverage`, the branch for PR #43. Netlify requires this base to be enabled for branch deploys, or the PR must be retargeted to the production branch after its parent merges. A skipped standalone branch build is separate from whether the branch is enabled in Netlify; verify the stacked preview actually triggers.

The TOML file cannot install the GitHub App, connect the site, or activate previews by itself. No deployment token or additional GitHub Actions workflow is required for the normal Netlify Git integration. Production hosting remains unchanged.

## Verification

After setup and merging the configuration:

1. Update existing PR branches to include the configuration if needed, and push a commit or retry their Netlify deploys.
2. Confirm the Netlify check links to a successful preview at `https://deploy-preview-<PR-number>--<site-name>.netlify.app`.
3. Open the docs and `/tools/risk-navigator.html`; check dataset selection, assets, and browser errors. For #43/#44, also check `/tools/patches/panel.mjs` and the patch coverage/cart views.
4. Push a change confined to `tool/` and confirm the preview rebuilds rather than reporting no changes in `website/`.
5. Verify the stacked #44 preview, and record the working URLs in #45 before closing it.

A passing local website build validates the build inputs, but does not establish that the Netlify connection or PR preview settings are active.

References: [Deploy Previews](https://docs.netlify.com/deploy/deploy-types/deploy-previews/) and [ignore-command exit codes](https://docs.netlify.com/build/configure-builds/ignore-builds/).
