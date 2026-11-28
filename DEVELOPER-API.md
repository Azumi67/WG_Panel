# Developer applications and fresh reseller backups

## Upgrade

This package is based on WGPanel_Developer_API_Backup_Update.zip. It retains PostgreSQL, the provisioning queue, reseller bot fixes and existing account data. No new DB tables, migrations or production dependencies are required. Application policy remains in the existing reseller Setting table. Existing policies and keys are preserved.

Back up the existing source, PostgreSQL database and WireGuard configuration. Resolve uncertain jobs before maintenance. Stop the panel, bot, reseller worker, provisioning, monitor and plan shop services that are running (including any watchdog/timer which restarts them). Extract the WG_Panel-main directory separately and overlay its contents on the installed source. Preserve .env, instance/, venv/, database and keys. Restart the previously active services and hard refresh the browser. Standard service names: wg-panel.service, wg-panel-bot.service, wg-reseller-worker.service, wg-plan-shop.service. Do not reinstall or migrate an already working PostgreSQL database.

## Access policy

Settings > Telegram > Applications lists the admin integration and reseller workspaces. Choose Manage, enable external application access, select allowed scopes and optionally allow the reseller to issue and rotate its own key. Save, then issue a key if needed. Phase 9 supports the original legacy key plus up to 16 named keys per role/workspace. Existing workspace keys are not deleted on upgrade but are unusable until the administrator explicitly enables access and assigns scopes. The administrator can enable an existing key without rotating it. Disabling access revokes all application keys for that reseller. Admin and shop keys are unaffected.

Effective access is the intersection of application scopes, account permissions, and Telegram feature grants. Set the reseller's Telegram feature grants in Manage Account if a scope is not effective. Custom bots use their own Telegram token; no built-in bot connection is necessary for customer API access. The optional message endpoint still requires an approved, enabled built-in bot and linked recipient. Never share the panel's global API key with a reseller. Admin application keys remain scoped to payment review and messaging; administrator-owned full management integrations may use the existing admin API with its existing global credential only on trusted servers. These are different keys.

The panel stores key digests, shows a new credential only at issuance, and keeps tenant ownership checks and request limits. An administrator who issues a key should deliver it through a secure channel. Rotation, permission removal and revocation prevent subsequent requests and cause queued API jobs to be rejected at authorization recheck; they are not cancellation of a running mutation. Review in-flight work before changing access. Multiple provisioning requests per account can be queued; execution remains ordered within an account. An unresolved review pauses subsequent execution and new changes for that account. Existing request IDs remain recoverable. Different accounts can execute independently where resources permit.

## Custom bot usage

Use HTTPS and Authorization: Bearer WORKSPACE_APP_KEY. See the Applications tab for 19 four-language examples and the API reference for additional existing admin/shop routes. API writes for create/edit/enable/disable/reset/rotate/delete use POST and return 202 with operation.id and status_url. For each intended mutation use a unique Idempotency-Key (1–80 ASCII letters, digits, underscores or hyphens). Keep that key on your side. When a submission is uncertain, GET /api/bot-apps/workspace/operations/by-request/{key} to recover it; if no job is found, retry the identical submission using the same key only, not a new key. Never blindly retry an operation in review. A completed create returns IDs. A completed mutation is not a guarantee of remote availability after completion. The legacy /access path is retained, but now requires Idempotency-Key and returns 202 with an operation reference instead of synchronous 200. Update older integrations before deploying Phase 4. The /access and /actions endpoints share the same normalized enable/disable request. A replay using the same authenticated key and payload returns the original operation, even after deletion; current permissions still apply.

The example at examples/custom_reseller_bot.py runs separately from WG Panel. Use an independent BotFather token and set PANEL, WORKSPACE_APP_KEY, CUSTOM_BOT_TOKEN and BOT_OWNER_ID in its environment. Install requests and python-telegram-bot in its own virtual environment. It accepts only the configured owner in private chat. It demonstrates read, create and request-status recovery; it is not a payment or full service bot. Test with a disposable account. Do not run two pollers against the same bot token.

API docs now show one endpoint group at a time, search across groups, and provide switchable cURL, Python, Node.js and PHP snippets for workspace routes. PostgreSQL deployment procedures remain in POSTGRESQL-MIGRATION.md. The previous endpoint groups remain available. Full legacy API audit was not performed.

## Backup

My backup > Generate & download already generated a fresh encrypted customer archive in the previous release. It now explicitly says so, bypasses browser caching, uses timestamped filenames, and reads PostgreSQL through a read-only REPEATABLE READ transaction, providing a consistent committed snapshot for a single account. It is not a scheduled backup store, a complete database dump or a live WireGuard counter snapshot. Archives contain active owned customers and recoverable keys, links, profiles and designs, as permitted. Save an archive before deleting customers if you need to recover them. Archive restore retains existing quota, identity, ownership, address and encryption safeguards. Restored deleted peers are paused. No persistent archive history is introduced.

## Cleanup and diagnostics

Old intermediate repair reports remain excluded from distribution; source updates and tests remain. No files named v32, v34 or v43 were present in the input archive. Redundant literal asset version arguments are removed where the panel's existing content-hash mechanism supplies rev. Ordinary Python/JS comments were removed with syntax-aware checks; licenses, shebangs, type/lint directives, vendor code, necessary version metadata and migrations remain. Removed files are absent in the ZIP; an overlay will not delete copies on the server. Do not use rsync --delete on an installation containing runtime state.

For continuing SQLSTATE 57014 cancellations or slow commits, run venv/bin/python scripts/diagnose_postgres_contention.py --seconds 45 while reproducing the issue; for CPU and I/O pressure use sudo python3 wg-postgres.py --resources. Keep synchronous commit and fsync enabled for customer/financial writes. Previous concurrency and bot fixes are preserved; the external API update does not resolve server storage or replication latency.

Rollback: stop the same services, reconcile pending external jobs using the current code first, then restore the previous source snapshot and restart. Previous releases do not enforce the new application policy, so explicitly revoke external keys before rollback if required. Do not overwrite the database solely to revert source changes.

## Telegram interface and verification

Admin Applications now renders inside the same Settings shell as Telegram connection and notifications; the same tabs and content alignment are used throughout. The reseller uses the same navigation and width for built-in bot and custom application views. Resellers with approved application access but no approved built-in bot can reach Applications from the Telegram sidebar entry. This does not enable built-in bot features. Persian is displayed as Persian (فارسی); the saved language code remains `fa`. Admin language selection controls notifications, not complete localization of the admin bot command menus. Existing reseller bot language support is retained. The HTTP status reference uses separate bordered rows and a distinct operation-state area. All prior API examples and permission checks remain.

For an actual end-to-end check on the installed server, issue a key for a disposable reseller with Plan usage & expiry enabled in the application and Telegram grants. On a trusted terminal, set PANEL to the HTTPS origin and enter the key without printing it:

```bash
read -r -p 'Panel HTTPS origin: ' PANEL
read -r -s -p 'Workspace application key: ' WORKSPACE_APP_KEY; printf '\n'
curl --fail-with-body --silent --show-error --max-time 20 \
  --header "Authorization: Bearer $WORKSPACE_APP_KEY" \
  "${PANEL%/}/api/bot-apps/workspace/status"
unset WORKSPACE_APP_KEY
```

Expected result: HTTP 200 and the approved workspace ID, quota and grants. A revoked or invalid key yields 401; an inactive account, disabled scope or wrong role yields 403. Do not test mutating endpoints on a live customer. The admin application key is not a global administrator API key; it is limited to the documented payment and registered-admin messaging endpoints. Admin and shop messaging still need the appropriate Telegram token and recipient configuration. The reseller custom bot can use its own Telegram connection without the built-in bot, except when calling the optional panel-managed messaging endpoint. Replacing or revoking a key does not cancel operations already running.

## Validation performed in this build

Python and Jinja parsing, first-party JavaScript syntax, the existing five application policy tests, seven simulated concurrency tests, five browser operation-client tests, two reseller bot reply tests, seven peer/history Chromium scenarios, seven workspace-feature Chromium scenarios, four developer UI scenarios, eight Telegram layout/API status scenarios, three application lifecycle tests and two Persian language tests passed. Lifecycle tests execute the real key-management and authorization functions with mocked database/session and request objects. Browser tests render the actual templates with stubbed backend responses; the layout suite uses the panel CSS cascade. These are not live PostgreSQL or WireGuard tests. The production Flask stack is not installed in the build environment; live Telegram connectivity, database performance and full deployment must be checked on staging.

## Phase 5 application credential restrictions

Administrators can set an expiry date (00:00 UTC on that date) and optional IP/CIDR allowlist in Telegram Applications. Updating these role/workspace-wide restrictions revokes all its application credentials; issue replacements. Named credentials additionally support independent expiry and IP restrictions. Unrestricted existing credentials continue to work. A request with an expired key or disallowed source IP is denied; queued requests also recheck credential validity and expiry before execution. Configure trusted proxy settings before enforcing source IP restrictions. Existing non-browser API clients retain bearer authentication; administrator browser-session API writes require CSRF.


## Phase 9 named applications and OpenAPI

Use Telegram > Applications > Named applications to create separate credentials for integrations. The administrator can issue keys for admin, Plan Shop, or individual workspaces. A reseller can issue/rotate/revoke its workspace keys only when self-management has been enabled by the administrator. A workspace key has no native administrator API privileges. The original legacy key continues to work with the same permissions and request IDs.

The named token format adds a non-secret application identifier before the random secret. Treat the entire token as confidential. The stored digest is SHA-256; only the newly issued or rotated token is displayed. Choose scopes, optional UTC expiry (starts at midnight), optional source networks and a 1–120 request/minute fixed-window limit. Workspace and role-wide limits still apply. Admin payment decisions require the explicit named permission; the older payment-review toggle is for the legacy key. Revoking a named credential does not revoke sibling keys. Changing named restrictions requires revoking and creating a replacement. Rotation keeps the same application ID; unstarted requests signed by the old token will be rejected. Use status lookup after rotation rather than resubmitting an old mutation. Legacy and named keys cannot read one another's operation results. Keep an original key/identity available until uncertain requests have been reconciled; after revocation use the signed-in workspace Operations page.

Download the machine-readable OpenAPI 3.0.3 document from Applications or API reference, or use `static/openapi/bot-apps.json`. It covers all 20 documented GET/POST application operations (including role-specific messaging), not the native admin, reseller-session or node routes. Build with `python scripts/build_application_spec.py`; `--check` detects drift in the generated file. The regression tests compare method/path coverage with Flask route decorators and check response/parameter references. These are source-derived contracts, not live endpoint certification.

Activity shows UTC-day authenticated request attempts that reach the named-key budget, including throttled attempts, and the most recent such attempt. Last seen is retained for about 30 days using existing budget cleanup. It does not represent successful business operations, a lifetime counter, or detailed request logs. The minute, day and last-seen rows are updated atomically by the existing request guard. The role/account-wide and recipient budgets still apply. Named keys add a budget transaction per authenticated API request; measure PostgreSQL latency before deploying at large volume. No new schema is required.

The starter bot adds cursor-based peer/subscription listing and peer enable/disable. It derives mutation request IDs from Telegram bot and update IDs to protect duplicate handling of the same Telegram update; a new user command is a new request. It does not automatically replay an uncertain mutation.
