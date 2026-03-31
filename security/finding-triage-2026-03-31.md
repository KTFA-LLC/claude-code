# Vulnerability Verification Triage (Claude Code) — 2026-03-31

Scope: Verify supplied findings against this repository snapshot and CLI threat model (developer-run local CLI, user-level permissions, local configuration trust boundaries, OAuth/account handling).

Legend:
- **Real**: Security issue is reproducible/credible in this code and threat model.
- **False positive**: Either intended behavior in this threat model or report overstates exploitability.

## Finalized list

| Finding ID | Title | Verdict | Final Severity | Notes |
|---|---|---|---|---|
| root_risk_assessment_6 | Arbitrary Privilege Escalation via Untrusted Project/Local Settings | **Real** | **High** | Project/local settings are merged and can influence default permission mode/rules unless managed lockout is enabled. |
| root_injection_1 | Remote Code Execution via Argument Injection in Plugin Shell Commands | **False positive** | N/A | Skill/plugin shell execution is a deliberate feature path; risk depends on trusting plugin/skill content and command invocation. |
| root_injection_3 | OS Command Injection via Unvalidated CLAUDE_CODE_TMPDIR | **Real** | **Medium** | Unsanitized env-derived path is interpolated into shell commands executed with `shell: true`. |
| root_authentication_6 | Missing OAuth context guard in API key retrieval | **Real** | **High** | Managed-context guard exists but API key source function still checks external env/helper paths in non-bare mode. |
| root_injection_2 | Windows Command Injection via External Editor Launch | **Partially real** | **Low** | `shell:true` + command string on Windows is risky, but practical exploit generally requires local env control (`EDITOR`/`VISUAL`) already under user control. |
| root_risk_assessment_3 | Insecure File Handling via Symbolic Link Race Conditions | **Partially real** | **Medium** | Sensitive files are written without anti-symlink checks; mostly local same-user hardening concern. |
| root_authentication_3 | Missing CSRF State Validation in OAuth Manual Authorization Flow | **Real** | **Medium** | State is parsed and passed from UI, but manual resolver path ignores/does not verify expected state before accepting code. |
| root_authentication_5 | Over-privileged OAuth Scopes and Lack of Client-Side Authorization Enforcement | **False positive** | N/A | Broader scope request appears intentional for product UX; server-side authorization should remain source of truth. |
| root_authentication_7 | Unauthenticated Credential Persistence due to Improper Authorization Ordering | **Real** | **Medium** | Credentials are persisted before `validateForceLoginOrg`; invalid org outcome does not roll back persisted auth artifacts. |
| root_configuration_2 | Legacy Configuration File Persistence Leading to Stale Security Settings | **False positive** | N/A | This is backward-compat behavior; report overstates as direct security bypass without stronger adversary assumptions. |
| root_configuration_9 | Unvalidated Arbitrary CA Bundle Injection via NODE_EXTRA_CA_CERTS | **False positive** | N/A | User-level config intentionally allows custom trust anchors; attacker who can modify user config is already in strong local position. |
| root_authentication_2 | Improper Authentication Flow Restriction in Third-Party Provider Modes | **Partially real** | **Low** | Token readers may still surface cached OAuth tokens when 3P mode is enabled; mostly auth UX/mode-isolation hardening. |
| root_authentication_9 | Persistent Authentication Failure due to Stale Credential Caching | **Real** | **Low** | 401 path in session ingress append returns without clearing cached token, causing repeated auth failure until external refresh/clear. |

## Evidence highlights

- Permission mode/rule loading from merged sources: `settings.permissions.defaultMode` accepted and rule loading includes project/local unless managed-only is enabled.
- Argument substitution and plugin shell prompt execution is direct string substitution followed by shell tool execution path.
- Clipboard image path uses `CLAUDE_CODE_TMPDIR` and composes shell command strings executed with `execa(..., { shell: true })`.
- Managed OAuth context helper exists, but API key retrieval logic does not globally short-circuit to managed-only key source.
- OAuth manual flow accepts `authorizationCode#state` input, but service manual handler resolves authorization code without checking expected state.
- Auth login flow persists OAuth/API credentials before `validateForceLoginOrg` check.
- Session ingress 401 handling does not clear cached token.

