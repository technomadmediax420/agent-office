# Autonomous delivery gate (in development)

The intended workflow accepts one project brief. Codex plans and independently reviews; Claude implements. Office then checks recorded tests, a 47-item audit, review findings, a backup and rollback result, and the exact release destination before a separate publisher can act. Routine work is meant to continue without human approval prompts. Missing or failed evidence blocks the run automatically.

Only the pure release evaluator in `src/server/autonomous/release-gate.ts` is implemented in this branch. It is **not wired to Agent Office**, does not start either agent, and cannot merge, deploy, or publish. The current Office permission behavior is unchanged.

## Gate contract

The original brief bytes are hashed and bound to a signed brief record containing the exact destination, publication authorization, and required test names with commands. A later signed release intent names the artifact digest, plan digest, source revision, tests, checklist version, and expiry. Separate signing keys are required for the brief, intent, plan, test runner, auditor, reviewer, and backup service. Every evidence record names the same run, brief, artifact, and destination. The gate verifies its MAC, timestamp, structure, and role-specific result. It recomputes the artifact hash from the bytes supplied by the caller.

The reviewer record must say Codex reviewed Claude's work and must have no unresolved findings. All 47 checklist entries must be Pass with an evidence reference or Not Applicable with a reason. Every named test must have a signed zero-exit receipt. A signed backup record must say rollback was verified. The evaluator returns `ready` only when all conditions hold; otherwise it returns machine-readable block reasons.

**A signed record is only as reliable as its issuer.** The coordinator still needs to collect actual process exit codes, hashes, independent reviewer output, and rollback proof before signing. Each issuer key and evidence store must be inaccessible to Claude's worktree and Codex's review process. A future publisher must re-hash the exact bytes it sends, verify a short-lived capability for the exact target, prevent duplicate sends after restart, check the deployed result, and roll back on failure. The evaluator's `ready` object is not itself a publish credential.

The existing Windows host ACL and Office hook/token findings remain unresolved. Do not enable unrestricted native agent access, connect a publisher, or release this workflow until that boundary is repaired and verified.

## Local verification

Run `npm run typecheck`, `node --import tsx --import=#tests/css --test tests/autonomous-release-gate.test.ts`, `npm test`, and `npm run build`. The focused gate tests cover a valid decision, destination/artifact changes, forged or missing evidence, failed checks, stale records, and expiry. They do not prove an Office integration or deployment.
