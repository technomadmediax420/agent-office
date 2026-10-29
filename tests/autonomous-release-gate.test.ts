import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { evaluateRelease, signReceipt, type GateKeys, type ReceiptKind, type SignedReceipt } from '../src/server/autonomous/release-gate.js';

const sha = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest('hex');

function fixture() {
  const keys = Object.fromEntries((['brief', 'intent', 'plan', 'test', 'checklist', 'review', 'backup'] as ReceiptKind[])
    .map((kind) => [kind, randomBytes(32)])) as GateKeys;
  const briefBytes = Buffer.from('Build and publish the authorized example to https://example.test/app');
  const artifact = Buffer.from('Verified website package');
  const context = { runId: 'run-1', briefSha256: sha(briefBytes), artifactSha256: sha(artifact), destination: 'https://example.test/app', recordedAt: 300 };
  const brief = { runId: context.runId, briefSha256: context.briefSha256, destination: context.destination,
    publishAuthorized: true, checklistId: 'tnmg-47-v1', requiredTests: [
      { name: 'typecheck', command: 'npm run typecheck' }, { name: 'build', command: 'npm run build' }, { name: 'ci', command: 'npm test' },
    ], createdAt: 100 };
  const intent = { ...context, planSha256: sha('plan'), sourceHead: 'a'.repeat(40), checklistId: brief.checklistId,
    requiredTests: brief.requiredTests, issuedAt: 200, expiresAt: 2_000 };
  const bodies = {
    plan: { ...context, planSha256: intent.planSha256, planner: 'codex' },
    tests: brief.requiredTests.map(({ name, command }) => ({ ...context, name, command, exitCode: 0, outputSha256: sha(`${name} output`) })),
    checklist: { ...context, checklistId: brief.checklistId,
      entries: Array.from({ length: 47 }, (_, i) => ({ id: i + 1, status: 'Pass', evidence: `audit/${i + 1}` })) },
    review: { ...context, planSha256: intent.planSha256, sourceHead: intent.sourceHead,
      reviewer: 'codex', worker: 'claude', decision: 'pass', findings: [] as { id: string; severity: 'high'; resolved: boolean }[] },
    backup: { ...context, backupSha256: sha('backup'), rollbackVerified: true },
  };
  const signed = (kind: ReceiptKind, body: unknown) => signReceipt(kind, body, keys[kind]);
  const receipts = () => [signed('plan', bodies.plan), ...bodies.tests.map((body) => signed('test', body)),
    signed('checklist', bodies.checklist), signed('review', bodies.review), signed('backup', bodies.backup)];
  const decide = (items = receipts(), b = signed('brief', brief), i = signed('intent', intent), bytes = artifact) =>
    evaluateRelease(b, i, items, briefBytes, bytes, keys, 1_000);
  return { keys, briefBytes, artifact, context, brief, intent, bodies, signed, receipts, decide };
}

test('a signed brief, matching artifact, 47 checked items, independent review, tests, and rollback pass', () => {
  const f = fixture();
  assert.deepEqual(f.decide(), { status: 'ready', reasons: [], runId: 'run-1', artifactSha256: sha(f.artifact), destination: f.context.destination });
});

test('the signed original brief controls the release destination and must match its bytes', () => {
  const f = fixture();
  assert.ok(f.decide(f.receipts(), f.signed('brief', { ...f.brief, destination: 'https://other.test' })).reasons.includes('intent_not_authorized_by_brief'));
  const damagedBrief = { ...f.signed('brief', f.brief), json: JSON.stringify({ ...f.brief, destination: 'https://other.test' }) };
  assert.deepEqual(f.decide(f.receipts(), damagedBrief), { status: 'blocked', reasons: ['invalid_brief'] });
  assert.deepEqual(evaluateRelease(f.signed('brief', f.brief), f.signed('intent', f.intent), f.receipts(), Buffer.from('changed brief'), f.artifact, f.keys, 1_000),
    { status: 'blocked', reasons: ['invalid_brief'] });
});

test('changing the destination or artifact after review blocks release', () => {
  const f = fixture();
  assert.ok(f.decide(f.receipts(), f.signed('brief', f.brief), f.signed('intent', { ...f.intent, destination: 'https://other.test' })).reasons.includes('intent_not_authorized_by_brief'));
  assert.ok(f.decide(f.receipts(), f.signed('brief', f.brief), f.signed('intent', f.intent), Buffer.from('different package')).reasons.includes('artifact_changed'));
  const receipts = f.receipts();
  receipts[receipts.length - 2] = f.signed('review', { ...f.bodies.review, destination: 'https://other.test' });
  assert.ok(f.decide(receipts).reasons.includes('invalid_review_receipt'));
});

test('missing, invalid, and duplicate evidence fail closed', () => {
  const f = fixture();
  assert.ok(f.decide(f.receipts().filter((r) => r.kind !== 'review')).reasons.includes('review_receipt_count'));
  assert.ok(f.decide([...f.receipts(), f.signed('test', f.bodies.tests[0])]).reasons.includes('invalid_test'));
  const forged = f.receipts();
  forged[1] = { ...forged[1], json: JSON.stringify({ ...f.bodies.tests[0], exitCode: 0, name: 'ci' }) };
  assert.ok(f.decide(forged).reasons.includes('invalid_test_receipt'));
  assert.ok(f.decide(f.receipts().filter((r) => r.kind !== 'test' || !r.json.includes('"name":"ci"'))).reasons.includes('missing_test:ci'));
  const wrongCommand = f.receipts();
  wrongCommand[1] = f.signed('test', { ...f.bodies.tests[0], command: 'echo passed' });
  assert.ok(f.decide(wrongCommand).reasons.includes('wrong_test_command:typecheck'));
});

test('failed test, unresolved review finding, and incomplete checklist block publication', () => {
  const f = fixture();
  const failed = f.receipts();
  failed[1] = f.signed('test', { ...f.bodies.tests[0], exitCode: 1 });
  assert.ok(f.decide(failed).reasons.includes('invalid_test'));
  const review = f.receipts();
  review[review.length - 2] = f.signed('review', { ...f.bodies.review, findings: [{ id: 'R1', severity: 'high', resolved: false }] });
  assert.ok(f.decide(review).reasons.includes('review_not_clear'));
  const checklist = f.receipts();
  checklist[checklist.length - 3] = f.signed('checklist', { ...f.bodies.checklist, entries: f.bodies.checklist.entries.slice(1) });
  assert.ok(f.decide(checklist).reasons.includes('incomplete_checklist'));
});

test('expired intent and unverified rollback block publication', () => {
  const f = fixture();
  assert.ok(evaluateRelease(f.signed('brief', f.brief), f.signed('intent', f.intent), f.receipts(), f.briefBytes, f.artifact, f.keys, 2_000).reasons.includes('intent_expired'));
  const receipts = f.receipts();
  receipts[receipts.length - 1] = f.signed('backup', { ...f.bodies.backup, rollbackVerified: false });
  assert.ok(f.decide(receipts).reasons.includes('rollback_not_verified'));
});

test('stale evidence and invalid gate input do not pass', () => {
  const f = fixture();
  const receipts = f.receipts();
  receipts[0] = f.signed('plan', { ...f.bodies.plan, recordedAt: 50 });
  assert.ok(f.decide(receipts).reasons.includes('invalid_plan_receipt'));
  assert.deepEqual(evaluateRelease(f.signed('brief', f.brief), f.signed('intent', f.intent), [], f.briefBytes, f.artifact, f.keys, NaN),
    { status: 'blocked', reasons: ['invalid_gate_input'] });
  assert.deepEqual(evaluateRelease(f.signed('brief', f.brief), f.signed('intent', f.intent), f.receipts(), f.briefBytes, undefined as unknown as Uint8Array, f.keys, 1_000),
    { status: 'blocked', reasons: ['invalid_gate_input'] });
});

test('another issuer key cannot mint evidence for this run', () => {
  const f = fixture();
  const receipts: SignedReceipt[] = f.receipts();
  receipts[0] = signReceipt('plan', f.bodies.plan, f.keys.review);
  assert.ok(f.decide(receipts).reasons.includes('invalid_plan_receipt'));
});
