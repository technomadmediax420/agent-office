// A deterministic gate for one autonomous release. This module makes no network or publish calls.
// The issuer keys belong to separate Office services, never to the model processes or worktree.
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export type ReceiptKind = 'brief' | 'intent' | 'plan' | 'test' | 'checklist' | 'review' | 'backup';
export type GateKeys = Record<ReceiptKind, Uint8Array>;

export interface SignedReceipt {
  kind: ReceiptKind;
  json: string;
  mac: string;
}

export interface ReleaseIntent {
  runId: string;
  briefSha256: string;
  artifactSha256: string;
  planSha256: string;
  sourceHead: string;
  destination: string;
  checklistId: string;
  requiredTests: RequiredTest[];
  issuedAt: number;
  expiresAt: number;
}

export interface ReleaseBrief {
  runId: string;
  briefSha256: string;
  destination: string;
  publishAuthorized: true;
  checklistId: string;
  requiredTests: RequiredTest[];
  createdAt: number;
}

export interface RequiredTest {
  name: string;
  command: string;
}

interface BoundReceipt {
  runId: string;
  briefSha256: string;
  artifactSha256: string;
  destination: string;
  recordedAt: number;
}

export interface PlanReceipt extends BoundReceipt {
  planSha256: string;
  planner: 'codex';
}

export interface TestReceipt extends BoundReceipt {
  name: string;
  command: string;
  exitCode: number;
  outputSha256: string;
}

export type ChecklistResult =
  | { id: number; status: 'Pass'; evidence: string }
  | { id: number; status: 'Not Applicable'; reason: string }
  | { id: number; status: 'Fail' | 'Blocked'; reason: string };

export interface ChecklistReceipt extends BoundReceipt {
  checklistId: string;
  entries: ChecklistResult[];
}

export interface ReviewReceipt extends BoundReceipt {
  planSha256: string;
  sourceHead: string;
  reviewer: 'codex';
  worker: 'claude';
  decision: 'pass' | 'fail';
  findings: { id: string; severity: 'critical' | 'high' | 'medium' | 'low'; resolved: boolean }[];
}

export interface BackupReceipt extends BoundReceipt {
  backupSha256: string;
  rollbackVerified: boolean;
}

export interface GateDecision {
  status: 'ready' | 'blocked';
  reasons: string[];
  runId?: string;
  artifactSha256?: string;
  destination?: string;
}

const SHA256 = /^[a-f0-9]{64}$/;
const GIT_HEAD = /^[a-f0-9]{40,64}$/;
const RECEIPT_MAX = 1_000_000;

const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const nonempty = (v: unknown, max = 512): v is string => typeof v === 'string' && v.length > 0 && v.length <= max && !/[\x00-\x1f\x7f]/.test(v);
const hash = (v: unknown): v is string => typeof v === 'string' && SHA256.test(v);
const common = (v: Record<string, unknown>): boolean => nonempty(v.runId, 128) && hash(v.briefSha256) && hash(v.artifactSha256);
const unique = (values: string[]): boolean => new Set(values).size === values.length;

/** Sign only in the trusted Office service for this receipt kind; never pass its key to an agent. */
export function signReceipt(kind: ReceiptKind, body: unknown, key: Uint8Array): SignedReceipt {
  if (key.byteLength < 32) throw new Error('Receipt key must contain at least 32 bytes');
  const json = JSON.stringify(body);
  if (!json || json.length > RECEIPT_MAX) throw new Error('Invalid receipt size');
  return { kind, json, mac: createHmac('sha256', key).update(`agent-office-release-v1\0${kind}\0${json}`).digest('hex') };
}

function openReceipt(receipt: SignedReceipt, key: Uint8Array | undefined): unknown {
  if (!key || key.byteLength < 32 || typeof receipt.json !== 'string' || receipt.json.length > RECEIPT_MAX || !hash(receipt.mac)) return undefined;
  const expected = createHmac('sha256', key).update(`agent-office-release-v1\0${receipt.kind}\0${receipt.json}`).digest();
  if (!timingSafeEqual(expected, Buffer.from(receipt.mac, 'hex'))) return undefined;
  try { return JSON.parse(receipt.json); } catch { return undefined; }
}

function validTests(v: unknown): v is RequiredTest[] {
  return Array.isArray(v) && v.length > 0 && v.length <= 100
    && v.every((x: unknown) => object(x) && nonempty(x.name, 128) && nonempty(x.command, 1000))
    && unique(v.map((x: RequiredTest) => x.name));
}

function validBrief(v: unknown): v is ReleaseBrief {
  return object(v) && nonempty(v.runId, 128) && hash(v.briefSha256) && nonempty(v.destination)
    && v.publishAuthorized === true && nonempty(v.checklistId, 128) && validTests(v.requiredTests)
    && Number.isSafeInteger(v.createdAt) && (v.createdAt as number) > 0;
}

function validIntent(v: unknown): v is ReleaseIntent {
  if (!object(v) || !common(v)) return false;
  return hash(v.planSha256) && typeof v.sourceHead === 'string' && GIT_HEAD.test(v.sourceHead)
    && nonempty(v.destination) && nonempty(v.checklistId, 128) && validTests(v.requiredTests)
    && Number.isSafeInteger(v.issuedAt) && (v.issuedAt as number) > 0
    && Number.isSafeInteger(v.expiresAt) && (v.expiresAt as number) > (v.issuedAt as number);
}

function bound(v: unknown, intent: ReleaseIntent, brief: ReleaseBrief, now: number): v is Record<string, unknown> {
  return object(v) && common(v) && v.runId === intent.runId && v.briefSha256 === intent.briefSha256
    && v.artifactSha256 === intent.artifactSha256 && v.destination === intent.destination
    && Number.isSafeInteger(v.recordedAt) && (v.recordedAt as number) >= brief.createdAt && (v.recordedAt as number) <= now;
}

function validChecklist(v: Record<string, unknown>, id: string): boolean {
  if (v.checklistId !== id || !Array.isArray(v.entries) || v.entries.length !== 47) return false;
  const seen = new Set<number>();
  for (const entry of v.entries) {
    if (!object(entry) || !Number.isInteger(entry.id) || (entry.id as number) < 1 || (entry.id as number) > 47 || seen.has(entry.id as number)) return false;
    seen.add(entry.id as number);
    if (entry.status !== 'Pass' && entry.status !== 'Not Applicable') return false;
    if (entry.status === 'Pass' && !nonempty(entry.evidence, 1000)) return false;
    if (entry.status === 'Not Applicable' && !nonempty(entry.reason, 1000)) return false;
  }
  return true;
}

/** The publisher must re-hash the exact bytes it sends; this decision is bound to these bytes. */
export function evaluateRelease(briefReceipt: SignedReceipt, intentReceipt: SignedReceipt, receipts: SignedReceipt[], briefBytes: Uint8Array, artifact: Uint8Array, keys: GateKeys, now = Date.now()): GateDecision {
  if (!Number.isSafeInteger(now) || !Array.isArray(receipts) || receipts.length > 256 || !(briefBytes instanceof Uint8Array)
    || !(artifact instanceof Uint8Array) || !keys || typeof keys !== 'object') return { status: 'blocked', reasons: ['invalid_gate_input'] };
  const brief = briefReceipt?.kind === 'brief' ? openReceipt(briefReceipt, keys.brief) : undefined;
  if (!validBrief(brief) || brief.createdAt > now || createHash('sha256').update(briefBytes).digest('hex') !== brief.briefSha256) return { status: 'blocked', reasons: ['invalid_brief'] };
  const intent = intentReceipt?.kind === 'intent' ? openReceipt(intentReceipt, keys.intent) : undefined;
  if (!validIntent(intent)) return { status: 'blocked', reasons: ['invalid_intent'] };
  const reasons: string[] = [];
  if (intent.issuedAt < brief.createdAt || intent.issuedAt > now) reasons.push('invalid_intent_time');
  if (intent.runId !== brief.runId || intent.briefSha256 !== brief.briefSha256 || intent.destination !== brief.destination
    || intent.checklistId !== brief.checklistId || JSON.stringify(intent.requiredTests) !== JSON.stringify(brief.requiredTests)) reasons.push('intent_not_authorized_by_brief');
  if (now >= intent.expiresAt) reasons.push('intent_expired');
  const actualHash = createHash('sha256').update(artifact).digest('hex');
  if (actualHash !== intent.artifactSha256) reasons.push('artifact_changed');
  const byKind = new Map<ReceiptKind, Record<string, unknown>[]>();
  for (const receipt of receipts) {
    if (!receipt || !['plan', 'test', 'checklist', 'review', 'backup'].includes(receipt.kind)) { reasons.push('unknown_receipt'); continue; }
    const body = openReceipt(receipt, keys[receipt.kind]);
    if (!bound(body, intent, brief, now)) { reasons.push(`invalid_${receipt.kind}_receipt`); continue; }
    const group = byKind.get(receipt.kind) ?? [];
    group.push(body);
    byKind.set(receipt.kind, group);
  }
  const one = (kind: ReceiptKind): Record<string, unknown> | undefined => {
    const group = byKind.get(kind) ?? [];
    if (group.length !== 1) reasons.push(`${kind}_receipt_count`);
    return group.length === 1 ? group[0] : undefined;
  };
  const plan = one('plan');
  if (plan && (plan.planner !== 'codex' || plan.planSha256 !== intent.planSha256)) reasons.push('invalid_plan');
  const checklist = one('checklist');
  if (checklist && !validChecklist(checklist, intent.checklistId)) reasons.push('incomplete_checklist');
  const review = one('review');
  if (review && (review.reviewer !== 'codex' || review.worker !== 'claude' || review.decision !== 'pass'
    || review.planSha256 !== intent.planSha256 || review.sourceHead !== intent.sourceHead
    || !Array.isArray(review.findings) || review.findings.some((f: unknown) => !object(f) || !nonempty(f.id, 128)
      || !['critical', 'high', 'medium', 'low'].includes(String(f.severity)) || f.resolved !== true))) reasons.push('review_not_clear');
  const backup = one('backup');
  if (backup && (!hash(backup.backupSha256) || backup.rollbackVerified !== true)) reasons.push('rollback_not_verified');
  const tests = byKind.get('test') ?? [];
  const names = new Set<string>();
  for (const t of tests) {
    if (!nonempty(t.name, 128) || !nonempty(t.command, 1000) || names.has(t.name) || t.exitCode !== 0 || !hash(t.outputSha256)) reasons.push('invalid_test');
    else names.add(t.name);
  }
  for (const required of intent.requiredTests) {
    const found = tests.find((t) => t.name === required.name);
    if (!found) reasons.push(`missing_test:${required.name}`);
    else if (found.command !== required.command) reasons.push(`wrong_test_command:${required.name}`);
  }
  return { status: reasons.length ? 'blocked' : 'ready', reasons: [...new Set(reasons)], runId: intent.runId, artifactSha256: intent.artifactSha256, destination: intent.destination };
}
