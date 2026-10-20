// Copyright 2026 Amir Mohammad Farhang; all rights reserved; private.
// Independent actual remote-review proof for a synthetic unsigned send.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { hashObject, sha256Hex, verifyObject } from '../../src/core/crypto.js';
import { verifyLog } from '../../src/governance/log.js';
import { verifyProviderResponse } from '../../src/provider/dsse.js';
import { decodeSendPlan, sendPlanHash, previewValid } from '../../src/wallet/plan.js';
const root = process.argv[2], pinsFile = process.argv[3];
assert(root && pinsFile, 'usage: verify-review-live.ts PRIVATE_REVIEW_DIRECTORY PRIVATE_PROVIDER_PINS');
const seen = new Map<string,string>();
function bytes(file: string) { const b = readFileSync(file); seen.set(file,sha256Hex(b)); return b; }
function json(file: string): any { return JSON.parse(bytes(file).toString('utf8')); }
const pinsBytes = bytes(pinsFile), pins = JSON.parse(pinsBytes.toString()).providers;
const receipt = json(join(root,'receipt.json'));
assert.equal(receipt.mode,'synthetic-unsigned-send-real-remote-software-runtime-review');
assert.equal(receipt.newTransactionBroadcast,false);
assert.equal(receipt.network,'utexo-testnet');
const policy = receipt.policy, request = receipt.request;
assert(verifyObject(policy,policy.ownerPk)); assert(verifyObject(request,request.agentPk));
assert.equal(policy.gatePk,receipt.gatePk); assert(policy.agentKeys.includes(request.agentPk));
assert(previewValid(request.plan,request.preview,policy.walletAdapterPk));
const decoded = decodeSendPlan(request.plan); assert.equal(decoded.amount,'50');
assert.equal(policy.review.softLimit,'40'); assert.equal(policy.review.humanThreshold,'80');
const entries = bytes(join(root,'decision-log.jsonl')).toString().split('\n').filter(Boolean).map(x=>JSON.parse(x));
const checkpoint = json(join(root,'decision-log.jsonl.checkpoint.json'));
assert.deepEqual(verifyLog(entries,receipt.gatePk,checkpoint),[]);
const privateFiles = readdirSync(join(root,'provider-evidence')).filter(name=>/^[a-f0-9]{64}\.json$/.test(name));
assert.equal(privateFiles.length,1,'exactly one reviewed send should call provider; hard refusal must stay local');
const evidence = json(join(root,'provider-evidence',privateFiles[0]));
const when = Date.parse(evidence.result.issued_at);
const checked = verifyProviderResponse(evidence,evidence.request,pins,when);
assert.equal(privateFiles[0],checked.evidence_sha256+'.json');
assert.equal(checked.record.result.kind,'agent-action-review'); assert.equal(checked.record.execution,'software');
assert.equal(checked.record.provider_id,policy.review.providerId);
assert.equal(evidence.request.context.plan_sha256,sendPlanHash(request.plan));
assert.equal(evidence.request.context.policy_sha256,hashObject(policy));
assert.equal(evidence.request.context.send_request_sha256,hashObject(request));
assert.equal(evidence.request.context.agent_public_key,request.agentPk);
assert.equal(evidence.request.subject.amount,decoded.amount);
assert.deepEqual(evidence.request.evidence.find((e:any)=>e.id==='send-plan').data,decoded);
assert.equal(bytes(join(root,'provider-evidence','request-'+evidence.request.request_id+'.used')).toString(),checked.evidence_sha256);
const expectedFindings = checked.record.result.findings.map((f:any)=>f.code);
const reviewed = receipt.reviewed, hard = receipt.humanThreshold;
for(const [label,decision] of [['reviewed',reviewed],['humanThreshold',hard]] as const){
 const e = entries.find(e=>e.kind==='authorization'&&e.actionId===decision.actionId);
 assert(e&&e.result===(decision.allowed?'allowed':'refused'));
 assert.equal(hashObject(e.detail.why),hashObject(decision.why));
 if(label==='reviewed'){
  assert.equal(e.detail.requestHash,hashObject(request)); assert.equal(e.detail.planHash,sendPlanHash(request.plan)); assert.equal(e.detail.policyHash,hashObject(policy));
  assert.equal(e.detail.providerReview.evidenceSha256,checked.evidence_sha256);
  assert.equal(e.detail.providerReview.resultRecordHash,hashObject(checked.record));
  assert.deepEqual([...e.detail.providerReview.reasonCodes].sort(),[...new Set(expectedFindings)].sort());
  verifyProviderResponse(evidence,evidence.request,pins,Math.max(when,e.at*1000));
 }
}
if(checked.record.result.recommendation==='escalate'){
 assert.equal(reviewed.allowed,false); assert.equal(reviewed.token,null); assert(reviewed.why.includes('PROVIDER_REVIEW_ESCALATED'));
}else{
 assert.equal(reviewed.allowed,true); assert(reviewed.token&&verifyObject(reviewed.token,receipt.gatePk));
 assert.equal(reviewed.token.review.evidenceSha256,checked.evidence_sha256);
 assert.equal(reviewed.token.planHash,sendPlanHash(request.plan));
 assert(reviewed.token.expiresAt<=Math.floor(Date.parse(checked.record.expires_at)/1000));
}
assert.equal(hard.allowed,false);assert.equal(hard.token,null);assert(hard.why.includes('HUMAN_APPROVAL_REQUIRED'));
assert.equal(entries.filter(e=>e.kind==='authorization').length,2);
assert.equal(entries.filter(e=>e.kind==='signing-token').length,0,'demo must never consume/sign/broadcast');
const state=json(join(root,'gate-state.json'));assert(verifyObject(state,receipt.gatePk));
const head=entries.filter(e=>e.kind==='state-commit'&&e.detail.namespace===`gate:${policy.network}:${policy.walletId}`).at(-1);
assert(head&&head.detail.stateHash===hashObject(state));
if(!reviewed.allowed)assert.deepEqual(state.state.spentByDay,{});
for(const[file,digest]of seen)assert.equal(sha256Hex(readFileSync(file)),digest);
const report={schemaVersion:1,independentQa:true,checkedAt:new Date().toISOString(),verdict:'PASS_ACTUAL_REMOTE_REVIEW_OF_SYNTHETIC_UNSIGNED_SEND',network:'utexo-testnet',syntheticUnsignedSend:true,newTransactionBroadcast:false,signingTokensConsumed:0,providerEvidenceSha256:checked.evidence_sha256,configuredPinsFileSha256:sha256Hex(pinsBytes),policyAndAgentRequestSignaturesValid:true,exactPlanPolicyRequestAgentAndEvidenceBindingsValid:true,providerRecommendation:checked.record.result.recommendation,reasonCodes:expectedFindings,execution:'software',reviewedAmount:'50',reviewedAllowed:reviewed.allowed,hardThresholdRefused:true,hardRefusalReason:'HUMAN_APPROVAL_REQUIRED',providerCalls:privateFiles.length,signedLogEntries:entries.length,decisionAndEvidenceLogBindingsValid:true,gateSnapshotMatchesRetainedJournal:true,privateEvidenceUnchanged:true,limits:['The request uses a synthetic unsigned plan. This proves actual provider review and local policy integration, not a native wallet send or on-chain broadcast.','Policy, gate and agent identities are internally verified ephemeral test authorities, not independently pinned operational-wallet identities.','Signed software evidence trusts the configured provider host; private runtime stage/model evidence has a separate verification report.','Operational provider keys, endpoints, full private evidence and wallet secrets are not exported.']};
writeFileSync('qa/addendum/review-live-verification.json',JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({verdict:report.verdict,providerRecommendation:report.providerRecommendation,reviewedAllowed:reviewed.allowed,hardThresholdRefused:true,providerEvidenceSha256:checked.evidence_sha256}));
