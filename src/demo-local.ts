// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
// This is an isolated structural demo. Its transaction vectors are synthetic and never broadcast.
import { mkdirSync, existsSync } from 'node:fs'
import { resolve, join, relative } from 'node:path'
import { Transaction, Psbt, payments, networks } from 'bitcoinjs-lib'
import { atomicWrite } from './core/store.js'
import { assert } from './core/validation.js'
import { bytesToHex, randomHex, randomKeyPair, canonicalJson } from './core/crypto.js'
import { signFlaggedManifest, type FlaggedSnapshot } from './compliance/flagged.js'
import { signPolicy, signRequest, signStop } from './governance/gate.js'
import { certifyPreview, type WalletSendPlan } from './wallet/plan.js'
import { loadConfig, type TrustConfig } from './config.js'
export async function demoLocal(statePath:string){
  const root=resolve(statePath);const allowed=resolve('.state');assert(root.startsWith(allowed+'/')&&!existsSync(root),'local demo requires a fresh directory below .state/; existing state is preserved')
  mkdirSync(root,{recursive:true,mode:0o700});const at=Math.floor(Date.now()/1000)
  const checker=randomKeyPair(),owner=randomKeyPair(),agent=randomKeyPair(),adapter=randomKeyPair(),issuer=randomKeyPair()
  atomicWrite(join(root,'secrets.env'),`export TRUST_CHECKER_SECRET=${bytesToHex(checker.secretKey)}\nexport TRUST_OWNER_SECRET=${bytesToHex(owner.secretKey)}\nexport TRUST_AGENT_SECRET=${bytesToHex(agent.secretKey)}\nexport TRUST_ADAPTER_SECRET=${bytesToHex(adapter.secretKey)}\nexport TRUST_ISSUER_SECRET=${bytesToHex(issuer.secretKey)}\nexport TRUST_HTTP_TOKEN=${randomHex(32)}\n`)
  function vector(){const script=payments.p2wpkh({pubkey:Buffer.from(`02${randomKeyPair().pubkey}`,'hex'),network:networks.testnet}).output!;const previous=new Transaction();previous.addInput(Buffer.alloc(32),0xffffffff);previous.addOutput(script,10000n);const witness=new Transaction();witness.addInput(Buffer.from(previous.getId(),'hex').reverse(),0);witness.addOutput(script,9000n);const psbt=new Psbt({network:networks.testnet}).addInput({hash:previous.getId(),index:0,witnessUtxo:{script,value:10000n}}).addOutput({script,value:9000n});return {previous,witness,psbt}}
  const clear=vector(),flagged=vector();const list:FlaggedSnapshot={v:1,domain:'trust-flagged-outpoints-v1',id:'test-local-synthetic-flagged',version:`local-${at}`,network:'utexo-testnet',testOnly:true,outpoints:[`${flagged.previous.getId()}:0`]}
  const listBytes=Buffer.from(canonicalJson(list));atomicWrite(join(root,'flagged/flagged-outpoints.json'),listBytes.toString());atomicWrite(join(root,'flagged/manifest.json'),canonicalJson(signFlaggedManifest(list,'flagged-outpoints.json',listBytes,issuer,at-1,at+86400))+'\n')
  const config:TrustConfig={v:1,network:'utexo-testnet',walletId:'synthetic-wallet-A',stateDir:'runtime',checkerSecretEnv:'TRUST_CHECKER_SECRET',ownerPk:owner.pubkey,sanctionsDir:resolve('fixtures/sanctions'),flagged:{provider:'local-file',dir:'flagged',trustedIssuerKeys:[issuer.pubkey]},http:{port:46421,tokenEnv:'TRUST_HTTP_TOKEN'}}
  const configFile=join(root,'trust.config.json');atomicWrite(configFile,JSON.stringify(config,null,2)+'\n')
  // Environment mutation is confined to this short-lived CLI invocation; secrets are never returned.
  process.env.TRUST_CHECKER_SECRET=bytesToHex(checker.secretKey)
  const services=loadConfig(configFile)
  const incoming=(v:ReturnType<typeof vector>)=>({network:'utexo-testnet' as const,assetId:'rgb:test-USD-not-USDT-synthetic',receiverWalletId:'synthetic-wallet-B',receivedAt:at,witnessTxid:v.witness.getId(),witnessRawHex:v.witness.toHex(),previousTransactions:{[v.previous.getId()]:v.previous.toHex()}})
  const clearInput=incoming(clear),flaggedInput=incoming(flagged)
  atomicWrite(join(root,'incoming-clear.json'),canonicalJson(clearInput)+'\n');atomicWrite(join(root,'incoming-flagged.json'),canonicalJson(flaggedInput)+'\n')
  const clearAttestation=await services.verify.verifyIncoming(clearInput),flaggedAttestation=await services.verify.verifyIncoming(flaggedInput)
  atomicWrite(join(root,'attestation-clear.json'),canonicalJson(clearAttestation)+'\n');atomicWrite(join(root,'attestation-flagged.json'),canonicalJson(flaggedAttestation)+'\n')
  const policy=signPolicy({v:1,domain:'trust-spending-policy-v1',version:1,prevHash:null,network:'utexo-testnet',walletId:config.walletId,gatePk:checker.pubkey,ownerPk:owner.pubkey,walletAdapterPk:adapter.pubkey,agentKeys:[agent.pubkey],assetId:clearInput.assetId,maxPerSend:'100',maxPerDay:'150',maxBitcoinFeeSats:'2000',allowedRecipients:['synthetic-B'],notBefore:at-1,expiresAt:at+86400,tokenTtlSeconds:60},owner)
  atomicWrite(join(root,'policy.json'),canonicalJson(policy)+'\n');services.gate.install(policy)
  const makeRequest=(amount:string)=>{const plan:WalletSendPlan={kind:'rgb-send',network:'utexo-testnet',walletId:config.walletId,assetId:policy.assetId,amount,recipientId:'synthetic-B',invoice:'rgb:synthetic-not-a-real-invoice',decodedInvoice:{recipientId:'synthetic-B',assetId:null,network:'testnet',amount:null,transportEndpoints:['rpcs://synthetic.invalid/json-rpc']},recipientMap:{[policy.assetId]:[{recipientId:'synthetic-B',witnessData:{amountSat:'1000',blinding:null},assignment:{Fungible:Number(amount)},transportEndpoints:['rpcs://synthetic.invalid/json-rpc']}]},unsignedPsbt:clear.psbt.toBase64()};return signRequest({v:1,domain:'trust-authorize-request-v1',requestId:randomHex(16),agentPk:agent.pubkey,issuedAt:at,expiresAt:at+120,plan,preview:certifyPreview(plan,adapter)},agent)}
  const within=makeRequest('50'),over=makeRequest('101');atomicWrite(join(root,'request-within.json'),canonicalJson(within)+'\n');atomicWrite(join(root,'request-over.json'),canonicalJson(over)+'\n')
  const withinDecision=services.gate.authorize(within),overDecision=services.gate.authorize(over)
  assert(withinDecision.allowed&&withinDecision.token,'within-limit synthetic authorization failed');services.gate.consume(withinDecision.token,within.plan,within.preview)
  const stop=signStop({v:1,domain:'trust-stop-v1',id:randomHex(16),network:'utexo-testnet',walletId:config.walletId,gatePk:checker.pubkey,ownerPk:owner.pubkey,issuedAt:at,expiresAt:at+120,reason:'synthetic local demo kill switch'},owner);atomicWrite(join(root,'stop-command.json'),canonicalJson(stop)+'\n');services.gate.stop(stop)
  const afterStop=services.gate.authorize(makeRequest('1'))
  const results={mode:'synthetic-local-structural-demo',liveTransfers:false,network:'utexo-testnet',networkFallback:'mutinynet',configFile:relative(process.cwd(),configFile),secretsFile:relative(process.cwd(),join(root,'secrets.env')),checkerPk:checker.pubkey,flaggedIssuerPk:issuer.pubkey,clear:clearAttestation.overall,flagged:flaggedAttestation.overall,withinAllowed:withinDecision.allowed,overAllowed:overDecision.allowed,overActionId:overDecision.actionId,stoppedAllowed:afterStop.allowed,chainProblems:services.log.verify()}
  atomicWrite(join(root,'local-demo-results.json'),canonicalJson(results)+'\n');return results
}
