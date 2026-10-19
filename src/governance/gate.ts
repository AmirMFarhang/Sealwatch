// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
// Adapted from Satstride governance/{gate,policy,sessions,store,why}.ts and wallet/signer.ts (Apache-2.0); see NOTICE.
import { hashObject, randomHex, signObject, verifyObject, type KeyPair } from '../core/crypto.js'
import { SignedStore } from '../core/store.js'
import { assert, integer, network, publicKey, text, units, type Network } from '../core/validation.js'
import { decodeSendPlan, previewValid, sendPlanHash, type WalletPreview, type WalletSendPlan } from '../wallet/plan.js'
import { FileDecisionLog } from './log.js'
export interface SpendingPolicy {v:1;domain:'trust-spending-policy-v1';version:number;prevHash:string|null;network:Network;walletId:string;gatePk:string;ownerPk:string;walletAdapterPk:string;agentKeys:string[];assetId:string;maxPerSend:string;maxPerDay:string;maxBitcoinFeeSats:string;allowedRecipients:string[];notBefore:number;expiresAt:number;tokenTtlSeconds:number;sig:string}
export interface SendRequest {v:1;domain:'trust-authorize-request-v1';requestId:string;agentPk:string;issuedAt:number;expiresAt:number;plan:WalletSendPlan;preview:WalletPreview;sig:string}
export interface GateToken {v:1;domain:'trust-approval-token-v1';id:string;actionId:string;gatePk:string;agentPk:string;network:Network;walletId:string;planHash:string;policyHash:string;policyVersion:number;issuedAt:number;expiresAt:number;sig:string}
export interface StopCommand {v:1;domain:'trust-stop-v1';id:string;network:Network;walletId:string;gatePk:string;ownerPk:string;issuedAt:number;expiresAt:number;reason:string;sig:string}
interface GateState {policy:SpendingPolicy|null;stopped:null|{at:number;reason:string};spentByDay:Record<string,string>;requests:string[];tokens:Record<string,{token:GateToken;used:boolean}>;commands:string[]}
export interface Decision {actionId:string;allowed:boolean;why:string[];policyVersion:number|null;token:GateToken|null}
export class PolicyGate {
  readonly store:SignedStore<GateState>
  constructor(readonly options:{key:KeyPair;ownerPk:string;network:Network;walletId:string;stateFile:string;log:FileDecisionLog;now?:()=>number}) {
    network(options.network);publicKey(options.ownerPk,'ownerPk');text(options.walletId,'walletId')
    this.store=new SignedStore(options.stateFile,options.key,()=>{assert(!options.log.entries().some(e=>['policy-install','authorization','kill-switch','signing-token'].includes(e.kind)),'gate state missing but prior signed governance history exists; refusing replay-state reset');return {policy:null,stopped:null,spentByDay:{},requests:[],tokens:{},commands:[]}})
  }
  private now(){const at=this.options.now?.()??Math.floor(Date.now()/1000);integer(at,'clock');return at}
  install(policy:SpendingPolicy):void {
    const o=this.options;const at=this.now()
    this.store.transact(s=>{
      assert(policy.v===1&&policy.domain==='trust-spending-policy-v1'&&policy.ownerPk===o.ownerPk&&verifyObject(policy,o.ownerPk),'policy must be signed by the configured owner')
      assert(policy.gatePk===o.key.pubkey&&policy.network===o.network&&policy.walletId===o.walletId,'policy gate/network/wallet binding mismatch')
      publicKey(policy.walletAdapterPk,'wallet adapter key');assert(Array.isArray(policy.agentKeys)&&policy.agentKeys.length>0,'policy needs agent keys');policy.agentKeys.forEach(k=>publicKey(k,'agent key'))
      assert(!policy.agentKeys.includes(policy.ownerPk)&&!policy.agentKeys.includes(policy.walletAdapterPk)&&!policy.agentKeys.includes(policy.gatePk),'agent key must be distinct from owner, adapter and gate authority')
      assert(units(policy.maxPerSend)>0n&&units(policy.maxPerDay)>=units(policy.maxPerSend),'policy spending limits invalid');units(policy.maxBitcoinFeeSats,'max fee')
      integer(policy.notBefore,'notBefore');integer(policy.expiresAt,'expiresAt');integer(policy.version,'version');integer(policy.tokenTtlSeconds,'tokenTtlSeconds');assert(policy.tokenTtlSeconds>0&&policy.tokenTtlSeconds<=600,'token lifetime must be 1..600 seconds');assert(policy.notBefore<=at&&at<policy.expiresAt,'policy outside validity window')
      assert(Array.isArray(policy.allowedRecipients)&&policy.allowedRecipients.length>0&&policy.allowedRecipients.every(a=>typeof a==='string'&&a.length>0),'policy needs explicit allowed recipients');text(policy.assetId,'assetId')
      assert(policy.version===(s.policy?.version??0)+1&&policy.prevHash===(s.policy?hashObject(s.policy):null),'policy version/hash chain invalid')
      s.policy=structuredClone(policy)
      o.log.append('policy-install','applied',{version:policy.version,policyHash:hashObject(policy)})
    })
  }
  authorize(request:SendRequest):Decision {
    const o=this.options;const at=this.now();const actionId=randomHex(16)
    return this.store.transact(s=>{
      const why:string[]=[];const p=s.policy;let decoded:ReturnType<typeof decodeSendPlan>|undefined
      if(!p)why.push('NO_POLICY')
      if(s.stopped)why.push('KILL_SWITCH_STOPPED')
      if(p&&(p.notBefore>at||at>=p.expiresAt))why.push('POLICY_EXPIRED_OR_NOT_ACTIVE')
      if(request.v!==1||request.domain!=='trust-authorize-request-v1'||!p?.agentKeys.includes(request.agentPk)||!verifyObject(request,request.agentPk))why.push('REQUEST_SIGNATURE_OR_AGENT_NOT_TRUSTED')
      if(!Number.isSafeInteger(request.issuedAt)||!Number.isSafeInteger(request.expiresAt)||request.issuedAt>at||at>=request.expiresAt||request.expiresAt-request.issuedAt>600)why.push('REQUEST_TIME_INVALID')
      if(typeof request.requestId!=='string'||request.requestId.length<16||s.requests.includes(request.requestId))why.push('REQUEST_REPLAY_OR_ID_INVALID')
      try {
        decoded=decodeSendPlan(request.plan)
        if(decoded.network!==o.network||decoded.walletId!==o.walletId)why.push('NETWORK_OR_WALLET_MISMATCH')
        if(p){
          if(!previewValid(request.plan,request.preview,p.walletAdapterPk))why.push('WALLET_PREVIEW_SIGNATURE_INVALID')
          if(decoded.assetId!==p.assetId)why.push('ASSET_NOT_ALLOWED')
          if(!p.allowedRecipients.includes(decoded.recipientId))why.push('RECIPIENT_NOT_ALLOWED')
          if(units(decoded.amount)>units(p.maxPerSend))why.push('PER_SEND_LIMIT_EXCEEDED')
          if(units(decoded.bitcoinFeeSats)>units(p.maxBitcoinFeeSats))why.push('BITCOIN_FEE_LIMIT_EXCEEDED')
          const day=new Date(at*1000).toISOString().slice(0,10)
          if(units(s.spentByDay[day]??'0')+units(decoded.amount)>units(p.maxPerDay))why.push('DAILY_LIMIT_EXCEEDED')
        }
      }catch(e){why.push(`PREVIEW_INVALID: ${(e as Error).message}`)}
      let token:GateToken|null=null
      if(!why.length&&p&&decoded){
        token=signObject({v:1 as const,domain:'trust-approval-token-v1' as const,id:randomHex(32),actionId,gatePk:o.key.pubkey,agentPk:request.agentPk,network:o.network,walletId:o.walletId,planHash:sendPlanHash(request.plan),policyHash:hashObject(p),policyVersion:p.version,issuedAt:at,expiresAt:Math.min(at+p.tokenTtlSeconds,p.expiresAt,request.expiresAt)},o.key.secretKey)
        const day=new Date(at*1000).toISOString().slice(0,10);s.spentByDay[day]=String(units(s.spentByDay[day]??'0')+units(decoded.amount));s.requests.push(request.requestId);s.tokens[token.id]={token,used:false};why.push('WITHIN_SIGNED_POLICY_LIMITS')
      }
      const decision={actionId,allowed:!!token,why,policyVersion:p?.version??null,token}
      o.log.append('authorization',token?'allowed':'refused',{why,requestHash:hashObject(request),planHash:decoded?sendPlanHash(request.plan):null,policyHash:p?hashObject(p):null},actionId)
      return decision
    })
  }
  /** Atomically burn the durable token immediately before the exact PSBT is signed. Failures keep it used. */
  consume(token:GateToken,plan:WalletSendPlan,preview:WalletPreview):void {
    const o=this.options;const at=this.now()
    this.store.transact(s=>{
      const p=s.policy
      assert(!s.stopped,'KILL_SWITCH_STOPPED')
      assert(p&&p.notBefore<=at&&at<p.expiresAt,'POLICY_EXPIRED_OR_NOT_ACTIVE')
      assert(token.v===1&&token.domain==='trust-approval-token-v1'&&token.gatePk===o.key.pubkey&&verifyObject(token,o.key.pubkey),'TOKEN_SIGNATURE_INVALID')
      assert(token.network===o.network&&token.walletId===o.walletId,'TOKEN_NETWORK_OR_WALLET_MISMATCH')
      assert(token.issuedAt<=at&&at<token.expiresAt,'TOKEN_TIME_INVALID')
      assert(token.policyHash===hashObject(p)&&token.policyVersion===p.version&&p.agentKeys.includes(token.agentPk),'TOKEN_POLICY_OR_AGENT_CHANGED')
      assert(previewValid(plan,preview,p.walletAdapterPk),'WALLET_PREVIEW_SIGNATURE_INVALID')
      assert(sendPlanHash(plan)===token.planHash,'DECODED_TRANSACTION_MISMATCH')
      const record=s.tokens[token.id];assert(record&&hashObject(record.token)===hashObject(token)&&!record.used,'TOKEN_UNKNOWN_OR_REUSED')
      record.used=true
      o.log.append('signing-token','consumed',{tokenId:token.id,planHash:token.planHash},token.actionId)
    })
  }
  stop(command:StopCommand):void {
    const o=this.options;const at=this.now()
    this.store.transact(s=>{
      assert(command.v===1&&command.domain==='trust-stop-v1'&&command.ownerPk===o.ownerPk&&verifyObject(command,o.ownerPk),'STOP_OWNER_SIGNATURE_INVALID')
      assert(command.gatePk===o.key.pubkey&&command.network===o.network&&command.walletId===o.walletId,'STOP_BINDING_INVALID')
      assert(Number.isSafeInteger(command.issuedAt)&&Number.isSafeInteger(command.expiresAt)&&command.issuedAt<=at&&at<command.expiresAt&&command.expiresAt-command.issuedAt<=600,'STOP_TIME_INVALID');assert(!s.commands.includes(command.id),'STOP_REPLAY');text(command.id,'stop id');text(command.reason,'stop reason')
      s.stopped={at,reason:command.reason};s.commands.push(command.id)
      o.log.append('kill-switch','stopped',{reason:command.reason,ownerPk:command.ownerPk,invalidatedPendingTokens:Object.values(s.tokens).filter(t=>!t.used).length},command.id)
    })
  }
  why(actionId:string){return this.options.log.why(actionId)}
}
export function signPolicy(policy:Omit<SpendingPolicy,'sig'>,owner:KeyPair):SpendingPolicy{return signObject(policy,owner.secretKey)}
export function signRequest(request:Omit<SendRequest,'sig'>,agent:KeyPair):SendRequest{return signObject(request,agent.secretKey)}
export function signStop(command:Omit<StopCommand,'sig'>,owner:KeyPair):StopCommand{return signObject(command,owner.secretKey)}
