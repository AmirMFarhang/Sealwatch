// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { readFileSync } from 'node:fs'
import { dirname, resolve, join } from 'node:path'
import { keyPairFromSecret, type KeyPair } from './core/crypto.js'
import { assert, network, publicKey, type Network } from './core/validation.js'
import { SanctionsScreen } from './compliance/sanctions.js'
import { LocalFileFlaggedListProvider, UtexoApiFlaggedListProvider } from './compliance/flagged.js'
import { FileDecisionLog } from './governance/log.js'
import { PolicyGate } from './governance/gate.js'
import { VerifyService } from './verify/incoming.js'
export interface TrustConfig {v:1;network:Network;walletId:string;stateDir:string;checkerSecretEnv:string;ownerPk:string;sanctionsDir:string;sanctionsManifestSha256?:string;testSanctions?:{id:string;version:string;addresses:string[]};flagged:{provider:'local-file'|'utexo-api';dir:string;trustedIssuerKeys:string[]};http?:{port:number;tokenEnv:string}}
export function loadConfig(file:string):{config:TrustConfig;key:KeyPair;verify:VerifyService;gate:PolicyGate;log:FileDecisionLog;sanctions:SanctionsScreen} {
  const config=JSON.parse(readFileSync(file,'utf8')) as TrustConfig
  assert(config.v===1,'unsupported config version');network(config.network);publicKey(config.ownerPk,'configured owner key')
  const secret=process.env[config.checkerSecretEnv];assert(secret,'configured checkerSecretEnv is missing');const key=keyPairFromSecret(secret)
  const base=dirname(resolve(file));const stateDir=resolve(base,config.stateDir)
  const log=new FileDecisionLog(join(stateDir,'decision-log.jsonl'),key)
  const sanctions=new SanctionsScreen(resolve(base,config.sanctionsDir),config.sanctionsManifestSha256,config.testSanctions)
  assert(['local-file','utexo-api'].includes(config.flagged.provider),'unsupported flagged-list provider')
  const flagged=config.flagged.provider==='local-file'?new LocalFileFlaggedListProvider(resolve(base,config.flagged.dir),config.flagged.trustedIssuerKeys):new UtexoApiFlaggedListProvider()
  const verify=new VerifyService({key,network:config.network,sanctions,flagged,log,historyDir:join(stateDir,'receiver-history')})
  const gate=new PolicyGate({key,ownerPk:config.ownerPk,network:config.network,walletId:config.walletId,stateFile:join(stateDir,'gate-state.json'),log})
  return {config,key,verify,gate,log,sanctions}
}
