// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { hashObject, sha256Hex, signObject, verifyObject, isHex, type KeyPair } from '../core/crypto.js'
import { assert, integer, network, type Network } from '../core/validation.js'
import { localFile, type ListInfo } from './sanctions.js'
export interface FlaggedSnapshot {v:1;domain:'trust-flagged-outpoints-v1';id:string;version:string;network:Network;testOnly:boolean;outpoints:string[]}
export interface FlaggedManifest {v:1;domain:'trust-flagged-manifest-v1';file:string;sha256:string;listId:string;version:string;network:Network;testOnly:boolean;issuedAt:number;expiresAt:number;issuerPk:string;sig:string}
export interface LoadedFlaggedList {info:ListInfo;network:Network;issuerPk:string;manifest:FlaggedManifest;manifestHash:string;outpoints:ReadonlySet<string>}
export interface FlaggedListProvider {readonly kind:'local-file'|'utexo-api';load(network:Network,at:number):Promise<LoadedFlaggedList>}
export const outpointValid=(p:unknown):p is string=>typeof p==='string'&&/^[0-9a-f]{64}:(0|[1-9][0-9]{0,9})$/.test(p)&&Number(p.split(':')[1])<=0xffffffff
export class LocalFileFlaggedListProvider implements FlaggedListProvider {
  readonly kind='local-file' as const
  constructor(readonly dir:string,private trustedIssuerKeys:readonly string[]) {assert(trustedIssuerKeys.length>0,'a flagged-list issuer must be explicitly trusted')}
  async load(expectedNetwork:Network,at:number):Promise<LoadedFlaggedList>{
    const m=JSON.parse(readFileSync(resolve(this.dir,'manifest.json'),'utf8')) as FlaggedManifest
    assert(m.v===1&&m.domain==='trust-flagged-manifest-v1'&&this.trustedIssuerKeys.includes(m.issuerPk)&&verifyObject(m,m.issuerPk),'flagged-list manifest signer untrusted or signature invalid')
    network(m.network);integer(m.issuedAt,'issuedAt');integer(m.expiresAt,'expiresAt');assert(m.network===expectedNetwork,'flagged-list network mismatch');assert(m.issuedAt<=at&&at<m.expiresAt,'flagged-list manifest not currently valid')
    assert(isHex(m.sha256,32),'flagged-list hash malformed')
    const bytes=readFileSync(localFile(this.dir,m.file));assert(sha256Hex(bytes)===m.sha256,'flagged-list file SHA-256 mismatch')
    const list=JSON.parse(bytes.toString()) as FlaggedSnapshot
    assert(list.v===1&&list.domain==='trust-flagged-outpoints-v1'&&list.network===expectedNetwork&&list.id===m.listId&&list.version===m.version&&list.testOnly===m.testOnly,'flagged-list metadata differs from its signed manifest')
    assert(typeof list.testOnly==='boolean'&&typeof list.id==='string'&&list.id.length>0&&typeof list.version==='string'&&list.version.length>0,'flagged-list identity invalid')
    assert(Array.isArray(list.outpoints)&&list.outpoints.every(outpointValid)&&new Set(list.outpoints).size===list.outpoints.length,'flagged-list outpoints invalid or duplicated')
    return {info:{id:list.id,version:list.version,sha256:m.sha256,testOnly:list.testOnly},network:expectedNetwork,issuerPk:m.issuerPk,manifest:m,manifestHash:hashObject(m),outpoints:new Set(list.outpoints)}
  }
}
export class UtexoApiFlaggedListProvider implements FlaggedListProvider {
  readonly kind='utexo-api' as const
  async load(_network:Network,_at:number):Promise<LoadedFlaggedList>{throw new Error('STUB: Utexo flagged-list API is not connected. TODO: obtain documented endpoint, authentication, issuer keys and version semantics from Utexo.')}
}
export function signFlaggedManifest(list:FlaggedSnapshot,file:string,bytes:Uint8Array,key:KeyPair,issuedAt:number,expiresAt:number):FlaggedManifest{return signObject({v:1 as const,domain:'trust-flagged-manifest-v1' as const,file,sha256:sha256Hex(bytes),listId:list.id,version:list.version,network:list.network,testOnly:list.testOnly,issuedAt,expiresAt,issuerPk:key.pubkey},key.secretKey)}
