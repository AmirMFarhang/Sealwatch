// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
// Derived from Satstride src/governance/store.ts (Apache-2.0); see NOTICE.
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { signObject, verifyObject, type KeyPair } from './crypto.js'
import { assert } from './validation.js'
/** Fail closed on an existing lock. Never evict a live writer using a time heuristic. */
export function withFileLock<T>(file: string, fn: () => T): T {
  mkdirSync(dirname(file), {recursive:true,mode:0o700})
  let fd: number
  try { fd=openSync(`${file}.lock`,'wx',0o600) } catch(e) { throw new Error(`state locked; retry after the writer exits: ${file}.lock`, {cause:e}) }
  try { return fn() } finally {closeSync(fd);unlinkSync(`${file}.lock`)}
}
export function atomicWrite(file: string, contents: string): void {
  mkdirSync(dirname(file), {recursive:true,mode:0o700})
  const temp=`${file}.${process.pid}.tmp`
  const fd=openSync(temp,'w',0o600)
  try {writeFileSync(fd,contents);fsyncSync(fd)} finally {closeSync(fd)}
  renameSync(temp,file)
  const dir=openSync(dirname(file),'r');try {fsyncSync(dir)} finally {closeSync(dir)}
}
export class SignedStore<T> {
  constructor(readonly file:string,private key:KeyPair,private initial:()=>T) {}
  read():T {
    if(!existsSync(this.file)) return this.initial()
    const value=JSON.parse(readFileSync(this.file,'utf8'))
    assert(value.domain==='trust-state-v1'&&value.pubkey===this.key.pubkey&&verifyObject(value,this.key.pubkey),'state signature invalid; refusing altered or foreign state')
    return structuredClone(value.state as T)
  }
  transact<R>(fn:(state:T)=>R):R {return withFileLock(this.file,()=>{ const state=this.read();const out=fn(state);atomicWrite(this.file,JSON.stringify(signObject({domain:'trust-state-v1',pubkey:this.key.pubkey,state},this.key.secretKey))+'\n');return out })}
}
