// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { mkdir, writeFile } from 'node:fs/promises'
import { probeNetwork } from '../src/network/probe.js'
async function main() {
  const result = await probeNetwork()
  await mkdir('release', { recursive: true })
  await writeFile('release/network-probe.json', `${JSON.stringify(result, null, 2)}\n`)
  console.log(JSON.stringify(result, null, 2))
  if (!result.ready) process.exitCode = 1
}
void main().catch(error => { console.error(String(error)); process.exitCode = 1 })
