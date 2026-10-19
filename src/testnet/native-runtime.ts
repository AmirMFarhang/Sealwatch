// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { setFlagsFromString } from 'node:v8'
import { runInNewContext } from 'node:vm'
const major = Number(process.versions.node.split('.')[0])
if (major !== 22 && major !== 24) throw new Error('The RGB native binding requires Node 22 or 24')
// rgb-lib SWIG handles must finish collection while the V8 isolate is still current.
setFlagsFromString('--expose-gc')
let collect: () => void
try { collect = runInNewContext('gc') as () => void } finally { setFlagsFromString('--no-expose-gc') }
process.once('exit', () => collect())
