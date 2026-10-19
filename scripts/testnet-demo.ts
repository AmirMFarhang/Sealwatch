// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { runTestnetDemo } from '../src/testnet/run.js'
void runTestnetDemo().catch(error => { console.error(String(error)); process.exitCode = 1 })
