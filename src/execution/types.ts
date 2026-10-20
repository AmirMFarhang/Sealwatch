// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
/** Labels describe verified execution, never a provider's unverified claim. */
export const EXECUTIONS = [
  "software",
  "tee:aws-nitro",
  "tee:intel-tdx",
  "tee:amd-sev-snp",
  "device:apple-app-attest",
  "device:android-key-attestation",
] as const;
export type Execution = (typeof EXECUTIONS)[number];
export type HardwareExecution = Exclude<Execution, "software">;
export function isExecution(value: unknown): value is Execution {
  return typeof value === "string" && EXECUTIONS.includes(value as Execution);
}
/** No real vendor parser is built. Every execution result currently remains software. */
export const CURRENT_EXECUTION = "software" as const;
