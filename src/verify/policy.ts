import { hashObject } from "../core/crypto.js";
/** Versioned receiver rules, distinct from a remote workload's own policy. */
export const RECEIVER_POLICY = Object.freeze({ id: "receiver-verification", version: 1, sanctions: "pinned-inputs-and-receiver-context", flagged: "signed-list-level-1", provider: "optional-strictest-error-flagged-clear", quarantine: "flagged-or-error-permanent-until-explicit-owner-recovery" });
export const RECEIVER_POLICY_REF = Object.freeze({ id: RECEIVER_POLICY.id, version: RECEIVER_POLICY.version, sha256: hashObject(RECEIVER_POLICY) });
