// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { isHex } from "./crypto.js";
export function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}
export function integer(value: unknown, name: string): asserts value is number {
  assert(
    Number.isSafeInteger(value) && Number(value) >= 0,
    `${name} must be a non-negative safe integer`,
  );
}
export function text(value: unknown, name: string): asserts value is string {
  assert(
    typeof value === "string" && value.length > 0 && value.length <= 4096,
    `${name} is required`,
  );
}
export function publicKey(
  value: unknown,
  name: string,
): asserts value is string {
  assert(isHex(value, 32), `${name} must be a 32-byte x-only public key`);
}
export function units(value: unknown, name = "amount"): bigint {
  assert(
    typeof value === "string" && /^(0|[1-9][0-9]{0,29})$/.test(value),
    `${name} must be a canonical non-negative integer string`,
  );
  return BigInt(value);
}
export const NETWORKS = ["utexo-testnet", "mutinynet"] as const;
export type Network = (typeof NETWORKS)[number];
export function network(value: unknown): asserts value is Network {
  assert(
    NETWORKS.includes(value as Network),
    "only Utexo testnet or Mutinynet fallback is supported",
  );
}
