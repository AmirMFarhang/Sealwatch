# Network and reproducible test run

The selected primary is the pinned Utexo RGB SDK's `network: 'testnet'`, which is **Bitcoin testnet3**. The TLS Electrum server advertises its testnet3 genesis, and the probe fetches block zero and independently double-hashes its raw header. The RGB proxy must return `server.info` with protocol `0.2` before the run proceeds. This checks network identity and transport availability; it does not constitute an Utexo partnership.

The endpoints come from the [published SDK 1.0.3 README](https://www.npmjs.com/package/@utexo/rgb-sdk/v/1.0.3); the exact version's README was independently read from its [npm source archive](https://registry.npmjs.org/@utexo/rgb-sdk/-/rgb-sdk-1.0.3.tgz). Bitcoin Core's [testnet3 chain parameters](https://github.com/bitcoin/bitcoin/blob/master/src/kernel/chainparams.cpp) give the expected genesis. Pinned packages are `@utexo/wdk-wallet-rgb` 2.0.3, `@utexo/rgb-sdk` 1.0.3, `@utexo/rgb-lib` 0.3.0-beta.8 and `@tetherto/wdk` 1.0.0-beta.19. Use Node 22 or 24.

| Profile | SDK network | Indexer | RGB proxy |
| --- | --- | --- | --- |
| `utexo-testnet` (primary) | `testnet` | `ssl://electrum.iriswallet.com:50013` | `rpcs://proxy.iriswallet.com/0.2/json-rpc` |
| `mutinynet` (fallback) | `signet` | `https://esplora.signet.kaleidoswap.com` | `rpcs://proxy.kaleidoswap.com/json-rpc` |

`TRUST_NETWORK=utexo-testnet` is the single profile switch; it also selects explorer URLs, state directories and faucets. The initial primary time box began **19 October 2026 at 17:07:03 Europe/Rome** and ends at **21:07:03 Europe/Rome** (`19:07:03Z`). Do not switch to fallback before that cutoff unless Amir explicitly changes the decision. The recorded run enforces this cutoff. Mutinynet shares signet's genesis; the fallback probe records the configured public endpoint and tip, but does not independently verify its custom signet challenge.

```sh
npm ci
node --import tsx scripts/network-probe.ts
node --import tsx scripts/testnet-wallets.ts status
```

Wallet A and B are generated independently on their first setup. Seeds, SDK databases, signing authorities and receiver history live only under ignored `.state/<profile>/`, with private file/directory permissions. `TRUST_STATE_DIR` selects a separate private state root. Every address printed by the status command belongs to these new wallets. Never import an existing wallet or use real funds.

For the primary, use the public [coinfaucet testnet3 faucet](https://coinfaucet.eu/en/btc-testnet/) or [uo1 testnet faucet](https://bitcoinfaucet.uo1.net/). Check faucet availability first: on 19 October the former required a human hCaptcha, and the latter reported its wallet offline and no coins available. No CAPTCHA bypass or paid funding is used. The fallback's public faucet is [faucet.mutinynet.com](https://faucet.mutinynet.com/). Request enough confirmed faucet coins for at least 45,000 sats per wallet before creating eight 5,000-sat colorable outputs.

```sh
node --import tsx scripts/testnet-wallets.ts create-utxos
# Wait for the public chain to confirm the UTXO creation transactions.
node --import tsx scripts/testnet-wallets.ts status
node --import tsx scripts/testnet-wallets.ts issue
node --import tsx scripts/testnet-demo.ts
```

The asset is explicitly named **“test USD, not USDT”**, ticker `TUSD`, precision 2. The adapter uses `createUtxos` before sending, invokes the native `sendBegin` with `donation=true`, and treats statuses as strings. These are required quirks of the pinned SDK stack.

The run prepares an actual PSBT with the exact decoded invoice and native recipient map, then the local wallet adapter certifies that preview using its separate key. A signed policy authorizes a one-use token bound to the decoded PSBT, asset, amount, destination, fee and map. WDK's signing policy permits only the exact PSBT whose approval was consumed immediately before signing. The first actual transfer also demonstrates the send within limits. A second actual transfer uses a test flagged list containing one of that transaction's **actual decoded witness inputs**. The receiver independently decodes raw transactions and previous outputs fetched from the indexer; it first requires the SDK to report a settled witness receive for that asset and txid.

A flagged receive causes a coarse local quarantine of **the entire asset in wallet B**, persisted across restarts. The adapter refuses subsequent asset sends. This does not reverse or reject Bitcoin consensus settlement. Only attestations and list identities/hashes are included in the portable receipt; detailed witness and previous transactions remain receiver-local. RGB consignment ancestry (level 2) is designed, pending a reliable SDK API.

`release/testnet-receipt.json` is the evidence record. `complete` requires confirmed explorer checks for both actual sends, clear and flagged attestations, enforced quarantine, over-limit refusal and stop refusal. Missing coins or failed checks are recorded as incomplete; planned transactions never receive invented txids. The private progress journal resumes recorded broadcasts instead of sending them again. Preserve the state directory when retrying a partial run. Public testnet services can stall, so the SDK polling window can expire honestly before confirmation.
