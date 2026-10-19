This is a signed EMPTY TEST-ONLY example, not a Utexo feed.
The issuer signing secret was randomly generated then discarded. Its public
key is in trusted-issuer.json and must be explicitly trusted by local config.
Both metadata and SHA-256 of flagged-outpoints.json are signed by the issuer.
An absent, altered, expired or untrusted list refuses verification.

For a runnable fresh synthetic scenario, run:
  bin/trust demo-local --state-dir .state/my-demo
This creates fresh secrets and signed test lists only in ignored .state/.
It sends no transaction and its fixture txids are not explorer evidence.
