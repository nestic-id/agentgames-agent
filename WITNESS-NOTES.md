# Witness / Circuit Reverse-Engineering Notes — Agent Games

Compiled 13 Nov 2026 from local analysis of the downloaded artifacts in
`~/workspace/agentgames/circuits/` (snarkjs 0.7.5, Node 24). Methods:
`strings` on the wasm binaries, `snarkjs zkey export verificationkey`,
FNV-1a-64 signal-name probing through snarkjs's own witness calculator
(error classification), element counters (`getInputSize()`), and targeted
assert-line fuzzing. Probe scripts: `scripts/probe-signals*.js`; raw results:
`data/signal-probe-results.json`, `data/signal-probe2-results.json`.

## What did NOT work

- `strings` on either `.wasm`: Circom 2.x witness calculators do not embed
  signal names — inputs are resolved by FNV-1a-64(name) → signal map.
  `strings` only surfaces runtime export names.
- Calling the wasm export `getInputSignalSize(hMSB, hLSB)` from a bare
  WebAssembly instantiation returns `0` for every plausible name and `-1`
  only for gibberish — unreliable standalone. The reliable oracle is
  snarkjs's own calculator: a real scalar input increments the
  "Not all inputs have been set. Only X out of N" counter; a real array
  input answers "Not enough values…"; anything else is not a signal.

## VERIFIED — gatekeeper circuit (13 public inputs, 0 private)

`getInputSize()` = 13 = `nPublic` from the exported VK → the input set below
is COMPLETE (all inputs are public, all size 1). A witness with all 13 set
calculates successfully.

| # | Signal name | Value source (our mapping) | Confidence |
|---|---|---|---|
| 1 | `taskId` | task.task_id (encoding unverified) | name: certain |
| 2 | `registeredVkHash` | task.input.registered_vk | name: certain |
| 3 | `proofVkHash` | task.input.proof_vk | name: certain |
| 4 | `minimum` | task.input.minimum | name: certain |
| 5 | `publicBalance` | task.input.public_balance | name: certain |
| 6 | `expiryBlock` | task.input.expiry_block | name: certain |
| 7 | `currentBlock` | task.input.current_block | name: certain |
| 8 | `recipient` | task.input.recipient | name: certain |
| 9 | `conditionRecipient` | task.input.condition_recipient | name: certain |
| 10 | `amount` | task.input.amount | name: certain |
| 11 | `maxTransfer` | task.input.max_transfer | name: certain |
| 12 | `decision` | our decision (encoding unverified) | name: certain |
| 13 | `salt` | ??? (we default to 0 via env) | name: certain, source unknown |

Notable: `proof_tx` is NOT a circuit input (the reuse binding is presumably
via `taskId`/`salt` platform-side). The circuit did NOT assert-fail on a
deliberately inconsistent input (registeredVkHash ≠ proofVkHash with
decision=0): the witness calculated. So the circuit appears to *bind* the
data + decision into the proof (platform re-verifies and scores the decision
itself) rather than enforcing the decision rule in-circuit — at least for
the combinations probed. Full-prove + local VK verify results are in the
project README / self-test output.

Still UNVERIFIED for gatekeeper (resolve from ONE practice-mode sample):
- Field encodings: how `registered_vk` (a 0x… string) becomes
  `registeredVkHash` (we use BigInt(value) mod BN254 p; switchable in
  `src/witness-config.gatekeeper.json` — encoder `hashField`), how
  `task_id` ("gk_…") becomes `taskId` (encoder `taskId`: hex→int, digits→int,
  else keccak256(utf8) mod p), and what `salt` is (default "0").
- `decision` encoding: we use APPROVE=1 / REJECT=0 (config
  `DECISION_APPROVE_VALUE` / `DECISION_REJECT_VALUE`).
- Public-signal ORDER in the response array: we pass snarkjs's
  `public_signals` through verbatim (declaration order); if the platform
  expects a different order it will show up as a practice verification
  failure, not a witness failure.

## VERIFIED — vfy-policy circuit (Steal the VFY)

- Input signals (names certain, via the counter oracle):
  scalars `commitment`, `matchId`, `turnNumber`, `selfBalance`,
  `opponentBalance`, `action`, `amount`, `circuitVersion`, `salt`, plus
  array `strategyParams` with **exactly 8 elements** (found by length scan:
  len<8 → "Not enough values"; len=8 → proceeds to asserts).
  Total input elements: 9 + 8 = 17 = `getInputSize()`. `nPublic` = 9.
  (Which 9 of the 17 elements are the public ones cannot be determined
  locally; snarkjs returns `public_signals` in the right order regardless.)
- **Commitment formula VERIFIED:** with
  `commitment = Poseidon(strategyParams[0..7], salt)` (circomlibjs Poseidon,
  params first, salt last), the circuit's first assert (template
  `VfyPolicyProof`, line 72) PASSES. Arrangements
  `Poseidon(salt, params…)`, `Poseidon(params…)`,
  `Poseidon(Poseidon(params…), salt)` all fail at line 72.
  → `scripts/commitment.js` uses exactly this arrangement (order switchable
  via `POSEIDON_INPUT_ORDER`).
- Template name leaked by assert errors: `VfyPolicyProof` (instance `_154`).

## UNRESOLVED — vfy-policy asserts at template lines 75 and 90

- Line 75 depends ONLY on `strategyParams` (commitment recomputed to match
  each time): all-zero params pass it; all-ones, all-twos, mixed 0/1/2,
  all-tens, and [1..8] all fail it — independent of action/amount/state.
  It is some params-validity constraint whose predicate we could not
  identify black-box (not a simple per-param range or a small sum bound,
  unless the bound is 0 — implausible; possibly a second hash/digest over
  the params in a different arrangement, or a params-structure check).
- Line 90 (reached with all-zero params) fails for every probed combination
  of turn (0/1/20), balances (100/100, 0/0, 90/110), action (0/1/2),
  amount (0/1/5/10/100), salt (0/1/7), circuitVersion (0/1/2).
- Consequence: as of this build, a fabricated Steal witness does NOT yet
  calculate end-to-end, so `scripts/selftest-proof.js` reports the Steal
  proof as NOT YET GENERABLE and the service degrades per
  `STEAL_PROOF_REQUIRED` (see README). ONE real practice-turn sample
  (envelope + an accepted response, or the dashboard's commitment helper
  output) should pin lines 75/90 down; the witness mapping is config-driven
  (`src/witness-config.steal.json`) precisely so this can be fixed in
  minutes.

## HMAC (from SPEC §3, still UNVERIFIED)

Digest/encoding of `x-agent-games-signature` is not published. Service
default: HMAC-SHA256 / hex, switchable via `HMAC_ALGO` / `HMAC_ENCODING`;
verification also accepts the alternate encoding (`HMAC_ACCEPT_ALT=true`)
and logs which one matched — the first preflight/practice request will
reveal the right combination in the logs.
