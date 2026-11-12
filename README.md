# optimistic-rollup-fraud-proof

An interactive fraud-proof simulator for optimistic rollups, in pure Python
(no dependencies).

## The idea

Optimistic rollups post state roots optimistically and let anyone challenge a
wrong one. A challenge is settled by a **bisection game**: the defender posts
the state root at the midpoint of the disputed execution trace, the
challenger picks the half where the two traces still disagree, and after
log2(N) rounds the dispute narrows to a **single step**, which is re-executed
to decide the winner. The loser forfeits their bond.

This repo simulates the whole flow on a deliberately tiny deterministic VM —
one integer register plus a step counter, with `add` / `sub` / `mul` ops —
so the protocol logic stays readable. State roots are SHA-256 commitments,
standing in for the Merkle roots a real rollup would use.

## What's inside

- `fraud_proof.py`
  - `apply_op` / `execute` / `trace_roots` — the toy VM and its state roots
  - `BisectionGame` — the interactive game: `respond()` posts a midpoint
    root, `resolve()` re-executes the single disputed step, `forfeit()`
    covers a party that stops responding (timeout)
  - `play_game` — drives a whole game from the defender's posted roots
  - `Rollup` — posts assertions with escrowed bonds, opens challenges,
    settles disputes (winner takes the loser's bond), and finalizes
    unchallenged assertions once the challenge window elapses

## Usage

```bash
python3 fraud_proof.py          # run the demo: a dishonest proposer gets caught
python3 fraud_proof.py --test   # run the doctests
```

Demo output:

```
Optimistic rollup fraud-proof demo
program: [('add', 10), ('mul', 2), ('sub', 3), ('add', 7)]
honest final root:  ...
claimed final root: ...  (dishonest proposer)
bisection narrowed to step 3 after 2 rounds
disputed step: ('add', 7) from state (17, 3)
winner: challenger (takes the loser's bond)
```

## Covered cases

- Dishonest proposer challenged by an honest challenger — challenger wins.
- Malicious challenger disputing an honest assertion — defender wins.
- Unchallenged assertion finalizes after the challenge window; the bond is
  refunded.
- A party that stops responding forfeits the game.
