"""Optimistic rollup fraud-proof simulator in pure Python.

Models the classic interactive bisection game used by optimistic rollups
(Optimism / Arbitrum style):

* A proposer posts an assertion -- the state root after executing a batch of
  transactions -- together with a bond.
* During the challenge window anyone may challenge the assertion by posting
  their own bond.  The two parties then bisect the disputed execution trace:
  the defender posts the state root at the midpoint; the challenger picks the
  half where their roots still disagree.  After log2(N) rounds the dispute
  narrows to a single step, which is re-executed (here: locally, standing in
  for the on-chain single-step proof) to decide the winner.  The loser
  forfeits their bond to the winner.
* If nobody challenges within the window, the assertion finalizes and the
  proposer's bond is refunded.

The "VM" is a deliberately tiny deterministic machine: one integer register
plus a step counter, with a small op set.  State roots are SHA-256
commitments, standing in for the Merkle roots a real rollup would use.

Run the demo::

    python3 fraud_proof.py

Run the doctests::

    python3 fraud_proof.py --test
"""

from __future__ import annotations

import hashlib

__all__ = [
    "apply_op",
    "state_root",
    "execute",
    "trace_roots",
    "BisectionGame",
    "play_game",
    "Assertion",
    "Rollup",
]


def apply_op(state, op):
    """Apply one VM op to ``state`` and return the new state.

    A state is ``(register, steps_executed)``.  Ops are ``(name, arg)`` with
    ``name`` in ``add`` / ``sub`` / ``mul``.

    >>> apply_op((10, 0), ("add", 5))
    (15, 1)
    >>> apply_op((10, 1), ("mul", 3))
    (30, 2)
    >>> apply_op((10, 2), ("sub", 4))
    (6, 3)
    """
    x, pc = state
    name, arg = op
    if name == "add":
        x += arg
    elif name == "sub":
        x -= arg
    elif name == "mul":
        x *= arg
    else:
        raise ValueError(f"unknown op: {name!r}")
    return (x, pc + 1)


def state_root(state):
    """Commitment to a state: SHA-256 over ``register:steps``.

    >>> state_root((0, 0)) == state_root((0, 0))
    True
    >>> state_root((0, 0)) == state_root((1, 0))
    False
    """
    return hashlib.sha256(f"{state[0]}:{state[1]}".encode()).hexdigest()


def execute(program, initial=(0, 0)):
    """Run ``program`` from ``initial``; return the list of states.

    ``states[i]`` is the state after ``i`` steps, so
    ``len(states) == len(program) + 1``.

    >>> prog = [("add", 2), ("mul", 3), ("sub", 1)]
    >>> execute(prog)
    [(0, 0), (2, 1), (6, 2), (5, 3)]
    """
    states = [initial]
    for op in program:
        states.append(apply_op(states[-1], op))
    return states


def trace_roots(program, initial=(0, 0)):
    """State roots for every step of ``program`` (``len(program) + 1`` roots).

    >>> prog = [("add", 2)]
    >>> roots = trace_roots(prog)
    >>> len(roots)
    2
    >>> roots[0] == state_root((0, 0))
    True
    """
    return [state_root(s) for s in execute(program, initial)]


class BisectionGame:
    """Interactive bisection over one disputed execution trace.

    ``program`` is the batch the assertion covers; ``initial`` is the agreed
    pre-state.  ``claimed_final_root`` is the proposer's posted root and
    ``challenger_roots`` the challenger's own trace roots (same length,
    agreeing at step 0, disagreeing at the final step -- otherwise there is
    nothing to dispute).

    The game narrows ``(lo, hi]`` -- steps ``<= lo`` are agreed, step ``hi``
    is the first step where the two traces disagree -- until a single step
    remains, which :meth:`resolve` re-executes to name the winner.
    """

    def __init__(self, program, initial, claimed_final_root, challenger_roots,
                 bond=100):
        if len(challenger_roots) != len(program) + 1:
            raise ValueError(
                "challenger_roots must have one root per step plus the initial state")
        if challenger_roots[0] != state_root(initial):
            raise ValueError(
                "challenger trace must start from the agreed initial state")
        if challenger_roots[-1] == claimed_final_root:
            raise ValueError(
                "challenger agrees with the claimed final root: nothing to dispute")
        self.program = list(program)
        self.initial = initial
        self.claimed_final_root = claimed_final_root
        self.challenger_roots = list(challenger_roots)
        self.bond = bond
        self.true_states = execute(program, initial)
        self.lo = 0
        self.hi = len(program)
        self.claimed_hi_root = claimed_final_root
        self.rounds = 0
        self.winner = None

    @property
    def narrowed(self):
        """True once the dispute covers exactly one step."""
        return self.hi - self.lo == 1

    @property
    def midpoint(self):
        """Middle step of the currently disputed range."""
        return (self.lo + self.hi) // 2

    def respond(self, mid_root):
        """Defender posts the root at the midpoint of the disputed range.

        Returns ``"left"`` when the dispute moves to ``(lo, mid]`` and
        ``"right"`` when it moves to ``(mid, hi]``.
        """
        if self.winner is not None:
            raise ValueError("game already decided")
        if self.narrowed:
            raise ValueError("already narrowed to a single step; call resolve()")
        mid = self.midpoint
        self.rounds += 1
        if mid_root == self.challenger_roots[mid]:
            self.lo = mid
            return "right"
        self.hi = mid
        self.claimed_hi_root = mid_root
        return "left"

    def forfeit(self, party):
        """``party`` (``"defender"`` or ``"challenger"``) stops responding.

        The other side wins immediately -- the on-chain equivalent of a
        response timeout.
        """
        if self.winner is not None:
            return self.winner
        if party == "defender":
            self.winner = "challenger"
        elif party == "challenger":
            self.winner = "defender"
        else:
            raise ValueError("party must be 'defender' or 'challenger'")
        return self.winner

    def resolve(self):
        """Re-execute the single disputed step and name the winner.

        The defender wins only if the claimed root for the disputed step
        matches the honestly executed result; otherwise the challenger wins.
        """
        if self.winner is not None:
            return self.winner
        if not self.narrowed:
            raise ValueError("bisect first: dispute still spans more than one step")
        pre = self.true_states[self.lo]
        expected = state_root(apply_op(pre, self.program[self.lo]))
        self.winner = "defender" if expected == self.claimed_hi_root else "challenger"
        return self.winner


def play_game(program, initial, claimed_final_root, challenger_roots,
              defender_roots, bond=100):
    """Play a whole bisection game: the defender posts from ``defender_roots``.

    Returns the :class:`BisectionGame` after resolution.

    Dishonest proposer -- the challenger's honest trace exposes the lie::

    >>> prog = [("add", 10), ("mul", 2), ("sub", 3), ("add", 7)]
    >>> honest = trace_roots(prog)
    >>> bad = state_root((999, 4))
    >>> defender = honest[:-1] + [bad]
    >>> game = play_game(prog, (0, 0), bad, honest, defender)
    >>> game.winner
    'challenger'
    >>> game.rounds
    2
    >>> game.lo, game.hi
    (3, 4)

    Malicious challenger -- the honest defender's trace wins::

    >>> challenger_prog = [("add", 10), ("mul", 2), ("add", 5), ("add", 7)]
    >>> challenger_roots = trace_roots(challenger_prog)
    >>> game = play_game(prog, (0, 0), honest[-1], challenger_roots, honest)
    >>> game.winner
    'defender'
    """
    game = BisectionGame(program, initial, claimed_final_root, challenger_roots, bond)
    while not game.narrowed:
        game.respond(defender_roots[game.midpoint])
    game.resolve()
    return game


class Assertion:
    """One posted assertion: claimed final root + bond + challenge window."""

    def __init__(self, proposer, program, initial, final_root, bond, posted_at,
                 challenge_window):
        self.proposer = proposer
        self.program = list(program)
        self.initial = initial
        self.final_root = final_root
        self.bond = bond
        self.posted_at = posted_at
        self.challenge_window = challenge_window
        self.status = "pending"  # pending | disputed | finalized | slashed
        self.challenger = None
        self.dispute = None


class Rollup:
    """Minimal optimistic rollup: post assertions, challenge them, finalize.

    Bonds are tracked in a plain ``balances`` ledger (addresses are just
    strings here); the winner of a dispute takes the loser's bond, and an
    unchallenged assertion refunds the proposer's bond on finalization.

    >>> rollup = Rollup(challenge_window=5)
    >>> rollup.fund("alice", 500)
    >>> rollup.fund("bob", 500)
    >>> prog = [("add", 10), ("mul", 2), ("sub", 3), ("add", 7)]
    >>> honest = trace_roots(prog)
    >>> bad = state_root((999, 4))
    >>> a = rollup.post_assertion("alice", prog, (0, 0), bad, bond=100)
    >>> rollup.balances["alice"]
    400
    >>> game = rollup.challenge(a, "bob", honest, bond=100)
    >>> rollup.balances["bob"]
    400
    >>> defender_roots = honest[:-1] + [bad]
    >>> while not game.narrowed:
    ...     game.respond(defender_roots[game.midpoint])
    'right'
    'right'
    >>> game.resolve()
    'challenger'
    >>> rollup.settle_dispute(a)
    'slashed'
    >>> rollup.balances["bob"]
    600
    >>> rollup.balances["alice"]
    400
    >>> b = rollup.post_assertion("alice", prog, (0, 0), honest[-1], bond=100)
    >>> rollup.finalize(b)
    Traceback (most recent call last):
    ...
    ValueError: challenge window has not elapsed yet
    >>> rollup.advance(5)
    >>> rollup.finalize(b)
    'finalized'
    >>> rollup.balances["alice"]
    400
    """

    def __init__(self, challenge_window=10):
        self.challenge_window = challenge_window
        self.block = 0
        self.balances = {}
        self.assertions = []

    def fund(self, address, amount):
        """Credit ``amount`` to ``address`` in the bond ledger."""
        self.balances[address] = self.balances.get(address, 0) + amount

    def advance(self, blocks=1):
        """Move the chain forward by ``blocks``."""
        self.block += blocks

    def post_assertion(self, proposer, program, initial, claimed_final_root,
                       bond=100):
        """Post an assertion, escrowing the proposer's bond."""
        if self.balances.get(proposer, 0) < bond:
            raise ValueError(f"{proposer} has insufficient balance for the bond")
        self.balances[proposer] -= bond
        assertion = Assertion(proposer, program, initial, claimed_final_root,
                              bond, self.block, self.challenge_window)
        self.assertions.append(assertion)
        return assertion

    def challenge(self, assertion, challenger, challenger_roots, bond=100):
        """Challenge a pending assertion; opens a bisection game."""
        if assertion.status != "pending":
            raise ValueError("assertion is not pending")
        if self.block > assertion.posted_at + assertion.challenge_window:
            raise ValueError("challenge window has elapsed")
        if self.balances.get(challenger, 0) < bond:
            raise ValueError(f"{challenger} has insufficient balance for the bond")
        self.balances[challenger] -= bond
        game = BisectionGame(assertion.program, assertion.initial,
                             assertion.final_root, challenger_roots, bond)
        assertion.status = "disputed"
        assertion.challenger = challenger
        assertion.dispute = game
        return game

    def settle_dispute(self, assertion):
        """Pay out a decided dispute: the winner takes the loser's bond."""
        game = assertion.dispute
        if game is None:
            raise ValueError("assertion was never disputed")
        if game.winner is None:
            raise ValueError("dispute has no winner yet")
        if game.winner == "challenger":
            self.balances[assertion.challenger] += assertion.bond + game.bond
            assertion.status = "slashed"
        else:
            self.balances[assertion.proposer] += assertion.bond + game.bond
            assertion.status = "finalized"
        return assertion.status

    def finalize(self, assertion):
        """Finalize an unchallenged assertion once its window has elapsed."""
        if assertion.status != "pending":
            raise ValueError("assertion is not pending")
        if self.block < assertion.posted_at + self.challenge_window:
            raise ValueError("challenge window has not elapsed yet")
        assertion.status = "finalized"
        self.balances[assertion.proposer] += assertion.bond
        return assertion.status

    def finalizable(self):
        """Pending assertions whose challenge window has elapsed.

        These are the assertions :meth:`finalize` will accept right now --
        a natural helper for an operator sweeping the rollup for work to do.

        >>> rollup = Rollup(challenge_window=5)
        >>> rollup.fund("alice", 500)
        >>> prog = [("add", 1)]
        >>> a = rollup.post_assertion("alice", prog, (0, 0), trace_roots(prog)[-1])
        >>> rollup.finalizable()
        []
        >>> rollup.advance(5)
        >>> rollup.finalizable() == [a]
        True
        >>> rollup.finalize(a)
        'finalized'
        >>> rollup.finalizable()
        []
        """
        deadline = self.block
        return [
            a for a in self.assertions
            if a.status == "pending"
            and a.posted_at + a.challenge_window <= deadline
        ]


def _demo():
    """Run the headline scenario and print what happened."""
    prog = [("add", 10), ("mul", 2), ("sub", 3), ("add", 7)]
    honest = trace_roots(prog)
    bad_final = state_root((999, 4))
    defender_roots = honest[:-1] + [bad_final]

    print("Optimistic rollup fraud-proof demo")
    print(f"program: {prog}")
    print(f"honest final root:  {honest[-1][:16]}...")
    print(f"claimed final root: {bad_final[:16]}...  (dishonest proposer)")
    game = play_game(prog, (0, 0), bad_final, honest, defender_roots)
    print(f"bisection narrowed to step {game.lo} after {game.rounds} rounds")
    print(f"disputed step: {prog[game.lo]} from state {game.true_states[game.lo]}")
    print(f"winner: {game.winner} (takes the loser's bond)")


if __name__ == "__main__":
    import sys

    if "--test" in sys.argv:
        import doctest

        raise SystemExit(doctest.testmod(verbose=False).failed)
    _demo()
