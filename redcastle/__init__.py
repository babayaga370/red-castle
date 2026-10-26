"""Red Castle - a guarded deletion pipeline for AI agents.

AI agents may *ask* to delete things. Only the Executioner, acting on a
warrant a human sealed in the Throne Room, may destroy anything.

    Agent -> Gateway -> Judge -> Quarantine -> Throne Room -> Executioner
                                     (everything recorded in the Chronicle)

    Around the wall: the Moat (guardrails), the Watchtower (monitoring)
    and the Traps (canaries).
"""

__version__ = "0.1.0"
