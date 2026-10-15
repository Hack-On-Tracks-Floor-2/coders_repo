"""Alias wrapper forwarding execution to simulate_attack.py.

Preserves backward-compatibility with existing hackathon scripts:
    python simulate_attacks.py --mode all
"""

from simulate_attack import main

if __name__ == "__main__":
    main()
