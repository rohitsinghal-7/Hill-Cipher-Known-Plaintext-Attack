Cyber Security Lab (7CS4-22) - Mini Project CSL-G04
Hill Cipher with Known-Plaintext Attack
Name: Rohit Singhal      Roll No.: 23ESKCS191
Submitted to: Vikash Dhankar, Assistant Professor, Dept. of CSE, SKIT Jaipur

REQUIREMENTS
  Python 3.8 or later (tested on Python 3.12.3, Ubuntu 24.04).
  No third-party package is needed. matplotlib is optional (only draws the
  graphs in experiments.py).

FILES
  src/hill_cipher.py             Hill cipher: mod-26 maths, matrix inverse, encrypt/decrypt
  src/known_plaintext_attack.py  Known-plaintext attack (3 strategies), chosen-plaintext
                                 attack, brute force
  src/main.py                    Menu program (python main.py) and demo (--demo)
  src/experiments.py             Seeded experiments -> results/results.json + graphs
  tests/test_hill.py             29 unit tests
  results/                       Output of experiments.py

HOW TO RUN
  cd src
  python main.py              (menu: encrypt, decrypt, known-plaintext attack,
                               chosen-plaintext attack, brute force, demo)
  python main.py --demo       (scripted demonstration, no input needed)
  python experiments.py       (experiments E1-E5; timings vary by machine)
  cd ..
  python -m unittest discover -s tests -v      (29 tests, all pass)

CONVENTION
  Letters A=0 ... Z=25.  Encryption is c = K * p (mod 26) for each n-letter
  block p (column vector); the key word of n*n letters fills K row by row.
  Example: key DDCF = [[3,3],[2,5]], HELP -> HIAT;  key GYBNQKURP, ACT -> POH.

ETHICAL NOTE
  Only dummy text and randomly generated keys on the local machine are used.
  No network, real password, personal data, malware or third-party system is
  involved.
