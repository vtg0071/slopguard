# Contributing to SlopGuard

Thanks for helping keep AI-assisted codebases clean and safe!

## Local Setup

```bash
git clone https://github.com/YOUR_USERNAME/slopguard.git
cd slopguard
pip install -e .
python -m unittest discover -s tests -v
slopguard check src --fail-on low
```

## Adding a New Detector

1. Add rule metadata in `src/slopguard/detectors/__init__.py` (`SG007`, etc.).
2. Implement your detector in `src/slopguard/detectors/`.
3. Wire it into `src/slopguard/scanner.py`.
4. Add unit tests in `tests/test_slopguard.py` and verify `slopguard check src --fail-on low` passes with Grade `A+`.
