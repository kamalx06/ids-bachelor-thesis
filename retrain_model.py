#!/usr/bin/env python3
"""CLI entry point for model retraining (delegates to ai.retrainer)."""

from ai.retrainer import main

if __name__ == "__main__":
    raise SystemExit(main())
