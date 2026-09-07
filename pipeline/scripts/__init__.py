"""Executable pipeline steps, each usable standalone from a shell.

Every module here is both an importable library and a `python3 -m` entry point, so
a step can be unit-tested without a build agent and reproduced locally by hand.
Standard library only — an agent that cannot reach PyPI must still run these.
"""
