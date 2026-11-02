"""Privileged-service boundary (R13, R13b): protocol, command authorization, core.

Nothing in this package elevates or touches the system on its own. The Windows
service shell, pipe DACL and worker tokens are separate thin layers checked by
the owner's elevated acceptance script; everything here runs unelevated in tests.
"""
