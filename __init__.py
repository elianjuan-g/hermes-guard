"""Hermes Guard — plugin root shim.

Hermes validates a plugin by loading the ``__init__.py`` that sits
BESIDE ``plugin.yaml`` (see hermes-agent plugin_validate.py: the
"loadable" check and the capability probe both load
``plugin_dir/__init__.py`` by file location). This package keeps its
code in ``src/hermes_guard/``, so this file only puts ``src/`` on
``sys.path`` and re-exports ``register``.

The probe calls ``register(RecordingContext())``; the context's
``get_config(key, default)`` returns the defaults, so register() is
safe to call with a stub.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "src"))

from hermes_guard import __version__, register  # noqa: E402,F401

__all__ = ["register", "__version__"]
