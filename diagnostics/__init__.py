"""
diagnostics — Auto-debug & self-healing diagnostics for TorShield

Re-exports from auto_debug_system.py and self_heal.py, providing
convenient access to the autonomous debugging and self-healing
capabilities from the organized enterprise structure.

Usage:
    from diagnostics import AutoDebugSystem
    from diagnostics import check_python_syntax, apply_patch

All original imports remain functional:
    from auto_debug_system import AutoDebugSystem  # still works
    from self_heal import check_python_syntax       # still works
"""

import importlib
import sys
import os

# Ensure project root is on sys.path
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# Import from auto_debug_system (root-level module)
_auto_debug = importlib.import_module("auto_debug_system")
AutoDebugSystem = _auto_debug.AutoDebugSystem

# Import from self_heal (root-level module)
_self_heal = importlib.import_module("self_heal")
check_python_syntax = _self_heal.check_python_syntax
check_yaml_syntax = _self_heal.check_yaml_syntax
apply_patch = _self_heal.apply_patch
commit_patches = _self_heal.commit_patches
write_log = _self_heal.write_log

# Import from torshield_ai_gateway.auto_debug (gateway-integrated auto-debug)
_auto_debug_gw = importlib.import_module("torshield_ai_gateway.auto_debug")
AutoDebugEngine = _auto_debug_gw.AutoDebugEngine

__all__ = [
    "AutoDebugSystem",
    "AutoDebugEngine",
    "check_python_syntax",
    "check_yaml_syntax",
    "apply_patch",
    "commit_patches",
    "write_log",
]
