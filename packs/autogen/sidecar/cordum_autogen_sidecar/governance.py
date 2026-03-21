"""Governance wrappers for AutoGen — uses sidecar-template's GovernedAutoGenFunction."""
# Re-export from the sidecar template governance module for convenience.
# The actual GovernedAutoGenFunction is in integrations/sidecar-template/python/governance.py

from governance import GovernedAutoGenFunction, GovernedTool, GovernanceDeniedError, GovernanceError

__all__ = ["GovernedAutoGenFunction", "GovernedTool", "GovernanceDeniedError", "GovernanceError"]
