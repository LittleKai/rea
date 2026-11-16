"""Hardeners: non-destructive transforms that strip reverse-engineering signal."""
from .engine import HardenManifest, harden_tree

__all__ = ["HardenManifest", "harden_tree"]
