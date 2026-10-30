"""PatchProof — find the flaw, prove the fix.

A find -> prove -> patch -> prove-fixed pipeline for deliberately vulnerable
software. The core idea: don't trust a scanner alert, and don't trust a patch.
Prove each finding is real with a working exploit, then accept a fix only if it
(a) blocks that exploit AND (b) keeps the app's functionality green.
"""
__version__ = "0.1.0"
