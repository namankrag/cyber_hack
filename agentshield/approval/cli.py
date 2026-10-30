"""Human approval CLI: list pending holds, approve or deny them.

Usage (from cyber_hack/):
  .venv\\Scripts\\python.exe -m agentshield.approval.cli list
  .venv\\Scripts\\python.exe -m agentshield.approval.cli approve CALL_ID
  .venv\\Scripts\\python.exe -m agentshield.approval.cli deny CALL_ID

Audit path: AGENTSHIELD_AUDIT_PATH or ./audit.log.jsonl. Decisions are
appended as linked entries; history is never mutated.
"""
from __future__ import annotations

import os
import sys

from .queue import ApprovalQueue
from ..audit.log import AuditLog


def _queue() -> ApprovalQueue:
    return ApprovalQueue(AuditLog(os.getenv("AGENTSHIELD_AUDIT_PATH",
                                           "audit.log.jsonl")))


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] not in ("list", "approve", "deny"):
        print("usage: approval.cli list | approve CALL_ID | deny CALL_ID")
        return 2
    q = _queue()
    if args[0] == "list":
        pend = q.pending()
        if not pend:
            print("no pending approvals")
            return 0
        for e in pend:
            print(f"{e['call_id']} {e['tool']} {e.get('arguments')} | {e.get('ts')}")
        return 0
    if len(args) != 2:
        print("need CALL_ID")
        return 2
    try:
        entry = q.decide(args[1], args[0], approver="cli-human")
    except ValueError as ex:
        print(f"refused: {ex}")
        return 1
    print(f"{args[0]}d {entry['call_id']} for {args[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
