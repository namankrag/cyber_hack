"""HTTP gateway — the enforcement point exposed over the network."""


#: Edge input budget shared by the HTTP and MCP doors. Oversized inputs are
#: rejected before they reach the CPU-heavy synchronous detectors (a 5MB
#: context blocks the event loop ~5s, measured). Legitimate tool calls carry
#: kilobytes, so 256KB is generous by design.
MAX_BODY_BYTES = 256 * 1024


def input_too_large(context: str, arguments: dict) -> bool:
    """True when an MCP/tool-call input exceeds the edge budget."""
    size = len(context or '')
    for value in (arguments or {}).values():
        size += len(str(value))
        if size > MAX_BODY_BYTES:
            return True
    return size > MAX_BODY_BYTES
