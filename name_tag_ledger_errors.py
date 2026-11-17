class LedgerError(Exception):
    """Typed failure for missing or untrusted durable ledger state."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code: str = code
        super().__init__(message or code)
