"""Exception types shared across the package."""


class DacError(Exception):
    """Base class for every error this package raises deliberately."""


class RuleError(DacError):
    """A rule file is malformed, or violates a repository invariant."""


class ConditionError(DacError):
    """A Sigma ``condition`` expression could not be parsed or resolved."""


class ParserError(DacError):
    """A log line did not match the parser's expected shape."""
