"""Application-specific errors shown to the operator."""


class AssessmentError(Exception):
    """Base class for expected assessment errors."""


class ConfigurationError(AssessmentError):
    """Project configuration is missing or invalid."""


class InvalidTargetError(AssessmentError):
    """The supplied IP address or hostname is malformed."""


class ScopeDeniedError(AssessmentError):
    """The target or destination is not in the approved local scope."""


class ResolutionError(AssessmentError):
    """The hostname could not be resolved safely."""


class PersistenceError(AssessmentError):
    """Assessment data could not be saved or loaded."""


class AssessmentNotFoundError(PersistenceError):
    """A requested assessment ID is not present in the project database."""
