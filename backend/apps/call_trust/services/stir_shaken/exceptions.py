"""Typed errors raised during STIR/SHAKEN verification."""


class StirShakenError(Exception):
    """Base class for controlled STIR/SHAKEN verification failures."""


class PassportFormatError(StirShakenError):
    """The compact PASSporT token is malformed or structurally invalid."""


class PassportClaimError(StirShakenError):
    """A required PASSporT claim is missing or invalid."""


class PassportSignatureError(StirShakenError):
    """The PASSporT signature could not be authenticated."""


class CertificateValidationError(StirShakenError):
    """The signing certificate is invalid or not trusted."""
