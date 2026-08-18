class SecureTransferError(Exception):
    """Base exception for all secure file transfer errors."""
    def __init__(self, message: str, details: str = None):
        self.message = message
        self.details = details
        super().__init__(self.message)

    def __str__(self):
        if self.details:
            return f"[SecureTransfer Error] {self.message} | Details: {self.details}"
        return f"[SecureTransfer Error] {self.message}"


class KeyGenerationError(SecureTransferError):
    """Raised when RSA key generation or saving fails."""
    pass


class KeyLoadError(SecureTransferError):
    """Raised when loading RSA keys from disk fails."""
    pass


class EncryptionError(SecureTransferError):
    """Raised when AES or RSA encryption fails."""
    pass


class DecryptionError(SecureTransferError):
    """Raised when AES or RSA decryption fails."""
    pass


class IntegrityError(SecureTransferError):
    """Raised when HMAC verification fails — file may have been tampered with."""
    pass


class HandshakeError(SecureTransferError):
    """Raised when the protocol handshake between sender and receiver fails."""
    pass


class PacketError(SecureTransferError):
    """Raised when packet framing or parsing fails."""
    pass


class SessionError(SecureTransferError):
    """Raised when a transfer session encounters an unexpected error."""
    pass