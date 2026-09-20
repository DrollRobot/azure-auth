r"""Sign with a private key held in the Windows certificate store.

The key never leaves the key storage provider, so this works for non-exportable and
TPM-backed keys. Signing goes through CNG (``NCryptSignHash``); legacy CryptoAPI keys are
not supported.

The design follows ``microsoft/entrabot`` (MIT licence),
``src/entrabot/auth/cncrypt_signer.py``. That implementation covers ``CurrentUser\My`` and
PKCS#1 padding; this one adds ``LocalMachine\My`` and PSS padding.

On platforms other than Windows every function raises
:class:`~azure_auth.auth.errors.CertificateUnavailable`.
"""

from __future__ import annotations

import sys
from typing import Literal

from azure_auth.auth.errors import CertificateUnavailable

StoreLocation = Literal["CurrentUser", "LocalMachine"]
Padding = Literal["pss", "pkcs1"]

_SHA1_HEX_LENGTH = 40
_SHA256_DIGEST_LENGTH = 32


class SignatureFailed(CertificateUnavailable):
    """The key storage provider refused to sign with the requested padding.

    Attributes:
        status: The ``SECURITY_STATUS`` returned by ``NCryptSignHash``.
    """

    def __init__(self, message: str, *, status: int) -> None:
        """Create the error.

        Args:
            message: Human readable description.
            status: The ``SECURITY_STATUS`` returned by ``NCryptSignHash``.
        """
        super().__init__(message)
        self.status = status


def normalise_thumbprint(thumbprint: str) -> str:
    """Return a SHA-1 thumbprint as 40 upper-case hex characters.

    Args:
        thumbprint: Thumbprint as shown by Windows; spaces and colons are ignored.

    Returns:
        The cleaned thumbprint.

    Raises:
        CertificateUnavailable: If the value is not a SHA-1 thumbprint.
    """
    cleaned = thumbprint.replace(" ", "").replace(":", "").upper()
    if len(cleaned) != _SHA1_HEX_LENGTH or any(c not in "0123456789ABCDEF" for c in cleaned):
        raise CertificateUnavailable(
            "certificate_thumbprint must be a SHA-1 thumbprint (40 hexadecimal characters)"
        )
    return cleaned


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _CERT_STORE_PROV_SYSTEM_W = 10
    _CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000
    _CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000
    _CERT_STORE_READONLY_FLAG = 0x00008000
    _CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000
    _X509_ASN_ENCODING = 0x00000001
    _PKCS_7_ASN_ENCODING = 0x00010000
    _CERT_FIND_SHA1_HASH = 0x00010000
    _CRYPT_ACQUIRE_SILENT_FLAG = 0x00000040
    _CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG = 0x00040000
    _BCRYPT_PAD_PKCS1 = 0x00000002
    _BCRYPT_PAD_PSS = 0x00000008
    _NCRYPT_SILENT_FLAG = 0x00000040
    _SHA256_ALGORITHM = "SHA256"

    class _CryptHashBlob(ctypes.Structure):
        """``CRYPT_HASH_BLOB``: a counted byte buffer."""

        _fields_ = (
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        )

    class _CertContext(ctypes.Structure):
        """``CERT_CONTEXT``: a certificate and its encoded bytes."""

        _fields_ = (
            ("dwCertEncodingType", wintypes.DWORD),
            ("pbCertEncoded", ctypes.POINTER(ctypes.c_ubyte)),
            ("cbCertEncoded", wintypes.DWORD),
            ("pCertInfo", ctypes.c_void_p),
            ("hCertStore", ctypes.c_void_p),
        )

    class _Pkcs1PaddingInfo(ctypes.Structure):
        """``BCRYPT_PKCS1_PADDING_INFO``."""

        _fields_ = (("pszAlgId", wintypes.LPCWSTR),)

    class _PssPaddingInfo(ctypes.Structure):
        """``BCRYPT_PSS_PADDING_INFO``."""

        _fields_ = (
            ("pszAlgId", wintypes.LPCWSTR),
            ("cbSalt", wintypes.ULONG),
        )

    def _load_libraries() -> tuple[ctypes.WinDLL, ctypes.WinDLL]:
        """Load ``crypt32`` and ``ncrypt`` and declare the prototypes used here.

        Returns:
            The ``crypt32`` and ``ncrypt`` library handles.
        """
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        ncrypt = ctypes.WinDLL("ncrypt", use_last_error=True)

        crypt32.CertOpenStore.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.LPCWSTR,
        ]
        crypt32.CertOpenStore.restype = ctypes.c_void_p
        crypt32.CertFindCertificateInStore.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        crypt32.CertFindCertificateInStore.restype = ctypes.POINTER(_CertContext)
        crypt32.CryptAcquireCertificatePrivateKey.argtypes = [
            ctypes.POINTER(_CertContext),
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.BOOL),
        ]
        crypt32.CryptAcquireCertificatePrivateKey.restype = wintypes.BOOL
        crypt32.CertFreeCertificateContext.argtypes = [ctypes.POINTER(_CertContext)]
        crypt32.CertFreeCertificateContext.restype = wintypes.BOOL
        crypt32.CertCloseStore.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        crypt32.CertCloseStore.restype = wintypes.BOOL

        ncrypt.NCryptSignHash.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_ubyte),
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.DWORD,
        ]
        ncrypt.NCryptSignHash.restype = ctypes.c_long
        ncrypt.NCryptFreeObject.argtypes = [ctypes.c_void_p]
        ncrypt.NCryptFreeObject.restype = ctypes.c_long
        return crypt32, ncrypt

    class _OpenCertificate:
        """A certificate found in a system store, released on exit."""

        def __init__(self, thumbprint: str, store_location: StoreLocation) -> None:
            """Remember which certificate to open.

            Args:
                thumbprint: SHA-1 thumbprint of the certificate.
                store_location: ``CurrentUser`` or ``LocalMachine``; the ``My`` store is used.
            """
            self._thumbprint = normalise_thumbprint(thumbprint)
            self._store_location = store_location
            self._crypt32, self.ncrypt = _load_libraries()
            self._store: int | None = None
            self.context: ctypes._Pointer[_CertContext] | None = None

        def __enter__(self) -> _OpenCertificate:
            """Open the store and find the certificate.

            Returns:
                This object, with ``context`` pointing at the certificate.

            Raises:
                CertificateUnavailable: If the store or the certificate cannot be opened.
            """
            location_flag = (
                _CERT_SYSTEM_STORE_LOCAL_MACHINE
                if self._store_location == "LocalMachine"
                else _CERT_SYSTEM_STORE_CURRENT_USER
            )
            self._store = self._crypt32.CertOpenStore(
                ctypes.c_void_p(_CERT_STORE_PROV_SYSTEM_W),
                0,
                None,
                location_flag | _CERT_STORE_READONLY_FLAG | _CERT_STORE_OPEN_EXISTING_FLAG,
                "MY",
            )
            if not self._store:
                raise CertificateUnavailable(
                    f"Cannot open certificate store {self._store_location}\\My "
                    f"(error {ctypes.get_last_error():#010x})"
                )

            raw = (ctypes.c_ubyte * 20).from_buffer_copy(bytes.fromhex(self._thumbprint))
            blob = _CryptHashBlob(len(raw), ctypes.cast(raw, ctypes.POINTER(ctypes.c_ubyte)))
            context = self._crypt32.CertFindCertificateInStore(
                self._store,
                _X509_ASN_ENCODING | _PKCS_7_ASN_ENCODING,
                0,
                _CERT_FIND_SHA1_HASH,
                ctypes.byref(blob),
                None,
            )
            if not context:
                self.__exit__(None, None, None)
                raise CertificateUnavailable(
                    f"Certificate {self._thumbprint} not found in {self._store_location}\\My"
                )
            self.context = context
            return self

        def __exit__(self, *_exc: object) -> None:
            """Release the certificate context and close the store."""
            if self.context:
                self._crypt32.CertFreeCertificateContext(self.context)
                self.context = None
            if self._store:
                self._crypt32.CertCloseStore(self._store, 0)
                self._store = None

        def acquire_key(self) -> tuple[ctypes.c_void_p, bool]:
            """Get a CNG handle for the certificate's private key.

            Returns:
                The key handle and whether the caller must free it.

            Raises:
                CertificateUnavailable: If the key is missing, is a legacy CryptoAPI key, or
                    the current account may not use it.
            """
            key = ctypes.c_void_p()
            key_spec = wintypes.DWORD()
            caller_must_free = wintypes.BOOL()
            acquired = self._crypt32.CryptAcquireCertificatePrivateKey(
                self.context,
                _CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | _CRYPT_ACQUIRE_SILENT_FLAG,
                None,
                ctypes.byref(key),
                ctypes.byref(key_spec),
                ctypes.byref(caller_must_free),
            )
            if not acquired:
                hint = (
                    " The account running this process needs read access to the private key"
                    " (certlm.msc > certificate > All Tasks > Manage Private Keys)."
                    if self._store_location == "LocalMachine"
                    else ""
                )
                raise CertificateUnavailable(
                    f"Cannot use the private key of certificate {self._thumbprint} in "
                    f"{self._store_location}\\My (error {ctypes.get_last_error():#010x}).{hint}"
                )
            return key, bool(caller_must_free.value)

    def load_certificate_der(
        thumbprint: str, store_location: StoreLocation = "CurrentUser"
    ) -> bytes:
        """Read a certificate's DER encoding from the Windows certificate store.

        Args:
            thumbprint: SHA-1 thumbprint of the certificate.
            store_location: ``CurrentUser`` or ``LocalMachine``; the ``My`` store is used.

        Returns:
            The DER-encoded certificate.

        Raises:
            CertificateUnavailable: If the certificate cannot be found.
        """
        with _OpenCertificate(thumbprint, store_location) as certificate:
            assert certificate.context is not None  # noqa: S101 (set by __enter__)
            contents = certificate.context.contents
            return ctypes.string_at(contents.pbCertEncoded, contents.cbCertEncoded)

    def sign_digest(
        thumbprint: str,
        digest: bytes,
        *,
        padding: Padding,
        store_location: StoreLocation = "CurrentUser",
    ) -> bytes:
        """Sign a SHA-256 digest with the certificate's private key.

        Args:
            thumbprint: SHA-1 thumbprint of the certificate.
            digest: The 32-byte SHA-256 digest to sign.
            padding: ``pss`` (salt length 32) or ``pkcs1``.
            store_location: ``CurrentUser`` or ``LocalMachine``; the ``My`` store is used.

        Returns:
            The raw RSA signature.

        Raises:
            CertificateUnavailable: If the certificate or its key cannot be used.
            SignatureFailed: If the key storage provider refuses to sign with ``padding``.
        """
        if len(digest) != _SHA256_DIGEST_LENGTH:
            raise ValueError("digest must be a 32-byte SHA-256 digest")

        padding_info: _PssPaddingInfo | _Pkcs1PaddingInfo
        if padding == "pss":
            padding_info = _PssPaddingInfo(_SHA256_ALGORITHM, _SHA256_DIGEST_LENGTH)
            flags = _BCRYPT_PAD_PSS | _NCRYPT_SILENT_FLAG
        else:
            padding_info = _Pkcs1PaddingInfo(_SHA256_ALGORITHM)
            flags = _BCRYPT_PAD_PKCS1 | _NCRYPT_SILENT_FLAG

        with _OpenCertificate(thumbprint, store_location) as certificate:
            key, caller_must_free = certificate.acquire_key()
            try:
                digest_buffer = (ctypes.c_ubyte * len(digest)).from_buffer_copy(digest)
                size = wintypes.DWORD()
                status = certificate.ncrypt.NCryptSignHash(
                    key,
                    ctypes.byref(padding_info),
                    digest_buffer,
                    len(digest),
                    None,
                    0,
                    ctypes.byref(size),
                    flags,
                )
                if status != 0:
                    raise SignatureFailed(
                        f"NCryptSignHash size probe failed with {padding} padding "
                        f"({status & 0xFFFFFFFF:#010x})",
                        status=status & 0xFFFFFFFF,
                    )
                signature = (ctypes.c_ubyte * size.value)()
                status = certificate.ncrypt.NCryptSignHash(
                    key,
                    ctypes.byref(padding_info),
                    digest_buffer,
                    len(digest),
                    signature,
                    size.value,
                    ctypes.byref(size),
                    flags,
                )
                if status != 0:
                    raise SignatureFailed(
                        f"NCryptSignHash failed with {padding} padding "
                        f"({status & 0xFFFFFFFF:#010x})",
                        status=status & 0xFFFFFFFF,
                    )
                return bytes(signature[: size.value])
            finally:
                if caller_must_free:
                    certificate.ncrypt.NCryptFreeObject(key)

else:

    def load_certificate_der(
        thumbprint: str, store_location: StoreLocation = "CurrentUser"
    ) -> bytes:
        """Raise, because the Windows certificate store only exists on Windows.

        Args:
            thumbprint: SHA-1 thumbprint of the certificate.
            store_location: ``CurrentUser`` or ``LocalMachine``.

        Raises:
            CertificateUnavailable: Always.
        """
        raise CertificateUnavailable(
            "certificate_thumbprint needs the Windows certificate store; "
            "use certificate_pem or certificate_pfx on this platform"
        )

    def sign_digest(
        thumbprint: str,
        digest: bytes,
        *,
        padding: Padding,
        store_location: StoreLocation = "CurrentUser",
    ) -> bytes:
        """Raise, because the Windows certificate store only exists on Windows.

        Args:
            thumbprint: SHA-1 thumbprint of the certificate.
            digest: The 32-byte SHA-256 digest to sign.
            padding: ``pss`` or ``pkcs1``.
            store_location: ``CurrentUser`` or ``LocalMachine``.

        Raises:
            CertificateUnavailable: Always.
        """
        raise CertificateUnavailable(
            "certificate_thumbprint needs the Windows certificate store; "
            "use certificate_pem or certificate_pfx on this platform"
        )
