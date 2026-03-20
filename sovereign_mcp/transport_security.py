"""
TransportSecurity — Mandatory mTLS for MCP Connections.
========================================================
Enforces mutual TLS (mTLS) for all network MCP connections.
The CA certificate is frozen in FrozenNamespace at startup
and cannot be modified at runtime.

Architecture Lines 754-808:
    1. Local connections (stdio): no encryption needed
    2. Network connections: mandatory mTLS
    3. Certificate management: frozen CA, revocation list
    4. Channel binding: prevents MITM re-establishment
    5. Fallback policy: CONNECTION REFUSED if mTLS fails

The frozen CA certificate extends the root of trust to the
transport layer. An attacker cannot substitute a fake CA at runtime.
"""

import hashlib
import hmac
import ssl
import os
import time
import logging

logger = logging.getLogger(__name__)


class TransportSecurity:
    """
    Mandatory mTLS enforcement for MCP network connections.

    Stores the frozen CA certificate, validates server and client
    certificates, enforces channel binding, and refuses any
    connection that cannot establish mutual TLS.

    Usage:
        ts = TransportSecurity(
            ca_cert_path="/path/to/ca.pem",
            client_cert_path="/path/to/client.pem",
            client_key_path="/path/to/client.key",
        )
        ts.freeze()

        # Create SSL context for outgoing connections
        ctx = ts.create_client_context()

        # Create SSL context for incoming connections
        ctx = ts.create_server_context(
            server_cert_path="/path/to/server.pem",
            server_key_path="/path/to/server.key",
        )

        # Validate a connection
        ts.validate_connection(ssl_socket)
    """

    def __init__(self, ca_cert_path=None, client_cert_path=None,
                 client_key_path=None, revocation_list=None,
                 max_cert_age_hours=24):
        """
        Args:
            ca_cert_path: Path to the CA certificate PEM file.
            client_cert_path: Path to the client certificate PEM file.
            client_key_path: Path to the client private key PEM file.
            revocation_list: List of revoked certificate serial numbers.
            max_cert_age_hours: Maximum certificate age in hours
                                (short-lived certificates).
        """
        self._ca_cert_path = ca_cert_path
        self._client_cert_path = client_cert_path
        self._client_key_path = client_key_path
        self._revocation_list = set(revocation_list or [])
        self._max_cert_age_hours = max_cert_age_hours
        self._frozen = False

        # Frozen state
        self._ca_cert_hash = None       # SHA-256 of frozen CA cert
        self._ca_cert_data = None       # Raw CA cert bytes
        self._client_cert_hash = None   # SHA-256 of frozen client cert
        self._frozen_at = None          # Timestamp of freeze

        logger.info("[TransportSecurity] Initialized. Not yet frozen.")

    def freeze(self):
        """
        Freeze the CA certificate and client certificate.

        After this call, the certificates cannot be changed.
        The CA cert hash becomes the trust anchor.

        Raises:
            RuntimeError: If already frozen or CA cert not configured.
            FileNotFoundError: If certificate files don't exist.
        """
        if self._frozen:
            raise RuntimeError(
                "TRANSPORT SECURITY SEALED: Already frozen. "
                "Certificate rotation requires blue-green deployment."
            )

        if not self._ca_cert_path:
            raise RuntimeError(
                "CA certificate path is required for transport security."
            )

        # Read and hash the CA certificate
        if not os.path.exists(self._ca_cert_path):
            raise FileNotFoundError(
                f"CA certificate not found: {self._ca_cert_path}"
            )
        with open(self._ca_cert_path, "rb") as f:
            self._ca_cert_data = f.read()
        self._ca_cert_hash = hashlib.sha256(self._ca_cert_data).hexdigest()

        # Hash the client certificate if provided
        if self._client_cert_path and os.path.exists(self._client_cert_path):
            with open(self._client_cert_path, "rb") as f:
                client_data = f.read()
            self._client_cert_hash = hashlib.sha256(client_data).hexdigest()

        self._frozen = True
        self._frozen_at = time.time()

        logger.info(
            f"[TransportSecurity] FROZEN. CA hash: {self._ca_cert_hash[:16]}... "
            f"Revocation list: {len(self._revocation_list)} entries. "
            f"Max cert age: {self._max_cert_age_hours}h"
        )

    @property
    def is_frozen(self):
        """Whether transport security has been frozen."""
        return self._frozen

    @property
    def ca_cert_hash(self):
        """SHA-256 hash of the frozen CA certificate."""
        return self._ca_cert_hash

    def verify_ca_integrity(self):
        """
        Verify that the CA certificate file has not been tampered with
        since it was frozen.

        Returns:
            tuple: (is_valid: bool, reason: str)
        """
        if not self._frozen:
            return False, "Transport security not frozen."

        if not os.path.exists(self._ca_cert_path):
            return False, f"CA certificate file missing: {self._ca_cert_path}"

        with open(self._ca_cert_path, "rb") as f:
            current_data = f.read()
        current_hash = hashlib.sha256(current_data).hexdigest()

        if hmac.compare_digest(current_hash, self._ca_cert_hash):
            return True, "CA certificate integrity verified."
        else:
            return False, (
                f"CA CERTIFICATE TAMPERED: hash mismatch. "
                f"Frozen: {self._ca_cert_hash[:16]}... "
                f"Current: {current_hash[:16]}..."
            )

    def create_client_context(self):
        """
        Create an SSL context for outgoing mTLS connections.

        The context requires:
        - Server certificate validation against frozen CA
        - Client certificate presentation (mutual auth)
        - TLS 1.2+ only
        - No fallback to unencrypted

        Returns:
            ssl.SSLContext configured for mTLS client connections.

        Raises:
            RuntimeError: If not frozen or certificates not configured.
        """
        if not self._frozen:
            raise RuntimeError(
                "TRANSPORT NOT FROZEN: Cannot create SSL context before freeze."
            )

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Enforce minimum TLS 1.2
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Load frozen CA certificate for server validation
        ctx.load_verify_locations(cadata=self._ca_cert_data.decode("utf-8"))

        # Load client certificate for mutual authentication
        if self._client_cert_path and self._client_key_path:
            ctx.load_cert_chain(
                certfile=self._client_cert_path,
                keyfile=self._client_key_path,
            )

        # Require server certificate verification
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True

        logger.info("[TransportSecurity] Client SSL context created (mTLS).")
        return ctx

    def create_server_context(self, server_cert_path, server_key_path):
        """
        Create an SSL context for incoming mTLS connections.

        The context requires:
        - Client certificate validation against frozen CA (mutual)
        - TLS 1.2+ only
        - No fallback

        Args:
            server_cert_path: Path to the server certificate.
            server_key_path: Path to the server private key.

        Returns:
            ssl.SSLContext configured for mTLS server connections.

        Raises:
            RuntimeError: If not frozen.
        """
        if not self._frozen:
            raise RuntimeError(
                "TRANSPORT NOT FROZEN: Cannot create SSL context before freeze."
            )

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Enforce minimum TLS 1.2
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Load server certificate
        ctx.load_cert_chain(
            certfile=server_cert_path,
            keyfile=server_key_path,
        )

        # Load frozen CA for client certificate validation (mTLS)
        ctx.load_verify_locations(cadata=self._ca_cert_data.decode("utf-8"))

        # REQUIRE client certificate (mutual TLS — not optional)
        ctx.verify_mode = ssl.CERT_REQUIRED

        logger.info("[TransportSecurity] Server SSL context created (mTLS).")
        return ctx

    def validate_connection(self, ssl_socket):
        """
        Validate an established SSL connection.

        Checks:
            1. Peer certificate is present (mutual TLS)
            2. Certificate is not in revocation list
            3. Connection uses TLS 1.2+

        Args:
            ssl_socket: An ssl.SSLSocket object.

        Returns:
            tuple: (is_valid: bool, reason: str)
        """
        if not self._frozen:
            return False, "Transport security not frozen."

        # Check 1: Peer certificate must be present
        peer_cert = ssl_socket.getpeercert()
        if not peer_cert:
            logger.warning(
                "[TransportSecurity] CONNECTION REFUSED: No peer certificate. "
                "mTLS requires both parties to present certificates."
            )
            return False, "No peer certificate. mTLS required."

        # Check 2: Check revocation list
        serial = peer_cert.get("serialNumber", "")
        if serial in self._revocation_list:
            logger.warning(
                f"[TransportSecurity] CONNECTION REFUSED: Certificate "
                f"serial {serial} is in revocation list."
            )
            return False, f"Certificate serial {serial} is revoked."

        # Check 3: TLS version
        tls_version = ssl_socket.version()
        _TLS_VERSION_ORDER = {
            "SSLv2": 0, "SSLv3": 1, "TLSv1": 2,
            "TLSv1.1": 3, "TLSv1.2": 4, "TLSv1.3": 5,
        }
        if tls_version and _TLS_VERSION_ORDER.get(tls_version, -1) < _TLS_VERSION_ORDER["TLSv1.2"]:
            logger.warning(
                f"[TransportSecurity] CONNECTION REFUSED: "
                f"TLS version {tls_version} below minimum TLSv1.2."
            )
            return False, f"TLS version {tls_version} below minimum TLSv1.2."

        # Check 4: Certificate age (H-18)
        if self._max_cert_age_hours and peer_cert:
            not_before = peer_cert.get("notBefore")
            not_after = peer_cert.get("notAfter")
            if not_before and not_after:
                try:
                    import email.utils
                    cert_start = email.utils.parsedate_to_datetime(not_before).timestamp()
                    cert_lifetime_hours = (time.time() - cert_start) / 3600
                    if cert_lifetime_hours > self._max_cert_age_hours:
                        logger.warning(
                            f"[TransportSecurity] CONNECTION REFUSED: "
                            f"Certificate age {cert_lifetime_hours:.1f}h exceeds "
                            f"max {self._max_cert_age_hours}h."
                        )
                        return False, (
                            f"Certificate age {cert_lifetime_hours:.1f}h exceeds "
                            f"maximum allowed {self._max_cert_age_hours}h."
                        )
                except (ValueError, TypeError) as e:
                    logger.warning(
                        f"[TransportSecurity] Cannot parse cert dates: {e}"
                    )

        logger.debug(
            f"[TransportSecurity] Connection validated. "
            f"TLS: {tls_version}, Serial: {serial}"
        )
        return True, "Connection validated."

    def generate_channel_binding_token(self, ssl_socket):
        """
        Generate a TLS channel binding token for inclusion in
        MCP protocol messages.

        This prevents MITM attacks that terminate and re-establish
        TLS connections. The binding token is verified as part of
        the tool identity check.

        Args:
            ssl_socket: An ssl.SSLSocket object.

        Returns:
            str: SHA-256 hex digest of the channel binding data.

        Raises:
            RuntimeError: If not frozen.
        """
        if not self._frozen:
            raise RuntimeError("Transport security not frozen.")

        # Get the TLS channel binding data (tls-unique)
        # This is a value derived from the TLS handshake that is unique
        # to this specific TLS session. An attacker who terminates and
        # re-establishes the TLS connection will get a different value.
        try:
            cb_data = ssl_socket.get_channel_binding("tls-unique")
            if cb_data:
                token = hashlib.sha256(cb_data).hexdigest()
                return token
        except (ValueError, AttributeError):
            pass

        # Fallback: Fail — cert DER hash is not session-unique (H-19)
        logger.warning(
            "[TransportSecurity] tls-unique unavailable and no safe fallback. "
            "Channel binding token cannot be generated."
        )
        return None

    def verify_channel_binding(self, ssl_socket, expected_token):
        """
        Verify a channel binding token against the current connection.

        Args:
            ssl_socket: An ssl.SSLSocket object.
            expected_token: The expected channel binding token string.

        Returns:
            tuple: (is_valid: bool, reason: str)
        """
        if not self._frozen:
            return False, "Transport security not frozen."

        actual_token = self.generate_channel_binding_token(ssl_socket)
        if not actual_token:
            return False, "Cannot generate channel binding token."

        if hmac.compare_digest(actual_token, expected_token):
            return True, "Channel binding verified."
        else:
            logger.warning(
                "[TransportSecurity] CHANNEL BINDING MISMATCH: "
                "possible MITM attack detected."
            )
            return False, (
                "Channel binding mismatch. Possible man-in-the-middle attack."
            )

    def revoke_certificate(self, serial_number):
        """
        M-19: Add a certificate serial number to the revocation list at runtime.

        This allows post-freeze revocation without requiring a process restart.
        The revocation list is mutable by design — it's append-only (revocations
        can be added but never removed), which is the correct security posture.

        Args:
            serial_number: The certificate serial number to revoke.

        Returns:
            tuple: (success: bool, reason: str)
        """
        if not self._frozen:
            return False, "Cannot revoke certificates before freeze."
        if not serial_number or not isinstance(serial_number, str):
            return False, "Serial number must be a non-empty string."
        if serial_number in self._revocation_list:
            return True, f"Serial {serial_number} already revoked."

        self._revocation_list.add(serial_number)
        logger.warning(
            f"[TransportSecurity] CERTIFICATE REVOKED: serial={serial_number}. "
            f"Revocation list now has {len(self._revocation_list)} entries."
        )
        return True, f"Certificate serial {serial_number} has been revoked."

    def is_local_connection(self, connection_type):
        """
        Check if a connection is local (stdio) and does not need encryption.

        Args:
            connection_type: "stdio", "tcp", "http", "https", etc.

        Returns:
            bool: True if the connection is local and doesn't need mTLS.
        """
        if not isinstance(connection_type, str):
            # S-04: Fail-safe — non-string connection types are never local
            return False
        return connection_type.lower() in ("stdio", "pipe", "local")

    def enforce_policy(self, connection_type, ssl_socket=None):
        """
        Enforce the transport security policy.

        - Local (stdio): ALLOWED without encryption
        - Network without mTLS: CONNECTION REFUSED
        - Network with mTLS: validated

        Args:
            connection_type: "stdio", "tcp", "http", "https", etc.
            ssl_socket: SSL socket for network connections.

        Returns:
            tuple: (allowed: bool, reason: str)
        """
        # Local connections are allowed without encryption
        if self.is_local_connection(connection_type):
            return True, "Local connection. No encryption needed."

        # Network connections MUST have mTLS
        if not self._frozen:
            return False, (
                "CONNECTION REFUSED: Transport security not frozen. "
                "Cannot accept network connections."
            )

        if ssl_socket is None:
            return False, (
                "CONNECTION REFUSED: No SSL socket for network connection. "
                "mTLS is mandatory. No fallback to unencrypted."
            )

        # Validate the connection
        return self.validate_connection(ssl_socket)
