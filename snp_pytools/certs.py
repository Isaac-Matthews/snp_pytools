# (C) Copyright 2024 Hewlett Packard Enterprise Development LP
# Author: Isaac Matthews <isaac@hpe.com>
# SPDX-License-Identifier: Apache-2.0

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import binascii
import os
from enum import Enum

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, utils
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import ObjectIdentifier


# There are taken from SEV-SNP Platform Attestation Using VirTEE/SEV
# https://www.amd.com/content/dam/amd/en/documents/developer/58217-epyc-9004-ug-platform-attestation-using-virtee-snp.pdf
class SnpOid(Enum):
    BootLoader = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.1")
    Tee = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.2")
    Snp = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.3")
    Ucode = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.8")
    HwId = ObjectIdentifier("1.3.6.1.4.1.3704.1.4")

    def __str__(self):
        return self.value.dotted_string


def load_certificates(cert_dir):
    """
    load_certificates
    Description: Load required certificates from a directory
    Input: cert_dir (str): Path to the directory containing certificates
    Output: dict: Dictionary of loaded certificates
    """
    certs = {}
    required_certs = ["ark", "ask", "vcek"]

    for filename in os.listdir(cert_dir):
        cert_type = next(
            (ct for ct in required_certs if filename.startswith(f"{ct}.")), None
        )
        if cert_type:
            if cert_type in certs:
                raise ValueError(
                    f"Multiple {cert_type.upper()} certificates found. There should be exactly one."
                )

            with open(os.path.join(cert_dir, filename), "rb") as cert_file:
                cert_data = cert_file.read()
                try:
                    # Try to load as DER
                    cert = x509.load_der_x509_certificate(cert_data)
                except ValueError:
                    try:
                        # If DER fails, try to load as PEM
                        cert = x509.load_pem_x509_certificate(cert_data)
                    except ValueError:
                        raise ValueError(
                            f"Unable to load certificate {filename}. It must be in DER or PEM format."
                        )

                certs[cert_type] = cert

    missing_certs = set(required_certs) - set(certs.keys())
    if missing_certs:
        raise ValueError(
            f"Missing required certificates: {', '.join(missing_certs).upper()}"
        )

    return certs


def print_all_certs(certs):
    """
    print_all_certs
    Description: Print fields of all certificates in the given dictionary
    Input: certs (dict): Dictionary of certificates
    Output: None
    """
    for cert_type, cert in certs.items():
        print(f"\n{cert_type.upper()} Certificate Fields:")
        print_certificate_fields(cert)


def get_public_key_algorithm(public_key):
    """
    get_public_key_algorithm
    Description: Determine the algorithm of the given public key
    Input: public_key: A public key object
    Output: str: Name of the public key algorithm
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"ECC (curve: {public_key.curve.name})"
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    elif isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448"
    else:
        return "Unknown"


def get_extension_value(cert, oid):
    """
    get_extension_value
    Description: Get the value of a specific extension from a certificate
    Inputs:
        cert: x509.Certificate object
        oid: ObjectIdentifier of the extension
    Output: Value of the extension (various types possible)
    """
    try:
        ext = cert.extensions.get_extension_for_oid(oid)
        value = ext.value
        if isinstance(value, x509.SubjectAlternativeName):
            return ", ".join(str(name) for name in value)
        elif isinstance(value, x509.KeyUsage):
            return repr(value)
        elif isinstance(value, x509.ExtendedKeyUsage):
            return ", ".join(str(usage) for usage in value)
        elif oid in [
            SnpOid.BootLoader.value,
            SnpOid.Tee.value,
            SnpOid.Snp.value,
            SnpOid.Ucode.value,
        ]:
            return int.from_bytes(value.value[2:], byteorder="big")
        elif oid == SnpOid.HwId.value:
            return binascii.hexlify(value.value).decode("ascii")
        else:
            return f"Unknown format: {binascii.hexlify(value.value).decode('ascii')}"
    except ExtensionNotFound:
        return "Not present"


def print_certificate_fields(cert):
    """
    print_certificate_fields
    Description: Print all relevant fields of a certificate
    Input: cert: x509.Certificate object
    Output: None
    """
    print(f"Subject: {cert.subject.rfc4514_string()}")
    print(f"Issuer: {cert.issuer.rfc4514_string()}")
    print(f"Version: {cert.version}")
    print(f"Serial Number: {cert.serial_number}")
    print(f"Not Valid Before: {cert.not_valid_before}")
    print(f"Not Valid After: {cert.not_valid_after}")
    print(
        f"Subject Alternative Names: {get_extension_value(cert, x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)}"
    )
    print(f"Key Usage: {get_extension_value(cert, x509.ExtensionOID.KEY_USAGE)}")
    print(
        f"Extended Key Usage: {get_extension_value(cert, x509.ExtensionOID.EXTENDED_KEY_USAGE)}"
    )
    print(f"Public Key Algorithm: {get_public_key_algorithm(cert.public_key())}")

    # Print SNP-specific extensions
    for snp_oid in SnpOid:
        value = get_extension_value(cert, snp_oid.value)
        if isinstance(value, int):
            print(f"{snp_oid.name}: {value}")
        elif isinstance(value, str):
            print(f"{snp_oid.name}: {value}")
        else:
            print(f"{snp_oid.name}: Unknown format")


def verify_certificate(cert, key):
    """
    verify_certificate
    Description: Verify a certificate's signature using a public key
    Inputs:
        cert: x509.Certificate object to verify
        key: Public key to use for verification
    Output: bool: True if verification succeeds, False otherwise
    """
    try:
        key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding=cert.signature_algorithm_parameters,
            algorithm=cert.signature_hash_algorithm,
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        raise ValueError(f"Error verifying certificate: {str(e)}")


def verify_report_components(report, cert, verbose=False):
    """
    verify_report_components
    Description: Verify components of an attestation report against a certificate
    Inputs:
        report: Attestation report object
        cert: x509.Certificate object (VCEK)
        verbose: Whether to print success messages
    Output: bool: True if all components match, False otherwise
    """
    # Check TCB components
    tcb_components = [
        ("BootLoader", SnpOid.BootLoader),
        ("TEE", SnpOid.Tee),
        ("SNP", SnpOid.Snp),
        ("Microcode", SnpOid.Ucode),
    ]

    for component_name, oid in tcb_components:
        cert_value = get_extension_value(cert, oid.value)
        report_value = getattr(report.reported_tcb, component_name.lower())

        if cert_value == report_value:
            if verbose:
                print(
                    f"Reported TCB {component_name} from certificate matches the attestation report."
                )
        else:
            print(
                f"Error: Reported TCB {component_name} mismatch. Certificate: {cert_value}, Report: {report_value}"
            )
            return False

    # Check Chip ID (Hardware ID in report)
    cert_hwid = get_extension_value(cert, SnpOid.HwId.value)
    report_hwid = report.chip_id.hex()

    if cert_hwid == report_hwid:
        if verbose:
            print("Chip ID from certificate matches the attestation report.")
    else:
        print(
            f"Error: Chip ID mismatch. Certificate: {cert_hwid}, Report: {report_hwid}"
        )
        return False

    return True


def verify_report(report, cert, verbose=False):
    """
    verify_report
    Description: Verify an attestation report against a VCEK certificate
    Inputs:
        report: Attestation report object
        cert: x509.Certificate object (VCEK)
        verbose: Whether to print success messages
    Output: bool: True if verification succeeds, False otherwise
    """
    if not verify_report_components(report, cert, verbose):
        print("Error: The attestation report values do not match the VCEK certificate.")
        return False
    elif verbose:
        print("Report components verified successfully against the VCEK certificate.")

    report_bytes = report.to_bytes()
    signed_bytes = report_bytes[0:672]  # Use the first 672 bytes (0x2A0)

    # digest = hashes.Hash(hashes.SHA384())
    # digest.update(signed_bytes)
    # hashed_info = digest.finalize()

    public_key = cert.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError(f"Unsupported public key type: {type(public_key)}")

    r = int.from_bytes(report.signature.get_trimmed_r(), "little")
    s = int.from_bytes(report.signature.get_trimmed_s(), "little")
    # print(f"R: {r}")
    # print(f"S: {s}")
    signature = utils.encode_dss_signature(r, s)
    # print(f"Encoded signature: {signature.hex()}")
    # print(f"Hashed info: {hashed_info.hex()}")

    try:
        public_key.verify(signature, signed_bytes, ec.ECDSA(hashes.SHA384()))
        if verbose:
            print("VCEK signed the Attestation Report!")
        return True
    except InvalidSignature as e:
        print(f"Error: Invalid signature. Details: {str(e)}")
        return False
