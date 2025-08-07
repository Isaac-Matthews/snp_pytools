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

import argparse
import os

from cryptography import x509

from .attestation_report import AttestationReport
from .certs import (
    check_certificate_against_crl,
    load_certificates,
    load_crl,
    print_all_certs,
    print_crl_fields,
    verify_certificate,
    verify_crl,
    verify_report,
)
from .fetch import CertFormat, Endorsement, ProcType, fetch_ca, fetch_crl, fetch_vcek


def verify_certificate_chain(certificates, verbose=False):
    """
    Verify the SEV-SNP certificate chain (ARK -> ASK -> VCEK).

    Args:
        certificates: Dictionary containing 'ark', 'ask', and 'vcek' certificates
        verbose: Whether to print verbose output

    Returns:
        bool: True if certificate chain is valid

    Raises:
        ValueError: If any certificate verification fails
    """
    # Check if the ARK certificate is self-signed
    ark_cert = certificates["ark"]
    if not verify_certificate(ark_cert, ark_cert.public_key()):
        raise ValueError("The ARK is not self-signed.")
    if verbose:
        print("The ARK is self-signed.")

    # Check that the ASK is signed by the ARK
    ask_cert = certificates["ask"]
    if not verify_certificate(ask_cert, ark_cert.public_key()):
        raise ValueError("The ASK is not signed by the ARK.")
    if verbose:
        print("The ASK is signed by the ARK.")

    # Check that the VCEK is signed by the ASK
    vcek_cert = certificates["vcek"]
    if not verify_certificate(vcek_cert, ask_cert.public_key()):
        raise ValueError("The VCEK is not signed by the ASK.")
    if verbose:
        print("The VCEK is signed by the ASK.")
        print("Certificate chain verified successfully.")

    return True


def verify_certificate_chain_with_crl(certificates, crl=None, verbose=False):
    """
    verify_certificate_chain_with_crl
    Description: Verify the SEV-SNP certificate chain including CRL checks
    Inputs:
        certificates: Dictionary containing 'ark', 'ask', and 'vcek' certificates
        crl: x509.CertificateRevocationList object (optional)
        verbose: Whether to print verbose output
    Output: bool: True if certificate chain is valid and no certificates are revoked
    """
    # Verify the basic certificate chain
    verify_certificate_chain(certificates, verbose)

    # If CRL is provided, check each certificate against it
    if crl is not None:
        # Check that the CRL is signed by the ARK
        ark_cert = certificates["ark"]
        if not verify_crl(crl, ark_cert.public_key()):
            raise ValueError("The CRL is not signed by the ARK.")
        if verbose:
            print("The CRL is signed by the ARK.")
        if verbose:
            print("\nChecking certificates against CRL...")

        # Check ASK certificate against CRL
        ask_cert = certificates["ask"]
        if not check_certificate_against_crl(ask_cert, crl, verbose):
            raise ValueError("ASK certificate is revoked according to CRL.")
        # Check VCEK certificate against CRL
        vcek_cert = certificates["vcek"]
        if not check_certificate_against_crl(vcek_cert, crl, verbose):
            raise ValueError("VCEK certificate is revoked according to CRL.")

        if verbose:
            print("None of the certificates have been revoked.")
    else:
        if verbose:
            print("No CRL provided")
        return False

    return True


def verify_attestation(
    report_bytes,
    certificates_path=None,
    certificates=None,
    crl=None,
    debug=False,
    verbose=False,
    processor_model="genoa",
):
    """
    Verify an SEV-SNP attestation report against certificate chain.

    Args:
        report_bytes: Binary attestation report data
        certificates_path: Path to certificates directory (if certificates not provided)
        certificates: Dictionary of certificates (if already loaded)
        crl: x509.CertificateRevocationList (if already loaded)
        debug: Enable debug mode
        verbose: Print verbose information

    Returns:
        tuple: (report object, certificates dict, report data hex string)

    Raises:
        ValueError: For verification failures
        FileNotFoundError: If certificates cannot be loaded
    """
    report = AttestationReport.unpack(report_bytes, debug=debug)
    if verbose:
        report.print_details()

    # Load certificates if not provided
    if certificates is None:
        if certificates_path is None:
            certificates_path = "ca"

        # Create certificates directory if it doesn't exist
        if not os.path.exists(certificates_path):
            if verbose:
                print(f"Creating certificates directory: {certificates_path}")
            os.makedirs(certificates_path, exist_ok=True)

        # Check if certificates exist, if not fetch them
        try:
            certificates = load_certificates(certificates_path)
        except (ValueError, FileNotFoundError):
            if verbose:
                print(f"Certificates not found, fetching from AMD KDS...")

            # Convert processor model to enum
            proc_type = ProcType[processor_model.upper()]

            # Fetch ARK and ASK certificates
            fetch_ca(CertFormat.PEM, proc_type, certificates_path, Endorsement.VCEK)

            # Create temporary file path for the attestation report
            import tempfile

            with tempfile.NamedTemporaryFile(delete=False) as temp:
                temp.write(report_bytes)
                temp_path = temp.name

            # Fetch VCEK certificate using the report
            fetch_vcek(CertFormat.PEM, proc_type, certificates_path, temp_path)

            # Remove temporary file
            os.unlink(temp_path)

            # Now try loading certificates again
            certificates = load_certificates(certificates_path)
            if verbose:
                print("Certificates successfully fetched and loaded.")

    # Load CRL if not provided
    if crl is None:
        try:
            crl = load_crl(certificates_path)
        except (ValueError, FileNotFoundError):
            if verbose:
                print(f"CRL not found, fetching from AMD KDS...")

            # Convert processor model to enum
            proc_type = ProcType[processor_model.upper()]

            # Fetch CRL
            fetch_crl(CertFormat.PEM, proc_type, certificates_path, Endorsement.VCEK)

            # Now try loading CRL again
            crl = load_crl(certificates_path)
            if verbose:
                print("CRL successfully fetched and loaded.")

    if verbose:
        print("\nLoaded Certificates:")
        print_all_certs(certificates)
        print("\n================================================")

    if verbose:
        print("\nLoaded CRL:")
        print_crl_fields(crl)
        print("\n================================================")

    verify_attestation_report(
        report=report,
        certificates=certificates,
        crl=crl,
        verbose=verbose,
    )
    return report, certificates, report.report_data.hex()


def verify_attestation_report(
    report: AttestationReport,
    certificates: dict,
    crl: x509.CertificateRevocationList,
    verbose: bool = False,
) -> bool:
    """
    Verify an SEV-SNP attestation report against a certificate chain and CRL.
    """
    if verbose:
        print("\nVerifying certificate chain")
    # Verify certificate chain
    verify_certificate_chain_with_crl(certificates, crl, verbose)

    # Check that the report is signed by the VCEK
    if verbose:
        print("\n================================================")
        print("\nVerifying attestation report.")

    vcek_cert = certificates["vcek"]
    if not verify_report(report, vcek_cert, verbose):
        raise ValueError(
            "The attestation report failed verification against the VCEK certificate."
        )

    if verbose:
        print("Report verified successfully against the VCEK certificate.")
        print("\n================================================")
        print("\nAll checks passed successfully.")
    return True


def main():
    """
    main
    Description: Parse command-line arguments, load and verify the attestation report and certificate chain
    Input: None (uses command-line arguments)
    Arguments:
        -f, --file: Path to the report file (default: report.bin)
        -d, --debug: Enable debug mode (flag, default: False)
        -v, --verbose: Enable verbose mode (flag, default: False)
        -c, --certs: Path to the certs directory (default: ca)
        -r, --reportdata: Print report data at the end of successful verification (flag, default: False)
        -p, --processor: Processor model for certificate fetching, only used if certs are not provided (choices: milan, genoa, bergamo, siena; default: genoa)
    Output: None (prints verification results to console and exits with status code)
    Examples:
        python verify.py
        python verify.py -f custom_report.bin -c /path/to/certs
        python verify.py -f custom_report.bin -c /path/to/certs --verbose
    """
    parser = argparse.ArgumentParser(description="Verify attestation report")
    parser.add_argument(
        "-f",
        "--file",
        default="report.bin",
        help="Path to the report file (default: report.bin)",
    )
    parser.add_argument(
        "-d", "--debug", action="store_true", default=False, help="Enable debug mode"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose mode",
    )
    parser.add_argument(
        "-c", "--certs", default="ca", help="Path to the certs directory (default: ca)"
    )
    parser.add_argument(
        "-r",
        "--reportdata",
        action="store_true",
        default=False,
        help="Print report data at the end of successful verification",
    )
    parser.add_argument(
        "-p",
        "--processor",
        default="genoa",
        choices=["milan", "genoa", "bergamo", "siena"],
        help="Processor model for certificate fetching (default: genoa)",
    )
    args = parser.parse_args()

    # If debug mode is on, automatically enable verbose mode
    if args.debug:
        args.verbose = True

    with open(args.file, "rb") as file:
        report_bytes = file.read()

    try:
        _, _, report_data = verify_attestation(
            report_bytes=report_bytes,
            certificates_path=args.certs,
            debug=args.debug,
            verbose=args.verbose,
            processor_model=args.processor,
        )

        if args.reportdata:
            print("\n\n")
            print(report_data)
        return 0  # Success exit code
    except (ValueError, FileNotFoundError) as e:
        print(f"Verification error: {e}")
        return 1  # Error exit code


if __name__ == "__main__":
    main()
