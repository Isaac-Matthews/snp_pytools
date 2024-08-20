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

from attestation_report import AttestationReport
from certs import load_certificates, print_all_certs, verify_certificate, verify_report


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
    args = parser.parse_args()

    # If debug mode is on, automatically enable verbose mode
    if args.debug:
        args.verbose = True

    with open(args.file, "rb") as file:
        binary_data = file.read()

    report = AttestationReport.unpack(binary_data, debug=args.debug)
    if args.verbose:
        report.print_details()

    certificates = load_certificates(args.certs)

    if args.verbose:
        print("\nLoaded Certificates:")
        print_all_certs(certificates)

    print("\n================================================")
    print("\nVerifying certificate chain.")
    # Check if the ARK certificate is self-signed
    ark_cert = certificates["ark"]
    if verify_certificate(ark_cert, ark_cert.public_key()):
        print("The ARK is self-signed.")
    else:
        print("Error: The ARK is not self-signed.")
        exit(1)

    # Check that the ASK is signed by the ARK
    ask_cert = certificates["ask"]
    if verify_certificate(ask_cert, ark_cert.public_key()):
        print("The ASK is signed by the ARK.")
    else:
        print("Error: The ASK is not signed by the ARK.")
        exit(1)

    # Check that the VCEK is signed by the ASK
    vcek_cert = certificates["vcek"]
    if verify_certificate(vcek_cert, ask_cert.public_key()):
        print("The VCEK is signed by the ASK.")
    else:
        print("Error: The VCEK is not signed by the ASK.")
        exit(1)
    print("Certificate chain verified successfully.")
    print("\n================================================")

    # Check that the report is signed by the VCEK and the report values match the VCEK certificate
    print("\nVerifying attestation report.")
    if verify_report(report, vcek_cert):
        print("Report verified successfully against the VCEK certificate.")
    else:
        print(
            "Error: The attestation report failed verification against the VCEK certificate."
        )
        exit(1)

    print("\n================================================")
    print("\nAll checks passed successfully.")
    if args.reportdata:
        print("\n\n")
        print(report.report_data.hex())


if __name__ == "__main__":
    main()
