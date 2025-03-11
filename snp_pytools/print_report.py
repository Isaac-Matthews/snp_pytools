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

from .attestation_report import AttestationReport


def main():
    """
    main
    Description: Parse command-line arguments, read an attestation report file, and print its details
    Input: None (uses command-line arguments)
    Arguments:
        -f, --file: Path to the report file (default: report.bin)
        -d, --debug: Enable debug mode (flag)
    Output: None (prints attestation report details to console)
    Examples:
        python print_report.py -f report.bin
        python print_report.py -f report.bin --debug
    """
    parser = argparse.ArgumentParser(description="Print attestation report")
    parser.add_argument(
        "-f",
        "--file",
        default="report.bin",
        help="Path to the report file (default: report.bin)",
    )
    parser.add_argument(
        "-d", "--debug", action="store_true", default=False, help="Enable debug mode"
    )
    args = parser.parse_args()

    with open(args.file, "rb") as file:
        binary_data = file.read()

    report = AttestationReport.unpack(binary_data, debug=args.debug)
    report.print_details()


if __name__ == "__main__":
    main()
