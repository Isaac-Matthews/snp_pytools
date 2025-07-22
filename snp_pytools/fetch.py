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
import enum
import os

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .attestation_report import AttestationReport

# Constants for AMD Key Distribution Service (KDS)
KDS_CERT_SITE = "https://kdsintf.amd.com"
KDS_VERSION = "v1"
KDS_CERT_CHAIN = "cert_chain"
KDS_CRL = "crl"


# Enum classes for various certificate and processor types
class Endorsement(enum.Enum):
    VCEK = "VCEK"
    VLEK = "VLEK"


class ProcType(enum.Enum):
    MILAN = "Milan"
    GENOA = "Genoa"
    BERGAMO = "Bergamo"
    SIENA = "Siena"

    def to_kds_url(self):
        """
        to_kds_url
        Description: Convert processor type to KDS URL format
        Input: self (ProcType)
        Output: str (URL-friendly processor name)
        """
        if self in [ProcType.GENOA, ProcType.SIENA, ProcType.BERGAMO]:
            return ProcType.GENOA.value
        return self.value


class CertFormat(enum.Enum):
    PEM = "pem"
    DER = "der"


def create_retry_session(
    retries=5, backoff_factor=0.1, status_forcelist=(500, 502, 503, 504), timeout=5
):
    """
    create_retry_session
    Description: Create a requests session with retry logic
    Inputs:
        - retries: int (number of retries)
        - backoff_factor: float (backoff factor for retries)
        - status_forcelist: tuple (HTTP status codes to retry on)
        - timeout: int (default timeout for requests)
    Output: requests.Session object with retry logic
    """
    session = requests.Session()
    retries = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.timeout = timeout
    return session


def request_ca_kds(processor_model: ProcType, endorser: Endorsement):
    """
    request_ca_kds
    Description: Fetch CA certificates from AMD KDS
    Inputs:
        - processor_model: ProcType
        - endorser: Endorsement
    Output: List of x509.Certificate objects
    """
    url = f"{KDS_CERT_SITE}/{endorser.value.lower()}/{KDS_VERSION}/{processor_model.to_kds_url()}/{KDS_CERT_CHAIN}"
    print(f"Fetching CA from {url}")
    session = create_retry_session()
    response = session.get(url, timeout=session.timeout)

    if response.status_code == 200:
        certs = x509.load_pem_x509_certificates(response.content)
        return certs
    else:
        raise Exception(f"Unable to fetch certificates: {response.status_code}")


def write_cert(
    certs_dir, cert_type, cert, cert_format: CertFormat, endorser: Endorsement
):
    """
    write_cert
    Description: Write a certificate to a file
    Inputs:
        - certs_dir: str (directory to save the certificate)
        - cert_type: str (type of certificate, e.g., "ARK", "ASK")
        - cert: x509.Certificate
        - cert_format: CertFormat
        - endorser: Endorsement
    Output: None (writes certificate to file)
    """
    if not os.path.exists(certs_dir):
        os.makedirs(certs_dir)

    filename = f"{cert_type.lower()}.{cert_format.value}"
    filepath = os.path.join(certs_dir, filename)

    if cert_format == CertFormat.PEM:
        with open(filepath, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    elif cert_format == CertFormat.DER:
        with open(filepath, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.DER))


def fetch_ca(
    encoding: CertFormat,
    processor_model: ProcType,
    certs_dir: str,
    endorser: Endorsement,
):
    """
    fetch_ca
    Description: Fetch and save CA certificates (ARK and ASK)
    Inputs:
        - encoding: CertFormat
        - processor_model: ProcType
        - certs_dir: str (directory to save certificates)
        - endorser: Endorsement
    Output: None (saves certificates to files)
    """
    certificates = request_ca_kds(processor_model, endorser)

    ark_cert = certificates[1]
    ask_cert = certificates[0]

    write_cert(certs_dir, "ARK", ark_cert, encoding, endorser)
    write_cert(certs_dir, "ASK", ask_cert, encoding, endorser)


def request_vcek_kds(processor_model: ProcType, att_report_path: str):
    """
    request_vcek_kds
    Description: Fetch VCEK certificate from AMD KDS
    Inputs:
        - processor_model: ProcType
        - att_report_path: str (path to attestation report file)
    Output: x509.Certificate
    """
    with open(att_report_path, "rb") as file:
        binary_data = file.read()

    report = AttestationReport.unpack(binary_data)

    hw_id = report.chip_id.hex()
    url = (
        f"{KDS_CERT_SITE}/vcek/{KDS_VERSION}/{processor_model.to_kds_url()}/"
        f"{hw_id}?blSPL={report.reported_tcb.bootloader:02}&"
        f"teeSPL={report.reported_tcb.tee:02}&"
        f"snpSPL={report.reported_tcb.snp:02}&"
        f"ucodeSPL={report.reported_tcb.microcode:02}"
    )

    print(f"Fetching VCEK from {url}")
    session = create_retry_session()
    response = session.get(url, timeout=session.timeout)

    if response.status_code == 200:
        try:
            # Try to load as PEM
            cert = x509.load_pem_x509_certificate(response.content)
        except ValueError:
            try:
                # If PEM fails, try to load as DER
                cert = x509.load_der_x509_certificate(response.content)
            except ValueError:
                raise ValueError(
                    "Unable to load certificate. It must be in DER or PEM format."
                )
        return cert
    else:
        raise Exception(f"Unable to fetch VCEK from URL: {response.status_code}")


def fetch_vcek(
    encoding: CertFormat,
    processor_model: ProcType,
    certs_dir: str,
    att_report_path: str,
):
    """
    fetch_vcek
    Description: Fetch and save VCEK certificate
    Inputs:
        - encoding: CertFormat
        - processor_model: ProcType
        - certs_dir: str (directory to save certificate)
        - att_report_path: str (path to attestation report file)
    Output: None (saves VCEK certificate to file)
    """
    vcek = request_vcek_kds(processor_model, att_report_path)
    write_cert(certs_dir, "VCEK", vcek, encoding, Endorsement.VCEK)


def request_crl_kds(processor_model: ProcType, endorser: Endorsement):
    """
    request_crl_kds
    Description: Fetch CRL from AMD KDS
    Inputs:
        - processor_model: ProcType
        - endorser: Endorsement
    Output: List of x509.Certificate objects
    """
    url = f"{KDS_CERT_SITE}/{endorser.value.lower()}/{KDS_VERSION}/{processor_model.to_kds_url()}/{KDS_CRL}"
    print(f"Fetching CRL from {url}")
    session = create_retry_session()
    response = session.get(url, timeout=session.timeout)

    if response.status_code == 200:
        crl = x509.load_der_x509_crl(response.content)
        return crl
    else:
        raise Exception(f"Unable to fetch certificates: {response.status_code}")


def fetch_crl(
    encoding: CertFormat,
    processor_model: ProcType,
    certs_dir: str,
    endorser: Endorsement,
):
    """
    fetch_crl
    Description: Fetch and save CRL
    Inputs:
        - encoding: CertFormat
        - processor_model: ProcType
        - certs_dir: str (directory to save CRL)
        - endorser: Endorsement
    Output: None (saves CRL to file)
    """
    crl = request_crl_kds(processor_model, endorser)
    write_cert(certs_dir, "CRL", crl, encoding, endorser)


def main():
    """
    main
    Description: Parse command-line arguments and execute appropriate certificate fetching function
    Input: None (uses command-line arguments)
    Arguments:
        -e, --encoding: Certificate encoding (choices: pem, der; default: pem)
        -p, --processor: Processor model (choices: milan, genoa, bergamo, siena; default: genoa)
        -d, --dir: Directory to save certificates (default: current directory)
        ca: Subcommand to fetch certificate authority (ARK & ASK)
            --endorser: Endorsement type for CA (choices: vcek, vlek; default: vcek)
        crl: Subcommand to fetch CRL
            --endorser: Endorsement type for CRL (choices: vcek, vlek; default: vcek)
        vcek: Subcommand to fetch VCEK
            -r, --report: Path to the attestation report (required for VCEK)
    Output: None (fetches and saves certificates based on user input)
    Examples:
        python fetch.py ca
        python fetch.py ca -p milan
        python fetch.py ca -p genoa -e der -d /path/to/certs
        python fetch.py ca -p bergamo -e der -d /path/to/certs --endorser vlek
        python fetch.py crl -p genoa -d /path/to/certs
        python fetch.py vcek -p siena -r report.bin
        python fetch.py vcek -r report.bin
    """
    parser = argparse.ArgumentParser(description="Fetch AMD certificates")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Common arguments
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument(
        "-e",
        "--encoding",
        type=str,
        choices=["pem", "der"],
        default="pem",
        help="Certificate encoding (default: pem)",
    )
    common_parser.add_argument(
        "-p",
        "--processor",
        type=str,
        choices=["milan", "genoa", "bergamo", "siena"],
        default="genoa",
        help="Processor model",
    )
    common_parser.add_argument(
        "-d",
        "--dir",
        type=str,
        default=".",
        help="Directory to save certificates (default: current directory)",
    )

    # CA subcommand
    ca_parser = subparsers.add_parser(
        "ca",
        parents=[common_parser],
        help="Fetch the certificate authority (ARK & ASK) from the KDS",
    )
    ca_parser.add_argument(
        "--endorser",
        type=str,
        choices=["vcek", "vlek"],
        default="vcek",
        help="Endorsement type (default: vcek)",
    )

    # CRL subcommand
    crl_parser = subparsers.add_parser(
        "crl",
        parents=[common_parser],
        help="Fetch the CRL from the KDS",
    )
    crl_parser.add_argument(
        "--endorser",
        type=str,
        choices=["vcek", "vlek"],
        default="vcek",
        help="Endorsement type (default: vcek)",
    )

    # VCEK subcommand
    vcek_parser = subparsers.add_parser(
        "vcek", parents=[common_parser], help="Fetch the VCEK from the KDS"
    )
    vcek_parser.add_argument(
        "-r", "--report", type=str, required=True, help="Path to the attestation report"
    )

    args = parser.parse_args()

    # Convert string arguments to enum types
    encoding = CertFormat[args.encoding.upper()]
    processor_model = ProcType[args.processor.upper()]

    if args.command == "ca":
        endorser = Endorsement[args.endorser.upper()]
        fetch_ca(encoding, processor_model, args.dir, endorser)
    elif args.command == "crl":
        endorser = Endorsement[args.endorser.upper()]
        fetch_crl(encoding, processor_model, args.dir, endorser)
    elif args.command == "vcek":
        fetch_vcek(encoding, processor_model, args.dir, args.report)


if __name__ == "__main__":
    main()
