# snp_pytools

snp_pytools is a Python-based tool for verifying AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging) attestation reports. This project provides functionality to parse, print, and verify attestation reports against a chain of certificates, and fetch certificates from the AMD Key Distribution Service (KDS).

## Project Structure

The project consists of the following main components:

1. `attestation_report.py`: Defines the `AttestationReport` class for parsing and representing attestation reports.
2. `certs.py`: Handles certificate loading, verification, and printing.
3. `guest_policy.py`: Defines the `GuestPolicy` class for managing guest policy information.
4. `platform_info.py`: Defines the `PlatformInfo` class for managing platform information.
5. `signature.py`: Defines the `Signature` class for handling cryptographic signatures.
6. `print_report.py`: Command-line tool for printing attestation report details.
7. `verify.py`: Main verification script that checks the attestation report against the certificate chain.
8. `fetch.py`: Tool for fetching certificates (ARK, ASK, VCEK) from the AMD Key Distribution Service.

## Usage

### Printing an Attestation Report

To print the details of an attestation report:

```
python print_report.py -f path/to/report.bin [-d]
```
or if installed with pip use `snp-print ...`.

- `-f` or `--file`: Path to the attestation report file (default: report.bin)
- `-d` or `--debug`: Enable debug mode for additional output

### Verifying an Attestation Report

To verify an attestation report against a certificate chain:

```
python verify.py -f path/to/report.bin -c path/to/certs/directory [-d] [-v]
```
or if installed with pip use `snp-verify ...`.

- `-f` or `--file`: Path to the attestation report file (default: report.bin)
- `-c` or `--certs`: Path to the directory containing certificates (default: ca)
- `-d` or `--debug`: Enable debug mode for additional output (automatically enables verbose mode)
- `-v` or `--verbose`: Enable verbose mode for detailed information
- `-r` or `--reportdata`: Print report data at the end of successful verification
- `-p` or `--processor`: Processor model (e.g., milan, genoa) used only if no certificates found (default: genoa)

### Fetching Certificates

To fetch certificates from the AMD Key Distribution Service:

```
python fetch.py ca -p PROCESSOR -e ENCODING -d DIRECTORY [--endorser {vcek,vlek}]
python fetch.py vcek -p PROCESSOR -e ENCODING -d DIRECTORY -r REPORT_PATH
```
or if installed with pip use `snp-fetch ...`.

- `ca`: Fetch ARK and ASK certificates
- `vcek`: Fetch VCEK certificate
- `-p` or `--processor`: Processor model (e.g., milan, genoa) (default: genoa)
- `-e` or `--encoding`: Certificate encoding format (PEM or DER)
- `-d` or `--directory`: Directory to save the fetched certificates
- `--endorser`: Endorser type (vcek or vlek) for fetching VCEK or VLEK certificates
- `-r` or `--report`: Path to the attestation report file (required for fetching VCEK)

## Requirements

- Python 3.6+
- cryptography library >= 39.0.0
- requests library

## Installation

1. Clone the repository
2. Move into root directory and install
   ```
   pip install .
   ```

## Uninstallation
1. Run pip uninstall
   ```
   pip uninstall snp_pytools
   ```

## Acknowledgments

This project is based on the AMD SEV-SNP specification and related documentation.
All the specifications used can be found here: [https://www.amd.com/en/developer/sev.html](https://www.amd.com/en/developer/sev.html)

The snpguest rust tool that can be used to generate the attestation report, and that models the verification process, can be found here: [https://github.com/virtee/snpguest/tree/main](https://github.com/virtee/snpguest/tree/main)