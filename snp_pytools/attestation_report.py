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

import struct
from dataclasses import dataclass, fields

from .guest_policy import GuestPolicy
from .platform_info import PlatformInfo
from .signature import Signature
from .snp_logging import get_logger

logger = get_logger(__name__)


@dataclass
class TcbVersion:
    """
    TcbVersion
    Description: Represents the Trusted Computing Base (TCB) version information
    """

    bootloader: int
    tee: int
    _reserved: bytes
    snp: int
    microcode: int


@dataclass
class Cpuid:
    """
    Cpuid
    Description: Represents CPUID information from the attestation report
    """

    family_id: bytes  # CPUID_FAM_ID - Combined Extended Family ID and Family ID
    model_id: bytes  # CPUID_MOD_ID - Model (combined Extended Model and Model fields)
    stepping: bytes  # CPUID_STEP - Stepping
    _reserved: bytes  # Reserved


@dataclass
class AttestationReport:
    """
    AttestationReport
    Description: Represents an AMD SEV-SNP Attestation Report
    """

    version: int
    guest_svn: int
    policy: GuestPolicy
    family_id: bytes
    image_id: bytes
    vmpl: int
    signature_algo: int
    current_tcb: TcbVersion
    platform_info: PlatformInfo
    _author_key_en: int
    _reserved_0: int
    report_data: bytes
    measurement: bytes
    host_data: bytes
    id_key_digest: bytes
    author_key_digest: bytes
    report_id: bytes
    report_id_ma: bytes
    reported_tcb: TcbVersion
    cpuid: Cpuid
    chip_id: bytes
    committed_tcb: TcbVersion
    current_build: int
    current_minor: int
    current_major: int
    _reserved_1: int
    committed_build: int
    committed_minor: int
    committed_major: int
    _reserved_2: int
    launch_tcb: TcbVersion
    _reserved_3: bytes
    signature: Signature

    format_string = (
        "<"
        "I"  # version: u32
        "I"  # guest_svn: u32
        "Q"  # policy: GuestPolicy (u64)
        "16s"  # family_id: [u8; 16]
        "16s"  # image_id: [u8; 16]
        "I"  # vmpl: u32
        "I"  # signature_algo: u32
        "BB4sBB"  # current_tcb: TcbVersion (bootloader: u8, tee: u8, reserved: [u8; 4], snp: u8, microcode: u8)
        "Q"  # platform_info: PlatformInfo (u64)
        "I"  # _author_key_en: u32
        "I"  # _reserved_0: u32
        "64s"  # report_data: [u8; 64]
        "48s"  # measurement: [u8; 48]
        "32s"  # host_data: [u8; 32]
        "48s"  # id_key_digest: [u8; 48]
        "48s"  # author_key_digest: [u8; 48]
        "32s"  # report_id: [u8; 32]
        "32s"  # report_id_ma: [u8; 32]
        "BB4sBB"  # reported_tcb: TcbVersion
        "ccc21s"  # cpuid: Cpuid (cpuid_fam_id: u8, cpuid_mod_id: u8, cpuid_step: u8, reserved: [u8; 21])
        "64s"  # chip_id: [u8; 64]
        "BB4sBB"  # committed_tcb: TcbVersion
        "B"  # current_build: u8
        "B"  # current_minor: u8
        "B"  # current_major: u8
        "B"  # _reserved_1: u8
        "B"  # committed_build: u8
        "B"  # committed_minor: u8
        "B"  # committed_major: u8
        "B"  # _reserved_2: u8
        "BB4sBB"  # launch_tcb: TcbVersion
        "168s"  # _reserved_3: [u8; 168]
        "512s"  # signature: Signature
    )

    def to_bytes(self) -> bytes:
        """
        to_bytes
        Description: Convert the AttestationReport to its binary representation
        Input: None
        Output: bytes: Binary representation of the AttestationReport
        """
        return struct.pack(
            self.format_string,
            self.version,
            self.guest_svn,
            self.policy._value,
            self.family_id,
            self.image_id,
            self.vmpl,
            self.signature_algo,
            self.current_tcb.bootloader,
            self.current_tcb.tee,
            self.current_tcb._reserved,
            self.current_tcb.snp,
            self.current_tcb.microcode,
            self.platform_info._value,
            self._author_key_en,
            self._reserved_0,
            self.report_data,
            self.measurement,
            self.host_data,
            self.id_key_digest,
            self.author_key_digest,
            self.report_id,
            self.report_id_ma,
            self.reported_tcb.bootloader,
            self.reported_tcb.tee,
            self.reported_tcb._reserved,
            self.reported_tcb.snp,
            self.reported_tcb.microcode,
            self.cpuid.family_id,
            self.cpuid.model_id,
            self.cpuid.stepping,
            self.cpuid._reserved,
            self.chip_id,
            self.committed_tcb.bootloader,
            self.committed_tcb.tee,
            self.committed_tcb._reserved,
            self.committed_tcb.snp,
            self.committed_tcb.microcode,
            self.current_build,
            self.current_minor,
            self.current_major,
            self._reserved_1,
            self.committed_build,
            self.committed_minor,
            self.committed_major,
            self._reserved_2,
            self.launch_tcb.bootloader,
            self.launch_tcb.tee,
            self.launch_tcb._reserved,
            self.launch_tcb.snp,
            self.launch_tcb.microcode,
            self._reserved_3,
            self.signature.to_bytes(),
        )

    @classmethod
    def unpack(cls, binary_data):
        """
        unpack
        Description: Create an AttestationReport instance from binary data
        Inputs:
            binary_data: bytes: Binary representation of an AttestationReport
        Output: AttestationReport: An instance of AttestationReport
        """
        logger.debug(f"Unpacking attestation report from {len(binary_data)} bytes")

        # Unpack the binary data using the format string
        unpacked = struct.unpack(cls.format_string, binary_data)
        logger.debug(f"Successfully unpacked {len(unpacked)} fields")

        # Log unpacked values for debugging
        field_names = [f.name for f in fields(cls)]
        for i, (value, field_name) in enumerate(zip(unpacked, field_names)):
            logger.debug(f"Index {i}: {value} - {field_name}")
            if isinstance(value, bytes):
                logger.debug(f"  Hex: {value.hex()}")

        # Create and return an AttestationReport instance
        report = cls(
            version=unpacked[0],
            guest_svn=unpacked[1],
            policy=GuestPolicy(unpacked[2]),
            family_id=unpacked[3],
            image_id=unpacked[4],
            vmpl=unpacked[5],
            signature_algo=unpacked[6],
            current_tcb=TcbVersion(
                unpacked[7], unpacked[8], unpacked[9], unpacked[10], unpacked[11]
            ),
            platform_info=PlatformInfo(unpacked[12]),
            _author_key_en=unpacked[13],
            _reserved_0=unpacked[14],
            report_data=unpacked[15],
            measurement=unpacked[16],
            host_data=unpacked[17],
            id_key_digest=unpacked[18],
            author_key_digest=unpacked[19],
            report_id=unpacked[20],
            report_id_ma=unpacked[21],
            reported_tcb=TcbVersion(
                unpacked[22], unpacked[23], unpacked[24], unpacked[25], unpacked[26]
            ),
            cpuid=Cpuid(unpacked[27], unpacked[28], unpacked[29], unpacked[30]),
            chip_id=unpacked[31],
            committed_tcb=TcbVersion(
                unpacked[32], unpacked[33], unpacked[34], unpacked[35], unpacked[36]
            ),
            current_build=unpacked[37],
            current_minor=unpacked[38],
            current_major=unpacked[39],
            _reserved_1=unpacked[40],
            committed_build=unpacked[41],
            committed_minor=unpacked[42],
            committed_major=unpacked[43],
            _reserved_2=unpacked[44],
            launch_tcb=TcbVersion(
                unpacked[45], unpacked[46], unpacked[47], unpacked[48], unpacked[49]
            ),
            _reserved_3=unpacked[50],
            signature=Signature.from_bytes(unpacked[51]),
        )

        logger.info(
            f"Successfully parsed attestation report (version: {report.version}, measurement: {report.measurement.hex()})"
        )
        return report

    def log_details(self):
        """
        log_details
        Description: Log a detailed representation of the AttestationReport
        Input: None
        Output: None (logs to logger)
        """
        logger.info("Attestation Report Details:")
        logger.info(f"Version:                     {self.version}")
        logger.info(f"Guest SVN:                   {self.guest_svn}")

        logger.info("Guest Policy:")
        logger.info(f"  ABI Minor:                 {self.policy.abi_minor}")
        logger.info(f"  ABI Major:                 {self.policy.abi_major}")
        logger.info(f"  SMT Allowed:               {self.policy.smt_allowed}")
        logger.info(f"  Migrate MA Allowed:        {self.policy.migrate_ma_allowed}")
        logger.info(f"  Debug Allowed:             {self.policy.debug_allowed}")
        logger.info(f"  Single Socket Required:    {self.policy.single_socket_required}")
        logger.info(f"  CXL Allowed:               {self.policy.cxl_allowed}")
        logger.info(f"  MEM AES 256 XTS:           {self.policy.mem_aes_256_xts}")
        logger.info(f"  RAPL Disabled:             {self.policy.rapl_dis}")
        logger.info(f"  Ciphertext Hiding:         {self.policy.ciphertext_hiding}")
        logger.info(f"  Page Swap Disabled:        {self.policy.page_swap_disable}")

        logger.info(f"Family ID:                   {self.family_id.hex()}")
        logger.info(f"Image ID:                    {self.image_id.hex()}")
        logger.info(f"VMPL:                        {self.vmpl}")
        logger.info(f"Signature Algorithm:         {self.signature_algo}")

        logger.info("Current TCB:")
        logger.info(f"  Bootloader:                {self.current_tcb.bootloader}")
        logger.info(f"  TEE:                       {self.current_tcb.tee}")
        logger.info(f"  Reserved:                  {self.current_tcb._reserved.hex()}")
        logger.info(f"  SNP:                       {self.current_tcb.snp}")
        logger.info(f"  Microcode:                 {self.current_tcb.microcode}")

        logger.info("Platform Info:")
        logger.info(f"  SMT Enabled:               {self.platform_info.smt_enabled}")
        logger.info(f"  TSME Enabled:              {self.platform_info.tsme_enabled}")
        logger.info(f"  ECC Enabled:               {self.platform_info.ecc_enabled}")
        logger.info(f"  RAPL Disabled:             {self.platform_info.rapl_disabled}")
        logger.info(
            f"  Ciphertext Hiding Enabled: {self.platform_info.ciphertext_hiding_enabled}"
        )
        logger.info(f"  Alias Check Complete:      {self.platform_info.alias_check_complete}")
        logger.info(f"  TIO Enabled:               {self.platform_info.tio_enabled}")

        logger.info(f"Author Key Enabled:          {self._author_key_en}")
        logger.info(f"Report Data:                 {self.report_data.hex()}")
        logger.info(f"Measurement:                 {self.measurement.hex()}")
        logger.info(f"Host Data:                   {self.host_data.hex()}")
        logger.info(f"ID Key Digest:               {self.id_key_digest.hex()}")
        logger.info(f"Author Key Digest:           {self.author_key_digest.hex()}")
        logger.info(f"Report ID:                   {self.report_id.hex()}")
        logger.info(f"Report ID Migration Agent:   {self.report_id_ma.hex()}")

        logger.info("Reported TCB:")
        logger.info(f"  Bootloader:                {self.reported_tcb.bootloader}")
        logger.info(f"  TEE:                       {self.reported_tcb.tee}")
        logger.info(f"  Reserved:                  {self.reported_tcb._reserved.hex()}")
        logger.info(f"  SNP:                       {self.reported_tcb.snp}")
        logger.info(f"  Microcode:                 {self.reported_tcb.microcode}")

        logger.info(f"CPUID:")
        logger.info(f"  Family ID:                 {self.cpuid.family_id.hex()}")
        logger.info(f"  Model ID:                  {self.cpuid.model_id.hex()}")
        logger.info(f"  Stepping:                  {self.cpuid.stepping.hex()}")
        logger.info(f"  Reserved:                  {self.cpuid._reserved.hex()}")

        logger.info(f"Chip ID:                     {self.chip_id.hex()}")

        logger.info("Committed TCB:")
        logger.info(f"  Bootloader:                {self.committed_tcb.bootloader}")
        logger.info(f"  TEE:                       {self.committed_tcb.tee}")
        logger.info(f"  Reserved:                  {self.committed_tcb._reserved.hex()}")
        logger.info(f"  SNP:                       {self.committed_tcb.snp}")
        logger.info(f"  Microcode:                 {self.committed_tcb.microcode}")

        logger.info(f"Current Build:               {self.current_build}")
        logger.info(f"Current Minor:               {self.current_minor}")
        logger.info(f"Current Major:               {self.current_major}")
        logger.info(f"Committed Build:             {self.committed_build}")
        logger.info(f"Committed Minor:             {self.committed_minor}")
        logger.info(f"Committed Major:             {self.committed_major}")

        logger.info("Launch TCB:")
        logger.info(f"  Bootloader:                {self.launch_tcb.bootloader}")
        logger.info(f"  TEE:                       {self.launch_tcb.tee}")
        logger.info(f"  Reserved:                  {self.launch_tcb._reserved.hex()}")
        logger.info(f"  SNP:                       {self.launch_tcb.snp}")
        logger.info(f"  Microcode:                 {self.launch_tcb.microcode}")

        logger.info("Signature:")
        logger.info(f"  R component:               {self.signature.get_r().hex()}")
        logger.info(f"  S component:               {self.signature.get_s().hex()}")
