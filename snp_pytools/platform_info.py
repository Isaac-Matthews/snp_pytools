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

from dataclasses import dataclass


@dataclass
class PlatformInfo:
    """
    PlatformInfo
    Description: Represents platform information with various configurable options
    """

    def __init__(self, value: int = 0):
        """
        __init__
        Description: Initialize a PlatformInfo object
        Input: value: int: The initial value of the platform info (default: 0)
        Output: None
        """
        self._value = value

    def _get_bit(self, position: int) -> bool:
        """
        _get_bit
        Description: Get the value of a specific bit in the platform info
        Input: position: int: The bit position to check
        Output: bool: The value of the specified bit
        """
        return bool(self._value & (1 << position))

    def _set_bit(self, position: int, value: bool):
        """
        _set_bit
        Description: Set the value of a specific bit in the platform info
        Inputs:
            position: int: The bit position to set
            value: bool: The value to set (True for 1, False for 0)
        Output: None
        """
        if value:
            self._value |= 1 << position
        else:
            self._value &= ~(1 << position)

    @property
    def smt_enabled(self) -> bool:
        """
        smt_enabled
        Description: Check if Simultaneous Multi-Threading (SMT) is enabled
        Input: None
        Output: bool: True if SMT is enabled, False otherwise
        """
        return self._get_bit(0)

    @smt_enabled.setter
    def smt_enabled(self, value: bool):
        """
        smt_enabled setter
        Description: Set whether Simultaneous Multi-Threading (SMT) is enabled
        Input: value: bool: True to enable SMT, False to disable
        Output: None
        """
        self._set_bit(0, value)

    @property
    def tsme_enabled(self) -> bool:
        """
        tsme_enabled
        Description: Check if Transparent Secure Memory Encryption (TSME) is enabled
        Input: None
        Output: bool: True if TSME is enabled, False otherwise
        """
        return self._get_bit(1)

    @tsme_enabled.setter
    def tsme_enabled(self, value: bool):
        """
        tsme_enabled setter
        Description: Set whether Transparent Secure Memory Encryption (TSME) is enabled
        Input: value: bool: True to enable TSME, False to disable
        Output: None
        """
        self._set_bit(1, value)

    @property
    def ecc_enabled(self) -> bool:
        """
        ecc_enabled
        Description: Check if Error-Correcting Code (ECC) memory is enabled
        Input: None
        Output: bool: True if ECC is enabled, False otherwise
        """
        return self._get_bit(2)

    @ecc_enabled.setter
    def ecc_enabled(self, value: bool):
        """
        ecc_enabled setter
        Description: Set whether Error-Correcting Code (ECC) memory is enabled
        Input: value: bool: True to enable ECC, False to disable
        Output: None
        """
        self._set_bit(2, value)

    @property
    def rapl_disabled(self) -> bool:
        """
        rapl_disabled
        Description: Check if Running Average Power Limit (RAPL) is disabled
        Input: None
        Output: bool: True if RAPL is disabled, False otherwise
        """
        return self._get_bit(3)

    @rapl_disabled.setter
    def rapl_disabled(self, value: bool):
        """
        rapl_disabled setter
        Description: Set whether Running Average Power Limit (RAPL) is disabled
        Input: value: bool: True to disable RAPL, False to enable
        Output: None
        """
        self._set_bit(3, value)

    @property
    def ciphertext_hiding_enabled(self) -> bool:
        """
        ciphertext_hiding_enabled
        Description: Check if ciphertext hiding is enabled
        Input: None
        Output: bool: True if ciphertext hiding is enabled, False otherwise
        """
        return self._get_bit(4)

    @ciphertext_hiding_enabled.setter
    def ciphertext_hiding_enabled(self, value: bool):
        """
        ciphertext_hiding_enabled setter
        Description: Set whether ciphertext hiding is enabled
        Input: value: bool: True to enable ciphertext hiding, False to disable
        Output: None
        """
        self._set_bit(4, value)

    def __repr__(self):
        """
        __repr__
        Description: Get a string representation of the PlatformInfo object
        Input: None
        Output: str: String representation of the PlatformInfo
        """
        return f"PlatformInfo(0x{self._value:016x})"
