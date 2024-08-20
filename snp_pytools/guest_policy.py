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
class GuestPolicy:
    """
    GuestPolicy
    Description: Represents the guest policy with various configurable options
    """

    def __init__(self, value: int = 0):
        """
        __init__
        Description: Initialize a GuestPolicy object
        Input: value: int: The initial value of the policy (default: 0)
        Output: None
        """
        self._value = value

    def _get_bits(self, start: int, end: int) -> int:
        """
        _get_bits
        Description: Extract a range of bits from the policy value
        Inputs:
            start: int: The starting bit position
            end: int: The ending bit position
        Output: int: The extracted bit value
        """
        mask = ((1 << (end - start + 1)) - 1) << start
        return (self._value & mask) >> start

    def _set_bits(self, start: int, end: int, value: int):
        """
        _set_bits
        Description: Set a range of bits in the policy value
        Inputs:
            start: int: The starting bit position
            end: int: The ending bit position
            value: int: The value to set
        Output: None
        """
        mask = ((1 << (end - start + 1)) - 1) << start
        self._value = (self._value & ~mask) | ((value << start) & mask)

    @property
    def abi_minor(self) -> int:
        """
        abi_minor
        Description: Get the ABI minor version
        Input: None
        Output: int: The ABI minor version
        """
        return self._get_bits(0, 7)

    @abi_minor.setter
    def abi_minor(self, value: int):
        """
        abi_minor setter
        Description: Set the ABI minor version
        Input: value: int: The ABI minor version to set
        Output: None
        """
        self._set_bits(0, 7, value)

    @property
    def abi_major(self) -> int:
        """
        abi_major
        Description: Get the ABI major version
        Input: None
        Output: int: The ABI major version
        """
        return self._get_bits(8, 15)

    @abi_major.setter
    def abi_major(self, value: int):
        """
        abi_major setter
        Description: Set the ABI major version
        Input: value: int: The ABI major version to set
        Output: None
        """
        self._set_bits(8, 15, value)

    @property
    def smt_allowed(self) -> bool:
        """
        smt_allowed
        Description: Check if SMT is allowed
        Input: None
        Output: bool: True if SMT is allowed, False otherwise
        """
        return bool(self._get_bits(16, 16))

    @smt_allowed.setter
    def smt_allowed(self, value: bool):
        """
        smt_allowed setter
        Description: Set whether SMT is allowed
        Input: value: bool: True to allow SMT, False to disallow
        Output: None
        """
        self._set_bits(16, 16, int(value))

    @property
    def migrate_ma_allowed(self) -> bool:
        """
        migrate_ma_allowed
        Description: Check if migration MA is allowed
        Input: None
        Output: bool: True if migration MA is allowed, False otherwise
        """
        return bool(self._get_bits(18, 18))

    @migrate_ma_allowed.setter
    def migrate_ma_allowed(self, value: bool):
        """
        migrate_ma_allowed setter
        Description: Set whether migration MA is allowed
        Input: value: bool: True to allow migration MA, False to disallow
        Output: None
        """
        self._set_bits(18, 18, int(value))

    @property
    def debug_allowed(self) -> bool:
        """
        debug_allowed
        Description: Check if debugging is allowed
        Input: None
        Output: bool: True if debugging is allowed, False otherwise
        """
        return bool(self._get_bits(19, 19))

    @debug_allowed.setter
    def debug_allowed(self, value: bool):
        """
        debug_allowed setter
        Description: Set whether debugging is allowed
        Input: value: bool: True to allow debugging, False to disallow
        Output: None
        """
        self._set_bits(19, 19, int(value))

    @property
    def single_socket_required(self) -> bool:
        """
        single_socket_required
        Description: Check if a single socket is required
        Input: None
        Output: bool: True if a single socket is required, False otherwise
        """
        return bool(self._get_bits(20, 20))

    @single_socket_required.setter
    def single_socket_required(self, value: bool):
        """
        single_socket_required setter
        Description: Set whether a single socket is required
        Input: value: bool: True to require a single socket, False otherwise
        Output: None
        """
        self._set_bits(20, 20, int(value))

    @property
    def cxl_allowed(self) -> bool:
        """
        cxl_allowed
        Description: Check if CXL is allowed
        Input: None
        Output: bool: True if CXL is allowed, False otherwise
        """
        return bool(self._get_bits(21, 21))

    @cxl_allowed.setter
    def cxl_allowed(self, value: bool):
        """
        cxl_allowed setter
        Description: Set whether CXL is allowed
        Input: value: bool: True to allow CXL, False to disallow
        Output: None
        """
        self._set_bits(21, 21, int(value))

    @property
    def mem_aes_256_xts(self) -> bool:
        """
        mem_aes_256_xts
        Description: Check if memory AES-256 XTS is enabled
        Input: None
        Output: bool: True if memory AES-256 XTS is enabled, False otherwise
        """
        return bool(self._get_bits(22, 22))

    @mem_aes_256_xts.setter
    def mem_aes_256_xts(self, value: bool):
        """
        mem_aes_256_xts setter
        Description: Set whether memory AES-256 XTS is enabled
        Input: value: bool: True to enable memory AES-256 XTS, False to disable
        Output: None
        """
        self._set_bits(22, 22, int(value))

    @property
    def rapl_dis(self) -> bool:
        """
        rapl_dis
        Description: Check if RAPL is disabled
        Input: None
        Output: bool: True if RAPL is disabled, False otherwise
        """
        return bool(self._get_bits(23, 23))

    @rapl_dis.setter
    def rapl_dis(self, value: bool):
        """
        rapl_dis setter
        Description: Set whether RAPL is disabled
        Input: value: bool: True to disable RAPL, False to enable
        Output: None
        """
        self._set_bits(23, 23, int(value))

    @property
    def ciphertext_hiding(self) -> bool:
        """
        ciphertext_hiding
        Description: Check if ciphertext hiding is enabled
        Input: None
        Output: bool: True if ciphertext hiding is enabled, False otherwise
        """
        return bool(self._get_bits(24, 24))

    @ciphertext_hiding.setter
    def ciphertext_hiding(self, value: bool):
        """
        ciphertext_hiding setter
        Description: Set whether ciphertext hiding is enabled
        Input: value: bool: True to enable ciphertext hiding, False to disable
        Output: None
        """
        self._set_bits(24, 24, int(value))

    def __repr__(self):
        """
        __repr__
        Description: Get a string representation of the GuestPolicy object
        Input: None
        Output: str: String representation of the GuestPolicy
        """
        return f"GuestPolicy(0x{self._value:016x})"
