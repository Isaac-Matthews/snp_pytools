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

import json
import os
from typing import Any, Dict, List, Optional, Union

from .attestation_report import AttestationReport


class PolicyValidationError(Exception):
    """Exception raised when policy validation fails."""

    pass


class AttestationPolicy:
    """
    AttestationPolicy - Validates SEV-SNP attestation reports against security policies

    This class loads and validates attestation reports against predefined security policies
    specified in JSON format.
    """

    def __init__(
        self,
        policy_data: Optional[Dict[str, Any]] = None,
        policy_file: Optional[str] = None,
    ):
        """
        Initialize AttestationPolicy from JSON data or file.

        Args:
            policy_data: Dictionary containing policy rules
            policy_file: Path to JSON file containing policy rules

        Raises:
            ValueError: If neither policy_data nor policy_file is provided, or if the policy file is invalid
            FileNotFoundError: If policy_file doesn't exist
            json.JSONDecodeError: If policy file contains invalid JSON
        """
        if policy_data is not None:
            self.policy = policy_data
        elif policy_file is not None:
            self.policy = self._load_policy_file(policy_file)
        else:
            raise ValueError("Either policy_data or policy_file must be provided")

        self._validate_policy_structure()

    def _load_policy_file(self, policy_file: str) -> Dict[str, Any]:
        """Load policy from JSON file."""
        if not os.path.exists(policy_file):
            raise FileNotFoundError(f"Policy file not found: {policy_file}")

        with open(policy_file, "r") as f:
            return json.load(f)

    def _validate_policy_structure(self) -> None:
        """Validate that the policy has the expected structure."""
        required_sections = ["metadata", "validation_rules"]
        for section in required_sections:
            if section not in self.policy:
                raise ValueError(f"Policy missing required section: {section}")

    def validate_report(
        self,
        report: AttestationReport,
        report_data: bytes = None,
        verbose: bool = False,
    ) -> bool:
        """
        Validate an attestation report against the policy.

        Args:
            report: AttestationReport object to validate
            report_data: Optional report data to validate against the report's report_data field
            verbose: Whether to print detailed validation information

        Returns:
            True if report passes all policy checks

        Raises:
            PolicyValidationError: If any policy check fails
        """
        if verbose:
            print(
                f"Validating report against policy: {self.policy.get('metadata', {}).get('name', 'Unknown')}"
            )

        # Validate report_data if provided
        if report_data is not None:
            if verbose:
                print(f"\nValidating provided report_data against attestation report")

            if report.report_data != report_data:
                error_msg = f"Report data mismatch: expected {report_data.hex()}, got {report.report_data.hex()}"
                if verbose:
                    print(f"  {error_msg}")
                raise PolicyValidationError(error_msg)
            elif verbose:
                print(f"  Report data validation passed")

        validation_results = []
        rules = self.policy.get("validation_rules", {})

        # Validate each field in the policy rules
        for field_name, field_rules in rules.items():
            if verbose:
                print(f"\nValidating field: {field_name}")

            try:
                # Get the field value from the report
                if not hasattr(report, field_name):
                    if verbose:
                        print(f"  Field '{field_name}' not found in attestation report")
                    validation_results.append((field_name, False))
                else:
                    field_value = getattr(report, field_name)
                    result = self._validate_object(
                        field_value, field_rules, verbose, field_name
                    )
                    validation_results.append((field_name, result))

            except Exception as e:
                if verbose:
                    print(f"  Error validating field '{field_name}': {e}")
                validation_results.append((field_name, False))

        # Check if all validations passed
        failed_validations = [name for name, result in validation_results if not result]
        if failed_validations:
            raise PolicyValidationError(
                f"Policy validation failed for: {', '.join(failed_validations)}"
            )

        if verbose:
            print("\nAll policy validations passed successfully!")

        return True

    def _validate_object(
        self, obj: Any, rules: Dict[str, Any], verbose: bool, obj_name: str = ""
    ) -> bool:
        """
        Validate an object (simple field or nested object) against validation rules.

        Args:
            obj: The object to validate
            rules: Validation rules for this object
            verbose: Whether to print verbose information
            obj_name: Name of the object for verbose output

        Returns:
            True if object passes validation
        """
        validation_passed = True

        # Handle different types of validation rules
        for rule_type, rule_value in rules.items():
            if rule_type == "exact_match":
                if not self._validate_exact_match(obj, rule_value, verbose, obj_name):
                    validation_passed = False
            elif rule_type == "min_value":
                if not self._validate_min_value(obj, rule_value, verbose, obj_name):
                    validation_passed = False
            elif rule_type == "max_value":
                if not self._validate_max_value(obj, rule_value, verbose, obj_name):
                    validation_passed = False
            elif rule_type == "allow_list":
                if not self._validate_allow_list(obj, rule_value, verbose, obj_name):
                    validation_passed = False
            elif rule_type == "deny_list":
                if not self._validate_deny_list(obj, rule_value, verbose, obj_name):
                    validation_passed = False
            elif rule_type == "boolean":
                if not self._validate_boolean(obj, rule_value, verbose, obj_name):
                    validation_passed = False
            else:
                # Handle nested attribute validation - get the attribute and validate it recursively
                if not hasattr(obj, rule_type):
                    if verbose:
                        print(f"  Field '{rule_type}' not found in {obj_name}")
                    validation_passed = False
                else:
                    attr_value = getattr(obj, rule_type)
                    attr_name = f"{obj_name}.{rule_type}" if obj_name else rule_type

                    # Handle all validation rules recursively
                    if isinstance(rule_value, dict):
                        # Complex validation rules - recurse
                        if not self._validate_object(
                            attr_value, rule_value, verbose, attr_name
                        ):
                            validation_passed = False
                    else:
                        # Simple values - wrap them in a rules dict and recurse
                        if isinstance(rule_value, bool):
                            wrapped_rules = {"boolean": rule_value}
                        else:
                            wrapped_rules = {"exact_match": rule_value}
                        if not self._validate_object(
                            attr_value, wrapped_rules, verbose, attr_name
                        ):
                            validation_passed = False

        return validation_passed

    def _validate_exact_match(
        self, field_value: Any, expected_value: Any, verbose: bool, field_name: str = ""
    ) -> bool:
        """Validate that field value exactly matches expected value."""
        if isinstance(field_value, bytes):
            # Handle byte fields by converting expected hex string to bytes
            if isinstance(expected_value, str):
                expected_bytes = bytes.fromhex(
                    self._normalize_hex_string(expected_value)
                )
                if field_value != expected_bytes:
                    if verbose:
                        print(f"  {field_name} value mismatch:")
                        print(f"     Expected: {expected_value}")
                        print(f"     Actual:   {field_value.hex()}")
                    return False
            else:
                if field_value != expected_value:
                    if verbose:
                        print(
                            f"  {field_name} value mismatch: {field_value} != {expected_value}"
                        )
                    return False
        else:
            if field_value != expected_value:
                if verbose:
                    print(
                        f"  {field_name} value mismatch: {field_value} != {expected_value}"
                    )
                return False

        if verbose:
            print(f"  {field_name} exact match validation passed: {field_value}")
        return True

    def _validate_min_value(
        self, field_value: Any, min_value: Any, verbose: bool, field_name: str = ""
    ) -> bool:
        """Validate that field value is >= minimum value."""
        if field_value < min_value:
            if verbose:
                print(
                    f"  {field_name} value {field_value} < required minimum {min_value}"
                )
            return False
        if verbose:
            print(
                f"  {field_name} minimum value validation passed: {field_value} >= {min_value}"
            )
        return True

    def _validate_max_value(
        self, field_value: Any, max_value: Any, verbose: bool, field_name: str = ""
    ) -> bool:
        """Validate that field value is <= maximum value."""
        if field_value > max_value:
            if verbose:
                print(
                    f"  {field_name} value {field_value} > allowed maximum {max_value}"
                )
            return False
        if verbose:
            print(
                f"  {field_name} maximum value validation passed: {field_value} <= {max_value}"
            )
        return True

    def _validate_allow_list(
        self,
        field_value: Any,
        allowed_values: List[Any],
        verbose: bool,
        field_name: str = "",
    ) -> bool:
        """Validate that field value is in list of allowed values."""
        if field_value not in allowed_values:
            if verbose:
                print(
                    f"  {field_name} value {field_value} not in allow list {allowed_values}"
                )
            return False
        if verbose:
            print(
                f"  {field_name} allow list validation passed: {field_value} in {allowed_values}"
            )
        return True

    def _validate_deny_list(
        self,
        field_value: Any,
        denied_values: List[Any],
        verbose: bool,
        field_name: str = "",
    ) -> bool:
        """Validate that field value is not in list of denied values."""
        if field_value in denied_values:
            if verbose:
                print(
                    f"  {field_name} value {field_value} found in deny list {denied_values}"
                )
            return False
        if verbose:
            print(
                f"  {field_name} deny list validation passed: {field_value} not in {denied_values}"
            )
        return True

    def _validate_boolean(
        self,
        field_value: Any,
        expected_value: bool,
        verbose: bool,
        field_name: str = "",
    ) -> bool:
        """Validate that field value matches expected boolean value."""
        if field_value != expected_value:
            if verbose:
                print(f"  {field_name} is {field_value}, expected {expected_value}")
            return False
        if verbose:
            print(f"  {field_name} is correctly set to {expected_value}")
        return True

    def _normalize_hex_string(self, hex_str: str) -> str:
        """Normalize hex string by removing prefixes and converting to lowercase."""
        if hex_str.startswith("0x"):
            hex_str = hex_str[2:]
        return hex_str.lower()

    def get_policy_summary(self) -> str:
        """Get a human-readable summary of the policy."""
        metadata = self.policy.get("metadata", {})
        rules = self.policy.get("validation_rules", {})

        summary = []
        summary.append(f"Policy: {metadata.get('name', 'Unknown')}")
        summary.append(f"Version: {metadata.get('version', 'Unknown')}")
        summary.append(f"Description: {metadata.get('description', 'No description')}")
        summary.append("")
        summary.append("Validation Rules:")

        for rule_type in rules.keys():
            summary.append(f"  - {rule_type}")

        return "\n".join(summary)


def validate_report_with_policy(
    report: AttestationReport,
    policy_file: str,
    report_data: bytes = None,
    verbose: bool = False,
) -> bool:
    """
    Convenience function to validate a report against a policy file.

    Args:
        report: AttestationReport object to validate
        policy_file: Path to JSON policy file
        report_data: Optional report data to validate against
        verbose: Whether to print detailed validation information

    Returns:
        True if report passes all policy checks

    Raises:
        PolicyValidationError: If any policy check fails
    """
    policy = AttestationPolicy(policy_file=policy_file)
    return policy.validate_report(report, report_data=report_data, verbose=verbose)
