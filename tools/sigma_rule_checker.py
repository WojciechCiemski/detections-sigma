#!/usr/bin/env python3

import os
import re
import yaml
from pathlib import Path
from typing import List

SIGMA_DIR = Path("rules/windows")
REQUIRED_FIELDS = ["title", "id", "description", "status", "logsource", "detection", "level", "tags"]
VALID_STATUSES = ["experimental", "testing", "stable", "deprecated"]
UUID_REGEX = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$")


def validate_sigma_rule(file_path: Path) -> List[str]:
    errors = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            rule = yaml.safe_load(f)

        if not isinstance(rule, dict):
            return ["File does not contain a valid YAML mapping"]

        # Check for required top-level fields
        for field in REQUIRED_FIELDS:
            if field not in rule:
                errors.append(f"Missing field: {field}")

        # Validate 'tags' field
        tags = rule.get("tags", [])
        if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
            errors.append("'tags' field must be a list of strings")
        elif not any(tag.startswith("attack.t") for tag in tags):
            errors.append("Missing MITRE ATT&CK tag in 'tags'")

        # Validate 'status' value
        status = rule.get("status")
        if status and status not in VALID_STATUSES:
            errors.append(f"Invalid status value: {status}")

        # Validate 'id' format
        rule_id = rule.get("id")
        if rule_id and not UUID_REGEX.match(str(rule_id).lower()):
            errors.append("Field 'id' is not a valid UUID")

        # Validate 'logsource' structure
        logsource = rule.get("logsource", {})
        if not isinstance(logsource, dict):
            errors.append("'logsource' must be a dictionary")
        elif "product" not in logsource:
            errors.append("'logsource' must contain 'product'")

        # Validate 'detection' structure
        detection = rule.get("detection", {})
        if not isinstance(detection, dict):
            errors.append("'detection' must be a dictionary")
        elif "condition" not in detection:
            errors.append("'detection' must contain 'condition'")

    except yaml.YAMLError as e:
        errors.append(f"YAML parse error: {str(e)}")
    except Exception as e:
        errors.append(f"Unexpected error: {str(e)}")

    return errors


def main():
    print(f"Validating Sigma rules in {SIGMA_DIR.resolve()}\n")
    failed = 0
    total = 0

    for file in SIGMA_DIR.glob("*.yml"):
        total += 1
        errors = validate_sigma_rule(file)
        if errors:
            failed += 1
            print(f"❌ {file.name} ({len(errors)} issue(s)):")
            for err in errors:
                print(f"   - {err}")
        else:
            print(f"✅ {file.name} is valid.")

    print("\n---")
    print(f"Checked {total} rule(s). {failed} with issues.")


if __name__ == "__main__":
    main()
