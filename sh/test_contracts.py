import json
import jsonschema
from pathlib import Path

def test_finding_schema():
    schema_path = Path("contracts/finding.schema.json")
    if not schema_path.exists():
        print(f"Error: Schema file {schema_path} not found.")
        exit(1)

    with open(schema_path) as f:
        schema = json.load(f)

    
    valid_finding = {
        "rule_id": "ST-001",
        "name": "SQL Injection",
        "severity": "CRITICAL",
        "file": "src/app.py",
        "line": 42,
        "message": "Potential SQL injection in query",
        "cwe": "CWE-89",
        "snippet": "db.execute(f'SELECT * FROM users WHERE id={user_id}')",
        "language": "python",
        "confidence": "HIGH",
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"]
    }

    jsonschema.validate(instance=valid_finding, schema=schema)
    print("✓ Valid finding passed validation")

    
    invalid_finding = {
        "rule_id": "ST-001",
        "name": "SQL Injection"
    }
    
    try:
        jsonschema.validate(instance=invalid_finding, schema=schema)
        raise AssertionError("✗ Invalid finding (missing fields) failed to raise ValidationError")
    except jsonschema.ValidationError:
        print("✓ Invalid finding (missing fields) correctly failed validation")

    
    invalid_finding_type = valid_finding.copy()
    invalid_finding_type["line"] = "forty-two"
    
    try:
        jsonschema.validate(instance=invalid_finding_type, schema=schema)
        raise AssertionError("✗ Invalid finding (wrong type) failed to raise ValidationError")
    except jsonschema.ValidationError:
        print("✓ Invalid finding (wrong type) correctly failed validation")

if __name__ == "__main__":
    try:
        test_finding_schema()
        print("\nAll contract tests passed!")
    except Exception as e:
        print(f"\nContract tests failed: {e}")
        exit(1)
