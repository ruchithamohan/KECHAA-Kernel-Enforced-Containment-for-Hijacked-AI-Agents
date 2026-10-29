"""JSON Schema authoring contract; semantic evaluation remains in policy.py."""

from .policy import ENVIRONMENT, LIMITS


def policy_schema() -> dict:
    path = {"type": "string", "pattern": "^/", "maxLength": 4096}
    paths = {"type": "array", "items": {"$ref": "#/$defs/path"}, "maxItems": 64, "uniqueItems": True}
    identifier = {"type": "string", "pattern": "^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}$"}
    profile = {
        "type": "object", "additionalProperties": False,
        "required": ["read", "write", "execute", "network", "environment", "limits"],
        "properties": {
            **{key: {"$ref": "#/$defs/paths"} for key in ("read", "write")},
            "execute": {**paths, "minItems": 1}, "network": {"const": "offline"},
            "extends": identifier,
            "environment": {"type": "object", "additionalProperties": False,
                            "properties": {name: {"type": "string", "maxLength": 4096} for name in sorted(ENVIRONMENT)}},
            "limits": {"type": "object", "additionalProperties": False, "required": sorted(LIMITS),
                       "properties": {name: {"type": "integer", "minimum": bounds[0], "maximum": bounds[1]} for name, bounds in sorted(LIMITS.items())}},
        },
    }
    rule = {
        "type": "object", "additionalProperties": False,
        "required": ["id", "executable", "profile", "decision"],
        "properties": {
            "id": identifier, "executable": path, "profile": identifier,
            "decision": {"enum": ["allow", "ask", "deny"]},
            "argv_prefix": {"type": "array", "maxItems": 64, "items": {"type": "string", "maxLength": 4096}},
            "expires_at": {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"},
            "exception_reason": {"type": "string", "minLength": 8, "maxLength": 1000},
        },
        "dependentRequired": {"expires_at": ["exception_reason", "argv_prefix"], "exception_reason": ["expires_at", "argv_prefix"]},
        "allOf": [{"if": {"required": ["expires_at"]},
                   "then": {"properties": {"decision": {"enum": ["allow", "ask"]}, "argv_prefix": {"minItems": 1}}}}],
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "KECHAA policy schema 1",
        "description": "Authoring structure only. kechaa policy validate also checks strict YAML, canonical paths, sensitive overlap, inheritance, environment, rule references and UTC dates.",
        "type": "object", "additionalProperties": False,
        "required": ["schema", "name", "default", "roots", "sensitive", "grant_ttl_seconds", "profiles", "rules"],
        "$defs": {"path": path, "paths": paths, "profile": profile, "rule": rule},
        "properties": {
            "schema": {"const": 1}, "name": identifier, "default": {"const": "deny"},
            "roots": {**paths, "minItems": 1}, "sensitive": paths,
            "grant_ttl_seconds": {"type": "integer", "minimum": 1, "maximum": 120},
            "profiles": {"type": "object", "minProperties": 1, "maxProperties": 16,
                         "propertyNames": identifier, "additionalProperties": {"$ref": "#/$defs/profile"}},
            "rules": {"type": "array", "minItems": 1, "maxItems": 128, "items": {"$ref": "#/$defs/rule"}},
        },
    }
