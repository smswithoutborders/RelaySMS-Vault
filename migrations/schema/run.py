"""
════════════════════════════════════════════════════════════════════════
                Database Migration Tool Using Peewee ORM
════════════════════════════════════════════════════════════════════════

Applies schema changes defined in JSON migration spec files.
"""

import argparse
import ast
import json
import logging
import os
import re
from typing import Any, Dict, List

import peewee
from playhouse.migrate import MySQLMigrator, migrate

from src.db import connect

logging.basicConfig(level="DEBUG")

# ──────────────────────────────────────────────────────────────────────
#                          Configuration
# ──────────────────────────────────────────────────────────────────────
MIGRATION_DIR = os.path.join("migrations", "schema")
SUCCESS = "✅"
FAILED = "❌"

db = connect()
migrator = MySQLMigrator(db)

ALLOWED_FIELDS = {
    "CharField": peewee.CharField,
    "BooleanField": peewee.BooleanField,
    "BlobField": peewee.BlobField,
    "TextField": peewee.TextField,
}

ALLOWED_FUNCTIONS = {
    "SQL": peewee.SQL,
}

ACTIONS = {
    "add_column": migrator.add_column,
    "drop_column": migrator.drop_column,
    "rename_column": migrator.rename_column,
    "add_not_null": migrator.add_not_null,
    "drop_not_null": migrator.drop_not_null,
    "rename_table": migrator.rename_table,
    "add_index": migrator.add_index,
    "drop_index": migrator.drop_index,
    "add_foreign_key_constraint": migrator.add_foreign_key_constraint,
    "drop_foreign_key_constraint": migrator.drop_foreign_key_constraint,
}


# ──────────────────────────────────────────────────────────────────────
#                         Helper Functions
# ──────────────────────────────────────────────────────────────────────
def parse_field(field_str: str) -> peewee.Field:
    """Parses a Peewee field definition string.

    Args:
        field_str (str): Field definition (e.g., "CharField(max_length=255)").

    Returns:
        peewee.Field: The corresponding Peewee field instance.
    """
    match = re.match(r"(\w+)\((.*)\)", field_str)
    if not match:
        raise ValueError(f"Invalid field format: {field_str}")

    field_type, field_args = match.groups()
    if field_type not in ALLOWED_FIELDS:
        raise ValueError(f"Unsupported field type: {field_type}")

    try:
        args, kwargs = _parse_arguments(field_args)
        return ALLOWED_FIELDS[field_type](*args, **kwargs)

    except (SyntaxError, ValueError) as e:
        raise ValueError(f"Error parsing field arguments: {field_args}\n\n{e}") from e


def _parse_arguments(field_args: str):
    """Parses arguments from a field definition.

    Args:
        field_args (str): The arguments in string format.

    Returns:
        tuple: (list of positional args, dict of keyword args).
    """
    args, kwargs = [], {}

    if not field_args:
        return args, kwargs

    parsed_args = ast.parse(f"dummy({field_args})").body[0].value

    if isinstance(parsed_args, ast.Call):
        args = [_parse_node(arg) for arg in parsed_args.args]
        kwargs = {kw.arg: _parse_node(kw.value) for kw in parsed_args.keywords}

    return args, kwargs


def _parse_node(node):
    """Parses an AST node into a Python value.

    Args:
        node (ast.AST): The AST node to parse.

    Returns:
        Any: Parsed value (e.g., list, int, string, peewee.SQL).
    """
    if isinstance(node, ast.List):
        return [_parse_node(elt) for elt in node.elts]

    if isinstance(node, ast.Call):
        return _parse_function_call(node)

    return ast.literal_eval(node)


def _parse_function_call(node):
    """Handles function calls within field arguments.

    Args:
        node (ast.Call): The AST function call node.

    Returns:
        Any: The evaluated function result.

    Raises:
        ValueError: If the function is not allowed.
    """
    if isinstance(node.func, ast.Name):
        func_name = node.func.id

        if func_name in ALLOWED_FUNCTIONS:
            func = ALLOWED_FUNCTIONS[func_name]
            func_args = [_parse_node(arg) for arg in node.args]
            return func(*func_args)

    raise ValueError(f"Disallowed function call: {ast.dump(node)}")


def get_latest_schema_version() -> str:
    """
    Retrieve the latest schema version from the migration directory.

    Returns:
        str: Latest schema version, or None if no migrations found.
    """
    if not os.path.isdir(MIGRATION_DIR):
        print(f"⚠️ Warning: Migration directory not found: {MIGRATION_DIR}")
        return None

    migration_files = sorted(
        (
            file
            for file in os.listdir(MIGRATION_DIR)
            if file.startswith("v") and file.endswith(".json")
        ),
        reverse=True,
    )
    return migration_files[0].rstrip(".json") if migration_files else None


def load_spec(spec_version: str) -> List[Dict[str, Any]]:
    """
    Load the migration specification file for the given version.

    Args:
        spec_version (str): Schema version (e.g., "v1.0").

    Returns:
        List[Dict[str, Any]]: Parsed migration operations.

    Raises:
        FileNotFoundError: If the spec file does not exist.
    """
    spec_file_path = os.path.join(MIGRATION_DIR, f"{spec_version}.json")
    if not os.path.exists(spec_file_path):
        raise FileNotFoundError(f"Spec file '{spec_file_path}' not found.")

    with open(spec_file_path, encoding="utf-8") as f:
        return json.load(f)


# ──────────────────────────────────────────────────────────────────────
#                     Migration Management Class
# ──────────────────────────────────────────────────────────────────────
class MigrationManager:
    """Handles the execution of database migrations."""

    def __init__(self):
        self.migrations_done = 0
        self.migrations_failed = 0

    def migrate_operations(self, operations: List[Dict[str, Any]]):
        """
        Execute migration operations.

        Args:
            operations (list): List of migration actions to execute.

        Raises:
            ValueError: If unsupported actions or fields are encountered.
        """
        print("\nMigration Operations:")
        print("══════════════════════════════════════════════════════════════════════")

        for operation in operations:
            print(f"\n🔄 Performing operation: {operation}")

            try:
                action = operation.pop("action")

                if "field" in operation:
                    operation["field"] = parse_field(operation["field"])

                if action not in ACTIONS:
                    raise ValueError(f"Unsupported action: {action}")

                migrate(ACTIONS[action](**operation))
                self.migrations_done += 1
                print(f"{SUCCESS} Operation successful: {operation}")

            except Exception as e:
                self.migrations_failed += 1
                print(f"{FAILED} Operation failed: {operation}\n   Error: {e}")

        print("\nMigration Summary:")
        print("══════════════════════════════════════════════════════════════════════")
        print(f"{SUCCESS} Completed migrations: {self.migrations_done}")
        print(f"{FAILED} Failed migrations: {self.migrations_failed}")

    def check_and_migrate_schema(self, current_schema_version: str):
        """
        Check the current schema version and run migrations if necessary.

        Args:
            current_schema_version (str): Current version of the schema.
        """
        latest_schema_version = get_latest_schema_version()

        if latest_schema_version and current_schema_version != latest_schema_version:
            print(
                f"\n🔁 Migration Required: Migrating from version "
                f"{current_schema_version} to {latest_schema_version}"
            )
            spec = load_spec(latest_schema_version)
            self.migrate_operations(spec)
            print(f"{SUCCESS} Migration to version {latest_schema_version} completed.")
        else:
            print(f"{SUCCESS} Database schema is up to date.")


# ──────────────────────────────────────────────────────────────────────
#                         Command-line Interface
# ──────────────────────────────────────────────────────────────────────
def run():
    """Main function to parse command-line arguments and initiate migration."""
    parser = argparse.ArgumentParser(
        description="Apply database migrations using a specified schema version."
    )
    parser.add_argument(
        "command", choices=["migrate", "rollback"], help="Command to execute."
    )
    parser.add_argument("spec_version", help="Schema version to apply.")
    args = parser.parse_args()

    print("\nDatabase Schema Migration Tool")
    print("══════════════════════════════════════════════════════════════════════")

    manager = MigrationManager()

    match args.command:
        case "migrate":
            spec = load_spec(args.spec_version)
            manager.migrate_operations(spec)
        case "rollback":
            print(f"{FAILED} Rollback feature is not implemented yet.")


if __name__ == "__main__":
    run()
