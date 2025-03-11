# Changelog

## [v1.1.0] - 2025-03-03

### Added

- Added a new column `language` of type `CharField(null=True, constraints=[SQL("DEFAULT 'en'")])` to the `entities` table.

## [v1.0.2] - 2024-10-10

### Changed

- Dropped the `NOT NULL` constraint from the `password_hash` column in the `entities` table.

### Added

- Added a new column `is_bridge_enabled` of type `BooleanField()` to the `entities` table.

## [v1.0.1] - 2024-09-18

### Changed

- Dropped the index `token_platform_account_identifier_hash` from the `tokens` table.

### Added

- Added a unique composite index on `platform`, `account_identifier_hash`, and `eid` in the `tokens` table.
