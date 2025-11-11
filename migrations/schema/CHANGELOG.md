# Changelog

## [v1.3.0] - 2025-11-11

### Added

- Added a new column `auth_method` of type `CharField(null=True, constraints=[SQL("DEFAULT 'phone_number'")])` to the `signups` table to track the authentication method used during signup (e.g., "email" or "phone_number"). Existing records will default to 'phone_number'.

## [v1.2.0] - 2025-11-04

### Added

- Added a new column `email_hash` of type `CharField(null=True)` to the `entities` table.
- Added a new column `email` of type `CharField(null=True)` to the `otp_rate_limit` table.
- Added a new column `email` of type `CharField(null=True)` to the `otp` table.
- Added unique index on `email_hash` column in the `entities` table.
- Added unique index on `email` column in the `otp_rate_limit` table.
- Added index on `email` column in the `otp` table.

### Changed

- Modified `phone_number_hash` column in the `entities` table to allow NULL values.
- Modified `phone_number` column in the `otp_rate_limit` table to allow NULL values.
- Modified `phone_number` column in the `otp` table to allow NULL values.
- Added CASCADE delete behavior to the foreign key relationship between `password_rate_limit` and `entities` tables.

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
