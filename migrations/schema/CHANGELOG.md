# Changelog

## [v1.7.0] - 2025-12-04

### Changed

- Renamed the `signups` table to `stats` to better reflect its purpose as a statistics tracking table.
- Dropped the `auth_method` column from the signups table (data migrated to `identifier_type` in v1.6.0).
- Dropped the `source` column from the signups table (data migrated to `origin` in v1.6.0).

## [v1.6.0] - 2025-12-04

### Added

- Added a new column `identifier_type` of type `CharField(null=True)` to the `signups` table to replace `auth_method`.
- Added a new column `origin` of type `CharField(null=True)` to the `signups` table to replace `source`.
- Added a new column `event_type` of type `CharField(null=True)` to the `signups` table to track the type of event (e.g., "signup").
- Added a new column `event_stage` of type `CharField(null=True, constraints=[SQL("DEFAULT 'initiate'")])` to the `signups` table to track the stage of the event ("initiate" or "complete").
- Added a new column `origin` of type `CharField(null=True)` to the `entities` table to track whether the entity was created via bridges or platforms.

### Changed

- Dropped the `NOT NULL` constraint from the `country_code` column in the `signups` table to allow NULL values.

## [v1.5.0] - 2025-12-03

### Added

- Added a new column `purpose` of type `CharField(max_length=50, null=True)` to the `otp` table to track the purpose of the OTP (e.g., "signup", "login", "password_reset").

### Changed

- Dropped the `NOT NULL` constraint from the `otp_code` column in the `otp` table to allow NULL values.

## [v1.4.0] - 2025-11-26

### Security Enhancements

- Removed the `is_verified` column from the `otp` table as it is no longer needed with the new fail-closed security model.
- Made `phone_number` and `email` columns unique in the `otp` table to prevent multiple active OTP records for the same identifier.
- This change enables atomic replace operations and prevents OTP reuse attacks where verified codes could be reused after expiry.

### Changed

- Dropped existing non-unique indexes on `phone_number` and `email` columns in the `otp` table.
- Added unique indexes on `phone_number` and `email` columns in the `otp` table.

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
