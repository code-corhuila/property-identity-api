# Changelog of `property-identity-api`

Every release of this repository, newest first. One release per course cut, tagged on `main`
(`git-conventions.md`, "Tags and versioning"; SemVer). Each entry lists the user stories it
brought, with the pull requests of `develop` that built them.

## [3.0.0] - 2026-11-15

### Added

- **HU-IDENT-001 (code-corhuila/property-docs#163) — Register an account**
  - chore(identity): scaffold the three-module spring boot service (#1)
  - feat(identity): add the user account domain model and its roles (#3)
  - docs(identity): publish the versioned openapi contract (#2)
  - feat(identity): add the common http adapters (#4)
  - feat(identity): add the account store port and its in-memory adapter (#5)
  - feat(identity): store accounts in the identity schema (#6)
  - feat(identity): register an account and read my account (#8)
- **HU-IDENT-004 (code-corhuila/property-docs#187) — Credential for the workflow and the worker**
  - feat(identity): sign tokens with rs256 and publish the jwks (#7)
  - feat(identity): issue the service tokens with an operational command (#11)
- **HU-IDENT-002 (code-corhuila/property-docs#185) — Log in, renew and close the session**
  - feat(identity): log in, renew and close the session (#9)
- **HU-IDENT-003 (code-corhuila/property-docs#186) — Become a host**
  - feat(identity): turn a guest account into a host (#10)
- **HU-NOTIF-001 (code-corhuila/property-docs#201) — Notify the guest of the outcome of a reservation**
  - feat(identity): give notification the contact of a guest (#12)
