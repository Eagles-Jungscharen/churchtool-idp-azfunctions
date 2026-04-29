# Copilot Instructions for churchtool-idp-azfunctions

## Project Purpose

This repository implements a ChurchTools Identity Provider (IDP) on Azure Functions (.NET isolated).
The system authenticates users against ChurchTools and issues RSA-signed JWT token sets:

- id_token
- access_token
- refresh_token

It also exposes a JWKS endpoint so downstream services can verify token signatures.

## Architecture Guardrails

Follow the current layering and keep responsibilities separated.

- Functions are HTTP entry points only.
- Services contain domain and integration logic.
- Models contain DTOs and storage entities.
- Dependency injection is configured in Program.cs.

Use these concrete boundaries:

- Functions/*: validate request, orchestrate service calls, map to HTTP results.
- Services/*: ChurchTools API access, JWT/JWK handling, token persistence logic.
- Models/*: request/response contracts and storage records.

Do not move business logic into Function classes unless explicitly requested.

## Runtime and Integration Context

The service depends on:

- ChurchTools API via CT_URL
- Azure Table Storage via AzureWebJobsStorage
- Azure Functions worker runtime (dotnet-isolated)

Default public endpoints are:

- POST /api/authenticate
- POST /api/refresh
- GET/POST /api/jwks.json

Preserve endpoint routes and request/response contract compatibility unless a change request explicitly asks for a breaking change.

## Token and Claim Contract

Current tokens include claims such as:

- firstname
- lastname
- email
- st_ref
- scopes (multiple)

Do not silently rename or remove claims.
If claim contract changes are required, update code and README in the same change.

Scopes are derived from ChurchTools groups using this shape:

- ct_group_<domainIdentifier>

Maintain this convention unless explicitly changed.

## Security Rules

When editing or adding code, follow these rules:

- Never log credentials.
- Never log raw ChurchTools cookies.
- Avoid logging full access or refresh tokens.
- Prefer structured logs with neutral, non-sensitive metadata.
- Keep refresh tokens one-time use behavior.
- Keep key lifecycle behavior consistent unless requested otherwise.

If you must log token-related data for diagnostics, log masked or truncated values only.

## Error Handling Rules

Use explicit and predictable HTTP semantics.

- 400 for malformed payloads or missing required fields.
- 401 for authentication/authorization failures.
- 502 for upstream dependency failures where applicable.

Prefer returning actionable but non-sensitive error messages.
Do not leak internal secrets, storage keys, or upstream response internals.

## Language Conventions

Apply the following language rules consistently across all code and documentation:

- **Code and variables**: English. This includes class names, method names, property names, variable names, and all identifiers.
- **Code comments**: German.
- **Error messages** (e.g. strings passed to `BadRequestObjectResult`, exception messages, validation error texts): German.
- **Log entries** (e.g. strings passed to `LogInformation`, `LogWarning`, `LogError`): English.

## Coding Conventions

- Keep nullable reference semantics aligned with current project settings.
- Use DI over manual service construction.
- Keep interfaces for service contracts where already established.
- Preserve existing naming style and folder organization.
- Prefer small, composable methods in services.

For new request/response contracts, use explicit JSON property names if wire format stability matters.

## Data and Storage Conventions

Table usage is part of the runtime contract.
Do not change table names or partition key semantics without an explicit migration task.

Current logical stores include:

- Public keys
- Private key metadata
- Refresh token mappings
- User login token references

Any schema change must include backward-compatibility or migration notes.

## Documentation and Change Hygiene

When behavior changes, update documentation in the same PR:

- README for public behavior and operational expectations.
- This file if coding rules or architecture constraints change.

If uncertainty exists about compatibility impact, ask before making breaking changes.
