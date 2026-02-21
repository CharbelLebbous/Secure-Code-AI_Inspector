# Secure Coding Criteria

Use these criteria when reviewing code:

1. Validate and sanitize untrusted input before use in queries/commands.
2. Use parameterized queries and avoid string concatenation in data access.
3. Enforce authorization checks at route and object level.
4. Prevent IDOR by validating resource ownership.
5. Encrypt sensitive data in transit and at rest.
6. Avoid exposing secrets, tokens, or sensitive internals in logs/responses.
7. Use secure defaults and least-privilege configuration.
8. Produce practical remediation with code-level specificity.
9. Do not reference files or lines that are not present in the provided chunk/scope.

