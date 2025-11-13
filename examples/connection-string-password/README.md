# connection-string-password Test Suite

This example tests detection of database and message broker connection strings with empty or hardcoded passwords.

## Problem

Embedding credentials directly in source code creates several security risks:
1. **Version control exposure**: Passwords stored in git history
2. **Credential rotation difficulty**: Requires code changes and redeployment
3. **Privilege escalation**: Developers get production credentials
4. **Audit trail gaps**: No logging of credential usage

## Test Cases

### Problematic (6 functions)

1. `postgres_empty_password` - Empty password (`:@` pattern)
2. `mysql_hardcoded_password` - Hardcoded password `password123`
3. `redis_hardcoded_password` - Hardcoded Redis password
4. `postgresql_hardcoded_password` - Password with special characters
5. `amqp_empty_password` - Empty RabbitMQ password
6. `mongodb_hardcoded_password` - Hardcoded MongoDB credentials

### Safe (7 functions)

1. `postgres_from_env` - Loading from environment variable
2. `mysql_constructed_from_env` - Building string from env vars
3. `redis_localhost_no_auth` - Localhost without authentication
4. `postgres_with_port_only` - No credentials in string
5. `postgres_unix_socket` - Unix socket (no password needed)
6. `connection_string_const` - Using constant (should be from config)
7. `unrelated_string` - Not actually a connection string

## Detection Strategy

The rule looks for:
1. Connection string protocols: `postgres://`, `mysql://`, `redis://`, `amqp://`, `mongodb://`
2. Empty password patterns: `user:@host`
3. Hardcoded password patterns: `user:password@host` where password is not empty and not numeric (port)

## Expected Results

- **Recall**: 6/6 = 100% (all problematic cases should be detected)
- **Precision**: Should have minimal false positives on safe cases
