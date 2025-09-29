# Raybeam API Reference

## Overview

Raybeam provides a REST API for managing SSH public keys with LDAP-based authentication. The API supports dual response formats:
- **text/plain** (default): SSH authorized_keys format, ideal for scripting
- **application/json**: Structured JSON responses, ideal for applications

All endpoints that require authentication use HTTP Basic Auth with LDAP credentials.

## Base URL

```
http://your-server:8080
```

## Authentication

### Basic Authentication

Most endpoints require HTTP Basic Authentication using LDAP credentials:

```bash
curl -u username:password http://your-server:8080/users/@me/ssh-keys
```

### Authorization Levels

- **Public**: No authentication required
- **Authenticated**: Valid LDAP credentials required
- **Admin**: Authenticated user must be in the configured admin LDAP group

## Special Path Parameters

### @me Alias

The `@me` alias represents the currently authenticated user:

```bash
# List your own keys
curl -u alice:password http://your-server:8080/users/@me/ssh-keys
```

### Multi-User Operations

Many endpoints support comma-separated sAMAccountNames for batch operations:

```bash
# Get keys for multiple users
curl http://your-server:8080/users/alice,bob,charlie/ssh-keys
```

## Endpoints

### System Information

#### Get Server Info

Returns version and repository information.

**Endpoint**: `GET /info`
**Authentication**: None
**Response Format**: JSON only

**Response**:
```json
{
  "version": "c95e75c",
  "source": "https://github.com/netresearch/raybeam"
}
```

**Example**:
```bash
curl http://your-server:8080/info
```

---

### SSH Key Management - Self-Service (@me)

#### List Own SSH Keys

List all SSH keys for the authenticated user.

**Endpoint**: `GET /users/@me/ssh-keys`
**Authentication**: Required (user)
**Response Formats**: text/plain, application/json

**Response (text/plain)**:
```
# Keys uploaded by "CN=Alice,OU=Users,DC=example,DC=com"
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFq...
```

**Response (application/json)**:
```json
{
  "success": true,
  "keys": {
    "SHA256:hSZQXa36JqMa2L3TRhc0t6RHSXVO3gy6rYx7RrVS2HA": {
      "fingerprint": "SHA256:hSZQXa36JqMa2L3TRhc0t6RHSXVO3gy6rYx7RrVS2HA",
      "key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...\n"
    }
  }
}
```

**Example**:
```bash
# Get text/plain format
curl -u alice:password http://your-server:8080/users/@me/ssh-keys

# Get JSON format
curl -u alice:password -H "Accept: application/json" \
  http://your-server:8080/users/@me/ssh-keys
```

---

#### Upload SSH Key (Self)

Upload a new SSH public key for the authenticated user.

**Endpoint**: `PUT /users/@me/ssh-keys`
**Authentication**: Required (user)
**Content-Type**: text/plain
**Response Formats**: text/plain, application/json

**Request Body**:
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... user@hostname
```

**Response (application/json)**:
```json
{
  "success": true
}
```

**Status Codes**:
- `201 Created`: Key uploaded successfully
- `401 Unauthorized`: Authentication failed
- `500 Internal Server Error`: Key already exists or validation failed

**Example**:
```bash
# Upload key from file
curl -u alice:password -T ~/.ssh/id_rsa.pub \
  http://your-server:8080/users/@me/ssh-keys

# Upload key inline
curl -u alice:password -X PUT \
  -d "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ..." \
  http://your-server:8080/users/@me/ssh-keys
```

**Notes**:
- Key comments are automatically removed during upload
- Duplicate keys (same fingerprint) are rejected
- Key is validated using golang.org/x/crypto/ssh parser

---

#### Get Specific SSH Key (Self)

Retrieve a specific SSH key by fingerprint for the authenticated user.

**Endpoint**: `GET /users/@me/ssh-keys/:fingerprint`
**Authentication**: Required (user)
**Response Formats**: text/plain, application/json

**Path Parameters**:
- `fingerprint`: SHA256 fingerprint (e.g., `SHA256:hSZQXa36JqMa2L3TRhc0t6RHSXVO3gy6rYx7RrVS2HA`)

**Response (text/plain)**:
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...
```

**Response (application/json)**:
```json
{
  "success": true,
  "key": {
    "fingerprint": "SHA256:hSZQXa36JqMa2L3TRhc0t6RHSXVO3gy6rYx7RrVS2HA",
    "key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...\n"
  }
}
```

**Status Codes**:
- `200 OK`: Key found
- `401 Unauthorized`: Authentication failed
- `404 Not Found`: Key not found

**Example**:
```bash
# Generate fingerprint
ssh-keygen -l -E sha256 -f ~/.ssh/id_rsa.pub

# Get key by fingerprint
curl -u alice:password \
  http://your-server:8080/users/@me/ssh-keys/SHA256:hSZQXa36JqMa2L3TRhc0t6RHSXVO3gy6rYx7RrVS2HA
```

---

#### Delete Specific SSH Key (Self)

Delete a specific SSH key by fingerprint for the authenticated user.

**Endpoint**: `DELETE /users/@me/ssh-keys/:fingerprint`
**Authentication**: Required (user)
**Response Formats**: text/plain, application/json

**Path Parameters**:
- `fingerprint`: SHA256 fingerprint

**Response (application/json)**:
```json
{
  "success": true
}
```

**Status Codes**:
- `200 OK`: Key deleted successfully
- `401 Unauthorized`: Authentication failed
- `500 Internal Server Error`: Deletion failed

**Example**:
```bash
curl -u alice:password -X DELETE \
  http://your-server:8080/users/@me/ssh-keys/SHA256:hSZQXa36JqMa2L3TRhc0t6RHSXVO3gy6rYx7RrVS2HA
```

---

#### Delete All SSH Keys (Self)

Delete all SSH keys for the authenticated user.

**Endpoint**: `DELETE /users/@me/ssh-keys`
**Authentication**: Required (user)
**Response Formats**: text/plain, application/json

**Response (application/json)**:
```json
{
  "success": true
}
```

**Status Codes**:
- `200 OK`: All keys deleted successfully
- `401 Unauthorized`: Authentication failed
- `500 Internal Server Error`: Deletion failed

**Example**:
```bash
curl -u alice:password -X DELETE \
  http://your-server:8080/users/@me/ssh-keys
```

---

### SSH Key Management - Multi-User Operations

#### List SSH Keys for Users

List all SSH keys for one or more users (comma-separated).

**Endpoint**: `GET /users/:sAMAccountNames/ssh-keys`
**Authentication**: None (public read)
**Response Formats**: text/plain, application/json

**Path Parameters**:
- `sAMAccountNames`: Single user or comma-separated list (e.g., `alice` or `alice,bob,charlie`)

**Response (text/plain)**:
```
# Keys uploaded by "CN=Alice,OU=Users,DC=example,DC=com"
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...
# Keys uploaded by "CN=Bob,OU=Users,DC=example,DC=com"
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFq...
```

**Response (application/json)**:
```json
{
  "success": true,
  "keys": {
    "CN=Alice,OU=Users,DC=example,DC=com": {
      "SHA256:hSZQXa36JqMa2L3TRhc0t6RHSXVO3gy6rYx7RrVS2HA": {
        "fingerprint": "SHA256:hSZQXa36JqMa2L3TRhc0t6RHSXVO3gy6rYx7RrVS2HA",
        "key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...\n"
      }
    },
    "CN=Bob,OU=Users,DC=example,DC=com": {
      "SHA256:different_fingerprint": {
        "fingerprint": "SHA256:different_fingerprint",
        "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFq...\n"
      }
    }
  }
}
```

**Status Codes**:
- `200 OK`: Keys retrieved successfully
- `404 Not Found`: One or more users not found in LDAP

**Example**:
```bash
# Get keys for single user
curl http://your-server:8080/users/alice/ssh-keys

# Get keys for multiple users
curl http://your-server:8080/users/alice,bob,charlie/ssh-keys

# Get JSON format
curl -H "Accept: application/json" \
  http://your-server:8080/users/alice,bob/ssh-keys
```

---

#### Upload SSH Keys for Users (Admin)

Upload a SSH public key for one or more users. Requires admin privileges unless uploading for self.

**Endpoint**: `PUT /users/:sAMAccountNames/ssh-keys`
**Authentication**: Required (admin or self)
**Content-Type**: text/plain
**Response Formats**: text/plain, application/json

**Path Parameters**:
- `sAMAccountNames`: Single user or comma-separated list

**Authorization**:
- If `sAMAccountNames` matches authenticated user: self-service allowed
- Otherwise: authenticated user must be in admin LDAP group

**Request Body**:
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... user@hostname
```

**Response (application/json)**:
```json
{
  "success": true
}
```

**Status Codes**:
- `201 Created`: Key(s) uploaded successfully
- `401 Unauthorized`: Authentication failed
- `403 Forbidden`: Not authorized (not admin or self)
- `404 Not Found`: One or more users not found in LDAP
- `500 Internal Server Error`: Upload failed

**Example**:
```bash
# Admin uploads key for multiple users
curl -u admin:password -T ~/.ssh/id_rsa.pub \
  http://your-server:8080/users/alice,bob,charlie/ssh-keys

# Self-service upload (same as @me endpoint)
curl -u alice:password -T ~/.ssh/id_rsa.pub \
  http://your-server:8080/users/alice/ssh-keys
```

---

#### Get Specific SSH Key for Users

Retrieve a specific SSH key by fingerprint for one or more users.

**Endpoint**: `GET /users/:sAMAccountNames/ssh-keys/:fingerprint`
**Authentication**: None (public read)
**Response Formats**: text/plain, application/json

**Path Parameters**:
- `sAMAccountNames`: Single user or comma-separated list
- `fingerprint`: SHA256 fingerprint

**Response (text/plain)**:
```
# Keys uploaded by "CN=Alice,OU=Users,DC=example,DC=com"
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...
# Keys uploaded by "CN=Bob,OU=Users,DC=example,DC=com"
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...
```

**Response (application/json)**:
```json
{
  "success": true,
  "keys": {
    "CN=Alice,OU=Users,DC=example,DC=com": {
      "fingerprint": "SHA256:hSZQXa36JqMa2L3TRhc0t6RHSXVO3gy6rYx7RrVS2HA",
      "key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...\n"
    }
  }
}
```

**Status Codes**:
- `200 OK`: Key found
- `404 Not Found`: Key not found or user(s) not found

**Example**:
```bash
curl http://your-server:8080/users/alice,bob/ssh-keys/SHA256:hSZQXa36JqMa2L3TRhc0t6RHSXVO3gy6rYx7RrVS2HA
```

---

#### Delete Specific SSH Key for Users

Delete a specific SSH key by fingerprint for one or more users. Requires authentication.

**Endpoint**: `DELETE /users/:sAMAccountNames/ssh-keys/:fingerprint`
**Authentication**: Required (user or admin)
**Response Formats**: text/plain, application/json

**Path Parameters**:
- `sAMAccountNames`: Single user or comma-separated list
- `fingerprint`: SHA256 fingerprint

**Authorization**:
- Authenticated user can delete their own keys
- Admin can delete any user's keys

**Response (application/json)**:
```json
{
  "success": true
}
```

**Status Codes**:
- `200 OK`: Key(s) deleted successfully
- `401 Unauthorized`: Authentication failed
- `404 Not Found`: User(s) not found
- `500 Internal Server Error`: Deletion failed

**Example**:
```bash
# User deletes own key
curl -u alice:password -X DELETE \
  http://your-server:8080/users/alice/ssh-keys/SHA256:hSZQXa36JqMa2L3TRhc0t6RHSXVO3gy6rYx7RrVS2HA

# Admin deletes keys for multiple users
curl -u admin:password -X DELETE \
  http://your-server:8080/users/alice,bob/ssh-keys/SHA256:hSZQXa36JqMa2L3TRhc0t6RHSXVO3gy6rYx7RrVS2HA
```

---

#### Delete All SSH Keys for Users (Admin)

Delete all SSH keys for one or more users. Requires admin privileges.

**Endpoint**: `DELETE /users/:sAMAccountNames/ssh-keys`
**Authentication**: Required (admin)
**Response Formats**: text/plain, application/json

**Path Parameters**:
- `sAMAccountNames`: Single user or comma-separated list

**Authorization**:
- Authenticated user must be in admin LDAP group

**Response (application/json)**:
```json
{
  "success": true
}
```

**Status Codes**:
- `200 OK`: Keys deleted successfully
- `401 Unauthorized`: Authentication failed
- `403 Forbidden`: Not in admin group
- `404 Not Found`: One or more users not found
- `500 Internal Server Error`: Deletion failed

**Example**:
```bash
# Delete all keys for multiple users
curl -u admin:password -X DELETE \
  http://your-server:8080/users/alice,bob,charlie/ssh-keys
```

---

## Response Formats

### Content Negotiation

Raybeam supports two response formats based on the `Accept` header:

**text/plain (default)**:
- Used when `Accept` header is not set or set to `text/plain`
- Returns SSH keys in authorized_keys format
- Ideal for direct use with SSH: `curl http://server/users/alice/ssh-keys >> ~/.ssh/authorized_keys`

**application/json**:
- Used when `Accept: application/json` header is present
- Returns structured JSON with success status and data/error fields
- Ideal for programmatic API consumption

### Error Responses

#### text/plain Format

```
authorization header not found
```

#### application/json Format

```json
{
  "success": false,
  "error": "authorization header not found"
}
```

### Common Error Messages

| Message | Meaning |
|---------|---------|
| `authorization header not found` | Basic Auth header missing |
| `authorization was not in the format of 'username:password'` | Malformed Basic Auth header |
| `authorization failed` | Invalid LDAP credentials or user not found |
| `not in admin group` | User authenticated but not in admin group |
| `user "<sAMAccountName>" not found` | Specified user doesn't exist in LDAP |
| `ssh key not found` | Specified fingerprint doesn't exist for user |
| `could not parse SSH key` | Invalid SSH public key format |
| `SSH key already uploaded` | Key with same fingerprint already exists |
| `internal server error` | Database or LDAP communication error |

---

## Common Workflows

### Initial Setup for User

```bash
# 1. Upload your SSH public key
curl -u alice:password -T ~/.ssh/id_rsa.pub \
  http://your-server:8080/users/@me/ssh-keys

# 2. Verify upload
curl -u alice:password http://your-server:8080/users/@me/ssh-keys
```

### Retrieving Keys for SSH Configuration

```bash
# Add to authorized_keys directly
curl http://your-server:8080/users/alice/ssh-keys >> ~/.ssh/authorized_keys

# Or for multiple users (e.g., team access)
curl http://your-server:8080/users/alice,bob,charlie/ssh-keys >> ~/.ssh/authorized_keys
```

### Key Rotation

```bash
# 1. Generate new key pair
ssh-keygen -t ed25519 -f ~/.ssh/id_new

# 2. Upload new key
curl -u alice:password -T ~/.ssh/id_new.pub \
  http://your-server:8080/users/@me/ssh-keys

# 3. Test new key access
ssh -i ~/.ssh/id_new user@target-server

# 4. Delete old key
OLD_FP=$(ssh-keygen -l -E sha256 -f ~/.ssh/id_rsa.pub | awk '{print $2}')
curl -u alice:password -X DELETE \
  http://your-server:8080/users/@me/ssh-keys/$OLD_FP
```

### Admin Bulk Operations

```bash
# Upload same key for multiple users
curl -u admin:password -T team_key.pub \
  http://your-server:8080/users/alice,bob,charlie/ssh-keys

# Remove all keys for departing team members
curl -u admin:password -X DELETE \
  http://your-server:8080/users/former_employee1,former_employee2/ssh-keys
```

---

## Rate Limiting

Raybeam does not currently implement rate limiting. Consider using a reverse proxy (nginx, Traefik) for rate limiting in production deployments.

## HTTPS Recommendations

Raybeam does not provide built-in TLS/HTTPS support. In production:
1. Deploy behind a TLS-terminating reverse proxy (nginx, Traefik, Caddy)
2. Never expose Basic Auth over unencrypted HTTP in production
3. Consider using mTLS for additional security

## API Versioning

Raybeam does not currently implement API versioning. The API is considered stable but may evolve in future releases. Check the `/info` endpoint for current version.