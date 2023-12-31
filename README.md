# Raybeam

Raybeam is a simple public key store written in [Go](https://go.dev/) and currently only supports storing SSH public
keys.

## Usage

> ℹ️ You may replace the `<LDAP sAMAccountName>` in URLs with `@me` to access the currently authenticated user. **You
> can only upload and delete keys for the currently authenticated user (unless you are in the administrator LDAP group).**

> ℹ️ You can also replace the `<LDAP sAMAccountName>` in URLs with multiple sAMAccountNames separated by commas to
> access multiple users at once. **You can only upload and delete keys for the currently authenticated user (unless you
> are in the administrator LDAP group).**

- SSH public keys:

  > ️️ℹ️ A fingerprint of a public key looks like this `SHA256:hSZQXa36JqMa2L3TRhc0t6RHSXVO3gy6rYx7RrVS2HA` and can be
  > generated with `ssh-keygen -l -E sha256 -f <path to public key file>`.

  - List all keys for a user:
    ```bash
    curl http://localhost:8080/users/<LDAP sAMAccountName>/ssh-keys
    ```
  - Upload a key:
    ```bash
    curl -T ~/.ssh/id_rsa.pub -u <LDAP sAMAccountName> http://localhost:8080/users/<LDAP sAMAccountName>/ssh-keys
    ```
  - Delete all keys of a user:
    ```bash
    curl -X DELETE -u <LDAP sAMAccountName> http://localhost:8080/users/<LDAP sAMAccountName>/ssh-keys
    ```
  - Get a specific key of a user:
    ```bash
    curl http://localhost:8080/users/<LDAP sAMAccountName>/ssh-keys/<SHA256 fingerprint>
    ```
  - Delete a key of a user:
    ```bash
    curl -X DELETE -u <LDAP sAMAccountName> http://localhost:8080/users/<LDAP sAMAccountName>/ssh-keys/<SHA256 fingerprint>
    ```

### Responses

By default, all responses will be in plain text (`text/plain`). You can request JSON responses by setting the
`Accept` header to `application/json`. This is done to make it easier to use the API in scripts.

## Running a Raybeam server

In order to run Raybeam, you have to have [Docker](https://www.docker.com/) installed and an LDAP server running.

```bash
docker run -it -v $PWD/db.bolt:/db.bolt -p 8080:8080 ghcr.io/netresearch/raybeam raybeam serve -s ldap://localhost:389 -b ou=users,dc=example,dc=com -u readonly -p readonly -g cn=Admin,ou=groups,dc=example,dc=com
```

> ℹ️ The database by default lives at `/db.bolt`.

## Deploying Raybeam

### Docker

There is a Docker image available at `ghcr.io/netresearch/raybeam`.

### Docker Compose

You can deploy Raybeam with Docker Compose using the following example `docker-compose.yml` file:

```yml
version: "3"

services:
  raybeam:
    image: "ghcr.io/netresearch/raybeam:latest"
    restart: unless-stopped
    command:
      - "raybeam"
      - "serve"
      - "-d"
      - "/raybeam/data/db.bolt"
      - "-s"
      - "ldap://localhost:389"
      - "-b"
      - "DC=example,DC=com"
      - "-u"
      - "readonly"
      - "-p"
      - "readonly"
      - "-g"
      - "CN=Raybeam Admins,OU=Groups,DC=example,DC=com"
    volumes:
      - "/var/lib/raybeam:/raybeam/data"
    ports:
      - "8080:8080"
```

#### Ansible

You can deploy the Raybeam container with Ansible using the following variable when using [netresearch.docker_containers](https://github.com/netresearch/ansible_role_docker_containers):

```yaml
netresearch_docker_containers:
  - name: "raybeam"
    image: "ghcr.io/netresearch/raybeam:latest"
    command:
      - "raybeam"
      - "serve"
      - "-d"
      - "/raybeam/data/db.bolt"
      - "-s"
      - "ldap://localhost:389"
      - "-b"
      - "DC=example,DC=com"
      - "-u"
      - "readonly"
      - "-p"
      - "readonly"
      - "-g"
      - "CN=Raybeam Admins,OU=Groups,DC=example,DC=com"
    networks:
      - name: "traefik_network"
    mounts:
      - type: bind
        source: "/var/lib/raybeam"
        target: "/raybeam/data"
    ports:
      - "8080:8080"
    labels: "{{ raybeam_container_labels }}"
    restart_policy: unless-stopped
```

> ℹ For more information, please refer to the [documentation of netresearch.docker_containers](https://github.com/netresearch/ansible_role_docker_containers#container-definition).

## License

Raybeam is licensed under the MIT license, for more information please refer to the [included LICENSE file](LICENSE).
