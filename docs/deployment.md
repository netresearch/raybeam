# Raybeam Deployment Guide

## Overview

This guide covers deploying Raybeam in various environments, from development to production. Raybeam is distributed as a single static binary and Docker container, making deployment straightforward.

## Prerequisites

### Required

- **LDAP Server**: Active Directory or OpenLDAP
  - Read-only service account
  - User base DN configured
  - Admin group created

- **Container Runtime** (Docker deployment):
  - Docker 20.10+ or compatible
  - Docker Compose 2.0+ (recommended)

- **Storage**:
  - Persistent volume for BoltDB file
  - Minimum 100MB (grows with key count)

### Recommended

- **Reverse Proxy**: Traefik, nginx, or Caddy
  - TLS/HTTPS termination
  - Rate limiting
  - Access logging

- **Monitoring**: Prometheus + Grafana
  - Application metrics
  - Infrastructure metrics

## Quick Start

### Docker Run

```bash
docker run -d \
  --name raybeam \
  -p 8080:8080 \
  -v /var/lib/raybeam:/db \
  ghcr.io/netresearch/raybeam:latest \
  raybeam serve \
    -d /db/db.bolt \
    -s ldap://ldap.example.com:389 \
    -b "DC=example,DC=com" \
    -u "CN=readonly,DC=example,DC=com" \
    -p "readonly_password" \
    -g "CN=Raybeam Admins,OU=Groups,DC=example,DC=com"
```

### Docker Compose (Recommended)

Create `docker-compose.yml`:

```yaml
version: "3.8"

services:
  raybeam:
    image: ghcr.io/netresearch/raybeam:latest
    container_name: raybeam
    restart: unless-stopped
    command:
      - "raybeam"
      - "serve"
      - "-d"
      - "/raybeam/data/db.bolt"
      - "-s"
      - "ldap://ldap.example.com:389"
      - "-b"
      - "DC=example,DC=com"
      - "-u"
      - "readonly"
      - "-p"
      - "${LDAP_PASSWORD}"
      - "-g"
      - "CN=Raybeam Admins,OU=Groups,DC=example,DC=com"
    volumes:
      - raybeam-data:/raybeam/data
    ports:
      - "8080:8080"
    environment:
      - TZ=UTC
    networks:
      - traefik

volumes:
  raybeam-data:
    driver: local

networks:
  traefik:
    external: true
```

Create `.env`:

```bash
LDAP_PASSWORD=your_secure_password
```

Start:

```bash
docker compose up -d
```

## Configuration

### Command-Line Flags

| Flag | Short | Required | Default | Description |
|------|-------|----------|---------|-------------|
| `--http-address` | `-l` | No | `:8080` | HTTP listen address |
| `--ldap-server` | `-s` | Yes | - | LDAP server URL |
| `--ldap-base-dn` | `-b` | No | `dc=example,dc=com` | LDAP base DN |
| `--database` | `-d` | No | `./db.bolt` | BoltDB file path |
| `--ldap-read-user` | `-u` | Yes | - | LDAP read-only user |
| `--ldap-read-password` | `-p` | Yes | - | LDAP read-only password |
| `--ldap-admin-group-dn` | `-g` | Yes | - | LDAP admin group DN |
| `--ldap-is-ad` | - | No | `false` | Enable Active Directory mode |

### LDAP Server URL Format

```
ldap://hostname:port    # Plain LDAP (development only)
ldaps://hostname:port   # LDAP over TLS (production)
```

**Examples**:
```bash
# Plain LDAP (port 389)
-s ldap://ldap.example.com:389

# LDAP over TLS (port 636)
-s ldaps://ldap.example.com:636

# Active Directory
-s ldap://dc1.corp.example.com:389 --ldap-is-ad
```

### LDAP Base DN

The Base DN defines where to start searching for users.

**Examples**:

```bash
# Standard
-b "DC=example,DC=com"

# With OU
-b "OU=Users,DC=example,DC=com"

# Active Directory with multiple DCs
-b "DC=corp,DC=example,DC=com"
```

### Admin Group DN

The exact DN of the LDAP group whose members have admin privileges.

**Examples**:

```bash
# Standard LDAP
-g "cn=raybeam-admins,ou=groups,dc=example,dc=com"

# Active Directory
-g "CN=Raybeam Admins,OU=Security Groups,DC=corp,DC=example,DC=com"
```

**Finding Your Admin Group DN**:

```bash
# LDAP
ldapsearch -x -H ldap://ldap.example.com \
  -D "cn=admin,dc=example,dc=com" \
  -W -b "dc=example,dc=com" \
  "(cn=raybeam-admins)"

# Active Directory
dsquery group -name "Raybeam Admins"
```

## Production Deployment

### With Traefik (Recommended)

`docker-compose.yml`:

```yaml
version: "3.8"

services:
  raybeam:
    image: ghcr.io/netresearch/raybeam:latest
    container_name: raybeam
    restart: unless-stopped
    command:
      - "raybeam"
      - "serve"
      - "-d"
      - "/raybeam/data/db.bolt"
      - "-s"
      - "${LDAP_SERVER}"
      - "-b"
      - "${LDAP_BASE_DN}"
      - "-u"
      - "${LDAP_READ_USER}"
      - "-p"
      - "${LDAP_READ_PASSWORD}"
      - "-g"
      - "${LDAP_ADMIN_GROUP_DN}"
    volumes:
      - raybeam-data:/raybeam/data
    networks:
      - traefik
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.raybeam.rule=Host(`raybeam.example.com`)"
      - "traefik.http.routers.raybeam.entrypoints=websecure"
      - "traefik.http.routers.raybeam.tls=true"
      - "traefik.http.routers.raybeam.tls.certresolver=letsencrypt"
      - "traefik.http.services.raybeam.loadbalancer.server.port=8080"
      # Rate limiting
      - "traefik.http.middlewares.raybeam-ratelimit.ratelimit.average=100"
      - "traefik.http.middlewares.raybeam-ratelimit.ratelimit.burst=50"
      - "traefik.http.routers.raybeam.middlewares=raybeam-ratelimit"

volumes:
  raybeam-data:
    driver: local

networks:
  traefik:
    external: true
```

`.env`:

```bash
LDAP_SERVER=ldaps://ldap.example.com:636
LDAP_BASE_DN=DC=example,DC=com
LDAP_READ_USER=CN=readonly,DC=example,DC=com
LDAP_READ_PASSWORD=your_secure_password
LDAP_ADMIN_GROUP_DN=CN=Raybeam Admins,OU=Groups,DC=example,DC=com
```

### With nginx

`nginx.conf`:

```nginx
upstream raybeam {
    server 127.0.0.1:8080;
}

# Rate limiting
limit_req_zone $binary_remote_addr zone=raybeam_auth:10m rate=10r/m;
limit_req_zone $binary_remote_addr zone=raybeam_general:10m rate=100r/m;

server {
    listen 443 ssl http2;
    server_name raybeam.example.com;

    # TLS configuration
    ssl_certificate /etc/ssl/certs/raybeam.example.com.crt;
    ssl_certificate_key /etc/ssl/private/raybeam.example.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;

    # Logging
    access_log /var/log/nginx/raybeam_access.log combined;
    error_log /var/log/nginx/raybeam_error.log warn;

    # Rate limiting for auth operations
    location ~ ^/users/(@me|[^/]+)/ssh-keys {
        if ($request_method ~* "(PUT|DELETE|POST)") {
            set $rate_limit_auth 1;
        }
    }

    location / {
        # Apply auth rate limiting
        if ($rate_limit_auth) {
            limit_req zone=raybeam_auth burst=20 nodelay;
        }
        # Apply general rate limiting
        limit_req zone=raybeam_general burst=200 nodelay;

        proxy_pass http://raybeam;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name raybeam.example.com;
    return 301 https://$server_name$request_uri;
}
```

## Binary Deployment

### Download

```bash
# Linux amd64
wget https://github.com/netresearch/raybeam/releases/latest/download/raybeam-linux-amd64

# macOS amd64
wget https://github.com/netresearch/raybeam/releases/latest/download/raybeam-darwin-amd64

# Make executable
chmod +x raybeam-*
sudo mv raybeam-* /usr/local/bin/raybeam
```

### Systemd Service

`/etc/systemd/system/raybeam.service`:

```ini
[Unit]
Description=Raybeam SSH Key Store
After=network.target

[Service]
Type=simple
User=raybeam
Group=raybeam
WorkingDirectory=/var/lib/raybeam

ExecStart=/usr/local/bin/raybeam serve \
  -d /var/lib/raybeam/db.bolt \
  -s ldaps://ldap.example.com:636 \
  -b "DC=example,DC=com" \
  -u "CN=readonly,DC=example,DC=com" \
  -p "${LDAP_PASSWORD}" \
  -g "CN=Raybeam Admins,OU=Groups,DC=example,DC=com"

Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/raybeam

[Install]
WantedBy=multi-user.target
```

Environment file `/etc/raybeam/env`:

```bash
LDAP_PASSWORD=your_secure_password
```

Enable and start:

```bash
# Create user
sudo useradd -r -s /bin/false raybeam

# Create data directory
sudo mkdir -p /var/lib/raybeam
sudo chown raybeam:raybeam /var/lib/raybeam
sudo chmod 700 /var/lib/raybeam

# Load environment
sudo mkdir -p /etc/raybeam
echo "LDAP_PASSWORD=your_password" | sudo tee /etc/raybeam/env
sudo chmod 600 /etc/raybeam/env

# Enable service
sudo systemctl daemon-reload
sudo systemctl enable raybeam
sudo systemctl start raybeam

# Check status
sudo systemctl status raybeam
```

## Kubernetes Deployment

### Deployment YAML

`raybeam-deployment.yaml`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: raybeam-ldap
  namespace: default
type: Opaque
stringData:
  ldap-password: "your_secure_password"
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: raybeam-data
  namespace: default
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: raybeam
  namespace: default
spec:
  replicas: 1  # BoltDB limitation: single writer
  selector:
    matchLabels:
      app: raybeam
  template:
    metadata:
      labels:
        app: raybeam
    spec:
      containers:
      - name: raybeam
        image: ghcr.io/netresearch/raybeam:latest
        args:
          - "raybeam"
          - "serve"
          - "-d"
          - "/raybeam/data/db.bolt"
          - "-s"
          - "ldaps://ldap.example.com:636"
          - "-b"
          - "DC=example,DC=com"
          - "-u"
          - "CN=readonly,DC=example,DC=com"
          - "-p"
          - "$(LDAP_PASSWORD)"
          - "-g"
          - "CN=Raybeam Admins,OU=Groups,DC=example,DC=com"
        env:
          - name: LDAP_PASSWORD
            valueFrom:
              secretKeyRef:
                name: raybeam-ldap
                key: ldap-password
        ports:
          - containerPort: 8080
            name: http
        volumeMounts:
          - name: data
            mountPath: /raybeam/data
        livenessProbe:
          httpGet:
            path: /info
            port: http
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /info
            port: http
          initialDelaySeconds: 5
          periodSeconds: 10
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 256Mi
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: raybeam-data
---
apiVersion: v1
kind: Service
metadata:
  name: raybeam
  namespace: default
spec:
  selector:
    app: raybeam
  ports:
    - port: 80
      targetPort: http
      protocol: TCP
      name: http
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: raybeam
  namespace: default
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/rate-limit: "100"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - raybeam.example.com
      secretName: raybeam-tls
  rules:
    - host: raybeam.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: raybeam
                port:
                  name: http
```

Apply:

```bash
kubectl apply -f raybeam-deployment.yaml
```

## Backup and Recovery

### Backup BoltDB

```bash
# Hot backup (safe while Raybeam is running)
#!/bin/bash
BACKUP_DIR=/backup/raybeam
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

mkdir -p $BACKUP_DIR
docker exec raybeam cat /raybeam/data/db.bolt > $BACKUP_DIR/db-$TIMESTAMP.bolt
chmod 600 $BACKUP_DIR/db-$TIMESTAMP.bolt

# Keep last 30 days
find $BACKUP_DIR -name "db-*.bolt" -mtime +30 -delete
```

**Automated Backups**:

Crontab entry:

```cron
# Daily backup at 2 AM
0 2 * * * /usr/local/bin/raybeam-backup.sh
```

### Restore from Backup

```bash
# Stop Raybeam
docker compose stop raybeam

# Restore backup
docker cp /backup/raybeam/db-20250929-020000.bolt raybeam:/raybeam/data/db.bolt

# Start Raybeam
docker compose start raybeam

# Verify
curl http://localhost:8080/info
```

## Monitoring

### Health Check

```bash
# HTTP health check
curl http://localhost:8080/info
```

Expected response:

```json
{
  "version": "c95e75c",
  "source": "https://github.com/netresearch/raybeam"
}
```

### Prometheus Metrics

Raybeam does not currently expose Prometheus metrics. Use reverse proxy metrics:

**nginx Prometheus Exporter**:

```bash
# Install nginx-prometheus-exporter
docker run -d \
  --name nginx-exporter \
  -p 9113:9113 \
  nginx/nginx-prometheus-exporter:latest \
  -nginx.scrape-uri=http://nginx:8080/stub_status
```

**Traefik Metrics**:

```yaml
# traefik.yml
metrics:
  prometheus:
    entryPoint: metrics
    addEntryPointsLabels: true
    addServicesLabels: true
```

### Log Monitoring

**Raybeam Logs**:

```bash
# Docker logs
docker logs -f raybeam

# Kubernetes logs
kubectl logs -f deployment/raybeam
```

**Log Format** (Fiber logger):

```
[INFO] 2025-09-29 10:15:30 | 200 |  125ms | GET  | /users/alice/ssh-keys
[WARN] 2025-09-29 10:15:45 | 401 |  250ms | POST | /users/@me/ssh-keys
```

**Log Aggregation**:

Ship logs to:
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Loki + Grafana
- Datadog
- Splunk

## Troubleshooting

### Connection Issues

**Problem**: Cannot reach Raybeam

```bash
# Check if container is running
docker ps | grep raybeam

# Check logs
docker logs raybeam

# Test locally
docker exec raybeam wget -O- http://localhost:8080/info
```

### LDAP Authentication Failures

**Problem**: All authentication fails with 401

```bash
# Test LDAP connectivity
docker exec raybeam sh -c "nc -zv ldap.example.com 389"

# Check LDAP credentials
ldapsearch -x -H ldap://ldap.example.com \
  -D "CN=readonly,DC=example,DC=com" \
  -w "password" \
  -b "DC=example,DC=com" \
  "(objectClass=user)"
```

**Common Issues**:
- Incorrect LDAP server URL
- Wrong Base DN
- Invalid service account credentials
- Firewall blocking LDAP ports (389, 636)

### Database Issues

**Problem**: Database errors or corruption

```bash
# Check database file permissions
ls -l /var/lib/raybeam/db.bolt
# Should be: -rw------- raybeam raybeam

# Check disk space
df -h /var/lib/raybeam

# Restore from backup if corrupted
docker compose stop raybeam
docker cp /backup/raybeam/db-latest.bolt raybeam:/raybeam/data/db.bolt
docker compose start raybeam
```

### Admin Authorization Issues

**Problem**: User authenticated but not recognized as admin

```bash
# Verify user's group membership
ldapsearch -x -H ldap://ldap.example.com \
  -D "CN=readonly,DC=example,DC=com" \
  -w "password" \
  -b "DC=example,DC=com" \
  "(sAMAccountName=alice)" \
  memberOf

# Check admin group DN matches exactly
# Raybeam logs should show: "not in admin group"
```

**Solution**: Ensure user is member of group with exact DN specified in `-g` flag

## Performance Tuning

### BoltDB Optimization

BoltDB performance is primarily I/O bound:

- Use SSD/NVMe storage
- Enable filesystem caching
- Consider RAID for throughput

**Storage Requirements**:

```
Estimated size = (average_key_size + overhead) × total_keys
Example: (600 bytes + 100 bytes) × 10,000 keys = ~7 MB
```

### Resource Allocation

**Minimum**:
- CPU: 0.1 cores (100m)
- Memory: 64 MB
- Storage: 100 MB

**Recommended**:
- CPU: 0.5 cores (500m)
- Memory: 256 MB
- Storage: 1 GB

**High Load**:
- CPU: 1-2 cores
- Memory: 512 MB
- Storage: 5 GB

### Scaling Strategies

**Vertical Scaling** (Recommended):
- Increase CPU for LDAP query processing
- Increase memory for BoltDB caching
- Faster storage for write performance

**Horizontal Scaling** (Limited):
- BoltDB single-writer limitation
- Consider read replicas with file replication
- Migrate to PostgreSQL for true horizontal scaling

## Security Hardening

See [Security Documentation](security.md) for comprehensive security guidance.

**Quick Checklist**:
- [ ] Deploy behind HTTPS/TLS
- [ ] Use ldaps:// for LDAP
- [ ] Configure rate limiting
- [ ] Set up firewall rules
- [ ] Enable access logging
- [ ] Implement monitoring
- [ ] Configure encrypted backups
- [ ] Review file permissions

## Upgrade Process

### Docker Upgrade

```bash
# Pull latest image
docker pull ghcr.io/netresearch/raybeam:latest

# Stop current container
docker compose stop raybeam

# Backup database
docker exec raybeam cat /raybeam/data/db.bolt > /backup/pre-upgrade.bolt

# Restart with new image
docker compose up -d raybeam

# Verify
curl http://localhost:8080/info
```

### Binary Upgrade

```bash
# Backup current binary
sudo cp /usr/local/bin/raybeam /usr/local/bin/raybeam.old

# Download new version
wget https://github.com/netresearch/raybeam/releases/latest/download/raybeam-linux-amd64
chmod +x raybeam-linux-amd64

# Stop service
sudo systemctl stop raybeam

# Backup database
sudo cp /var/lib/raybeam/db.bolt /backup/pre-upgrade.bolt

# Install new binary
sudo mv raybeam-linux-amd64 /usr/local/bin/raybeam

# Start service
sudo systemctl start raybeam

# Verify
curl http://localhost:8080/info
```

## Multi-Environment Deployment

### Development

```yaml
# docker-compose.dev.yml
services:
  raybeam:
    image: ghcr.io/netresearch/raybeam:latest
    ports:
      - "8080:8080"
    command:
      - "raybeam"
      - "serve"
      - "-d"
      - "/tmp/db.bolt"
      - "-s"
      - "ldap://openldap:389"
      - "-b"
      - "dc=example,dc=org"
      - "-u"
      - "cn=admin,dc=example,dc=org"
      - "-p"
      - "admin"
      - "-g"
      - "cn=admins,dc=example,dc=org"
```

### Staging

```yaml
# docker-compose.staging.yml
services:
  raybeam:
    image: ghcr.io/netresearch/raybeam:v1.2.3  # Pinned version
    networks:
      - staging-traefik
    labels:
      - "traefik.http.routers.raybeam-staging.rule=Host(`raybeam-staging.example.com`)"
```

### Production

```yaml
# docker-compose.prod.yml
services:
  raybeam:
    image: ghcr.io/netresearch/raybeam:v1.2.3  # Pinned version
    restart: always
    networks:
      - prod-traefik
    labels:
      - "traefik.http.routers.raybeam.rule=Host(`raybeam.example.com`)"
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
```

## References

- [Docker Documentation](https://docs.docker.com/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Traefik Documentation](https://doc.traefik.io/traefik/)
- [nginx Documentation](https://nginx.org/en/docs/)
- [BoltDB Documentation](https://github.com/etcd-io/bbolt)