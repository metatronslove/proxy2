# Generate CA key and certificate
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=proxy2 CA"

# Generate wildcard certificate key
openssl genrsa -out cert.key 2048

# Create directory for per-host certificates
New-Item -ItemType Directory -Force -Path certs
Write-Host "Certificate generation complete." -ForegroundColor Green
