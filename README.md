# 🔐 Azure Key Vault - Complete Guide

> **Your comprehensive guide to secure secrets management across .NET, Java, Python, and CI/CD pipelines**

---

## 📑 Table of Contents

- [Overview](#-overview)
- [.NET Implementation](#-net-implementation)
- [Java Implementation](#-java-implementation)
- [Python Implementation](#-python-implementation)
- [CI/CD Pipeline Integration](#-cicd-pipeline-integration)
- [Security Certificates](#-security-certificates-management)
- [Common Issues & Solutions](#-common-issues--solutions)
- [Best Practices](#-best-practices)

---

## 🎯 Overview

Azure Key Vault is a cloud service for securely storing and accessing secrets, keys, and certificates. It helps solve the following problems:

**What you can store:**
- API keys and connection strings
- Passwords and secrets
- Certificates (SSL/TLS)
- Cryptographic keys

**Key Benefits:**
- Centralized secrets management
- Access control with Azure AD
- Audit logging
- Automatic certificate renewal
- Hardware Security Module (HSM) backed keys

---

## 💻 .NET Implementation

### Installation

```bash
dotnet add package Azure.Identity
dotnet add package Azure.Security.KeyVault.Secrets
dotnet add package Azure.Security.KeyVault.Certificates
```

### Basic Usage

```csharp
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

// Create a client using DefaultAzureCredential
var keyVaultUrl = "https://your-keyvault-name.vault.azure.net/";
var client = new SecretClient(new Uri(keyVaultUrl), new DefaultAzureCredential());

// Retrieve a secret
KeyVaultSecret secret = await client.GetSecretAsync("DatabasePassword");
string secretValue = secret.Value;

Console.WriteLine($"Retrieved secret: {secretValue}");
```

### ASP.NET Core Integration

```csharp
// Program.cs
using Azure.Identity;

var builder = WebApplication.CreateBuilder(args);

// Add Azure Key Vault to configuration
var keyVaultUrl = builder.Configuration["KeyVaultUrl"];
builder.Configuration.AddAzureKeyVault(
    new Uri(keyVaultUrl),
    new DefaultAzureCredential());

var app = builder.Build();

// Access secrets from configuration
var dbPassword = builder.Configuration["DatabasePassword"];
```

### appsettings.json

```json
{
  "KeyVaultUrl": "https://your-keyvault-name.vault.azure.net/",
  "Logging": {
    "LogLevel": {
      "Default": "Information"
    }
  }
}
```

---

## ☕ Java Implementation

### Maven Dependencies

```xml
<dependencies>
    <dependency>
        <groupId>com.azure</groupId>
        <artifactId>azure-security-keyvault-secrets</artifactId>
        <version>4.6.0</version>
    </dependency>
    <dependency>
        <groupId>com.azure</groupId>
        <artifactId>azure-identity</artifactId>
        <version>1.10.0</version>
    </dependency>
</dependencies>
```

### Basic Usage

```java
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;

public class KeyVaultExample {
    public static void main(String[] args) {
        String keyVaultUrl = "https://your-keyvault-name.vault.azure.net/";
        
        // Create a secret client
        SecretClient secretClient = new SecretClientBuilder()
            .vaultUrl(keyVaultUrl)
            .credential(new DefaultAzureCredentialBuilder().build())
            .buildClient();
        
        // Retrieve a secret
        KeyVaultSecret secret = secretClient.getSecret("DatabasePassword");
        System.out.println("Secret value: " + secret.getValue());
    }
}
```

### Spring Boot Integration

```java
// application.properties
azure.keyvault.uri=https://your-keyvault-name.vault.azure.net/

// Configuration class
@Configuration
@ConfigurationProperties("azure.keyvault")
public class KeyVaultConfig {
    private String uri;
    
    @Bean
    public SecretClient secretClient() {
        return new SecretClientBuilder()
            .vaultUrl(uri)
            .credential(new DefaultAzureCredentialBuilder().build())
            .buildClient();
    }
}
```

---

## 🐍 Python Implementation

### Installation

```bash
pip install azure-identity
pip install azure-keyvault-secrets
pip install azure-keyvault-certificates
```

### Basic Usage

```python
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Initialize the Key Vault client
key_vault_url = "https://your-keyvault-name.vault.azure.net/"
credential = DefaultAzureCredential()
client = SecretClient(vault_url=key_vault_url, credential=credential)

# Retrieve a secret
secret = client.get_secret("DatabasePassword")
print(f"Secret value: {secret.value}")

# Set a secret
client.set_secret("NewSecret", "SecretValue123")
```

### Django Integration

```python
# settings.py
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

KEY_VAULT_URL = "https://your-keyvault-name.vault.azure.net/"
credential = DefaultAzureCredential()
secret_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)

# Retrieve secrets
DATABASE_PASSWORD = secret_client.get_secret("DatabasePassword").value
SECRET_KEY = secret_client.get_secret("DjangoSecretKey").value

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'mydb',
        'USER': 'dbuser',
        'PASSWORD': DATABASE_PASSWORD,
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

### Flask Example

```python
from flask import Flask
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

app = Flask(__name__)

# Initialize Key Vault client
key_vault_url = "https://your-keyvault-name.vault.azure.net/"
credential = DefaultAzureCredential()
secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

# Load configuration from Key Vault
app.config['DATABASE_URL'] = secret_client.get_secret("DatabaseUrl").value
app.config['API_KEY'] = secret_client.get_secret("ApiKey").value

@app.route('/')
def hello():
    return "Application configured with Key Vault!"
```

---

## 🔄 CI/CD Pipeline Integration

### Azure DevOps Pipeline

```yaml
# azure-pipelines.yml
trigger:
- main

pool:
  vmImage: 'ubuntu-latest'

variables:
- group: KeyVault-Variables  # Variable group linked to Key Vault

steps:
- task: AzureKeyVault@2
  inputs:
    azureSubscription: 'Your-Service-Connection'
    KeyVaultName: 'your-keyvault-name'
    SecretsFilter: '*'  # Or specify: 'Secret1,Secret2'
    RunAsPreJob: true

- script: |
    echo "Using secret from Key Vault"
    echo "Database Password: $(DatabasePassword)"
  displayName: 'Use Key Vault Secret'

- task: DotNetCoreCLI@2
  inputs:
    command: 'build'
  env:
    ConnectionString: $(DatabaseConnectionString)
```

### GitHub Actions

```yaml
# .github/workflows/deploy.yml
name: Deploy Application

on:
  push:
    branches: [ main ]

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Azure Login
      uses: azure/login@v1
      with:
        creds: ${{ secrets.AZURE_CREDENTIALS }}
    
    - name: Get secrets from Key Vault
      uses: azure/get-keyvault-secrets@v1
      with:
        keyvault: "your-keyvault-name"
        secrets: 'DatabasePassword, ApiKey, ConnectionString'
      id: keyvault
    
    - name: Use secrets in deployment
      run: |
        echo "Database Password retrieved"
        # Use secrets as environment variables
        export DB_PASSWORD="${{ steps.keyvault.outputs.DatabasePassword }}"
        export API_KEY="${{ steps.keyvault.outputs.ApiKey }}"
```

### GitLab CI/CD

```yaml
# .gitlab-ci.yml
variables:
  AZURE_KEYVAULT_NAME: "your-keyvault-name"

stages:
  - build
  - deploy

before_script:
  - az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID
  - export DB_PASSWORD=$(az keyvault secret show --name DatabasePassword --vault-name $AZURE_KEYVAULT_NAME --query value -o tsv)

build:
  stage: build
  script:
    - echo "Building with secrets from Key Vault"
    - dotnet build

deploy:
  stage: deploy
  script:
    - echo "Deploying application"
    - echo "Using database password: $DB_PASSWORD"
```

---

## 🔒 Security Certificates Management

### Importing Certificates

```bash
# Using Azure CLI
az keyvault certificate import \
  --vault-name your-keyvault-name \
  --name MyCertificate \
  --file certificate.pfx \
  --password cert-password
```

### .NET - Retrieve Certificate

```csharp
using Azure.Security.KeyVault.Certificates;

var certificateClient = new CertificateClient(
    new Uri("https://your-keyvault-name.vault.azure.net/"),
    new DefaultAzureCredential());

KeyVaultCertificateWithPolicy certificate = 
    await certificateClient.GetCertificateAsync("MyCertificate");

// Download the certificate with private key
var certWithPrivateKey = await certificateClient
    .DownloadCertificateAsync("MyCertificate");

X509Certificate2 x509Certificate = certWithPrivateKey.Value;
```

### Java - Retrieve Certificate

```java
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;

CertificateClient certificateClient = new CertificateClientBuilder()
    .vaultUrl("https://your-keyvault-name.vault.azure.net/")
    .credential(new DefaultAzureCredentialBuilder().build())
    .buildClient();

KeyVaultCertificateWithPolicy certificate = 
    certificateClient.getCertificate("MyCertificate");
```

### Python - Retrieve Certificate

```python
from azure.keyvault.certificates import CertificateClient

certificate_client = CertificateClient(
    vault_url="https://your-keyvault-name.vault.azure.net/",
    credential=DefaultAzureCredential()
)

certificate = certificate_client.get_certificate("MyCertificate")
print(f"Certificate: {certificate.name}")
```

### Auto-Renewal Configuration

```bash
# Set up auto-renewal for Let's Encrypt or other CA
az keyvault certificate set-attributes \
  --vault-name your-keyvault-name \
  --name MyCertificate \
  --enabled true

# Configure lifecycle actions
az keyvault certificate contact add \
  --vault-name your-keyvault-name \
  --email admin@example.com
```

---

## ⚠️ Common Issues & Solutions

### Issue 1: Access Denied (403 Forbidden)

**Problem:** Application cannot access Key Vault secrets.

**Symptoms:**
```
Azure.RequestFailedException: Access denied
Status: 403 (Forbidden)
```

**Solutions:**

1. **Grant proper permissions:**
```bash
# Assign Key Vault Secrets User role
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee <user-or-service-principal-id> \
  --scope /subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.KeyVault/vaults/<keyvault-name>
```

2. **Or use access policies (legacy):**
```bash
az keyvault set-policy \
  --name your-keyvault-name \
  --object-id <object-id> \
  --secret-permissions get list
```

3. **Enable Managed Identity** for Azure resources (App Service, VMs, etc.)

---

### Issue 2: Authentication Failures with DefaultAzureCredential

**Problem:** `DefaultAzureCredential` cannot authenticate.

**Symptoms:**
```
CredentialUnavailableException: DefaultAzureCredential failed to retrieve a token
```

**Solutions:**

1. **For local development:**
```bash
# Login using Azure CLI
az login

# Or set environment variables
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_TENANT_ID="your-tenant-id"
```

2. **For production, use Managed Identity:**
```csharp
// .NET - Explicitly use Managed Identity
var credential = new ManagedIdentityCredential();
var client = new SecretClient(new Uri(keyVaultUrl), credential);
```

---

### Issue 3: Key Vault Name Resolution Issues

**Problem:** Cannot resolve Key Vault DNS name.

**Symptoms:**
```
No such host is known: your-keyvault-name.vault.azure.net
```

**Solutions:**

1. **Check Key Vault URL format:**
```
Correct: https://your-keyvault-name.vault.azure.net/
Incorrect: https://your-keyvault-name.vault.azure.com/
```

2. **Verify network connectivity:**
```bash
# Test DNS resolution
nslookup your-keyvault-name.vault.azure.net

# Check firewall rules
az keyvault network-rule list --name your-keyvault-name
```

---

### Issue 4: Throttling (429 Too Many Requests)

**Problem:** Too many requests to Key Vault.

**Symptoms:**
```
Status: 429 (TooManyRequests)
Service request failed. Please retry after some time.
```

**Solutions:**

1. **Implement caching:**
```csharp
// Cache secrets in memory
private static Dictionary<string, string> _secretCache = new();

public async Task<string> GetSecretWithCacheAsync(string secretName)
{
    if (_secretCache.ContainsKey(secretName))
        return _secretCache[secretName];
    
    var secret = await _secretClient.GetSecretAsync(secretName);
    _secretCache[secretName] = secret.Value.Value;
    return secret.Value.Value;
}
```

2. **Use exponential backoff:**
```python
import time
from azure.core.exceptions import ResourceExistsError

def get_secret_with_retry(client, secret_name, max_retries=3):
    for attempt in range(max_retries):
        try:
            return client.get_secret(secret_name).value
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
            else:
                raise
```

---

### Issue 5: Certificate Import Failures

**Problem:** Cannot import certificate to Key Vault.

**Symptoms:**
```
The specified PFX is invalid or the password is incorrect
```

**Solutions:**

1. **Verify certificate format:**
```bash
# Check certificate details
openssl pkcs12 -info -in certificate.pfx

# Convert if needed
openssl pkcs12 -export -out certificate.pfx -inkey private.key -in certificate.crt
```

2. **Ensure proper permissions:**
```bash
az keyvault set-policy \
  --name your-keyvault-name \
  --object-id <object-id> \
  --certificate-permissions import get list
```

---

### Issue 6: Soft-Delete Issues

**Problem:** Cannot create a Key Vault or secret with the same name.

**Symptoms:**
```
Conflict: Secret is currently in a deleted but recoverable state
```

**Solutions:**

```bash
# List deleted secrets
az keyvault secret list-deleted --vault-name your-keyvault-name

# Recover deleted secret
az keyvault secret recover --name SecretName --vault-name your-keyvault-name

# Or permanently purge (if soft-delete is enabled)
az keyvault secret purge --name SecretName --vault-name your-keyvault-name
```

---

### Issue 7: Firewall and Virtual Network Issues

**Problem:** Application cannot access Key Vault from specific networks.

**Solutions:**

```bash
# Add your IP to firewall
az keyvault network-rule add \
  --name your-keyvault-name \
  --ip-address <your-ip>

# Add virtual network rule
az keyvault network-rule add \
  --name your-keyvault-name \
  --vnet-name MyVNet \
  --subnet MySubnet

# Allow trusted Azure services
az keyvault update \
  --name your-keyvault-name \
  --bypass AzureServices
```

---

## ✨ Best Practices

### 1. Use Managed Identity
Always prefer Managed Identity over service principals for Azure resources.

### 2. Implement Secret Rotation
```bash
# Set expiration dates
az keyvault secret set \
  --vault-name your-keyvault-name \
  --name MySecret \
  --value "SecretValue" \
  --expires "2025-12-31T23:59:59Z"
```

### 3. Enable Logging and Monitoring
```bash
# Enable diagnostic logging
az monitor diagnostic-settings create \
  --resource <keyvault-resource-id> \
  --name KeyVaultLogs \
  --logs '[{"category": "AuditEvent", "enabled": true}]' \
  --workspace <log-analytics-workspace-id>
```

### 4. Use RBAC over Access Policies
Azure RBAC provides more granular control and is the recommended approach.

### 5. Cache Secrets Appropriately
Don't fetch secrets on every request. Cache them with reasonable TTL.

### 6. Separate Environments
Use different Key Vaults for Development, Staging, and Production.

### 7. Tag Your Resources
```bash
az keyvault update \
  --name your-keyvault-name \
  --tags Environment=Production Team=DevOps
```

### 8. Enable Soft Delete and Purge Protection
```bash
az keyvault create \
  --name your-keyvault-name \
  --resource-group your-rg \
  --enable-soft-delete true \
  --enable-purge-protection true
```

---

## 📚 Additional Resources

- [Azure Key Vault Documentation](https://docs.microsoft.com/azure/key-vault/)
- [Azure Key Vault Best Practices](https://docs.microsoft.com/azure/key-vault/general/best-practices)
- [Managed Identity Documentation](https://docs.microsoft.com/azure/active-directory/managed-identities-azure-resources/)

---

<div align="center">

**Made with ❤️ for Azure developers**

*Last updated: January 2026*

</div>
