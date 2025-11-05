# Local Development Setup

## Quick Start

### 1. Copy the example environment file

```bash
cp .env.example .env
```

### 2. Generate an Ed25519 signing key

```bash
scripts/generate-ed25519-key.sh > pbcopy
```

Paste the output (copied to clipboard by `pbcopy` above) in `.env`:

```bash
EASYOIDC_SIGNING_KEY='-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEI...
-----END PRIVATE KEY-----'
```

### 3. Create a Google OAuth App

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create OAuth 2.0 Client ID
3. Set authorized redirect URI: `http://localhost:8080/callback/google`
4. Copy Client ID and Client Secret to `.env`:

```bash
EASYOIDC_OAUTH_CLIENT_ID=123456789.apps.googleusercontent.com
EASYOIDC_OAUTH_CLIENT_SECRET=GOCSPX-xxxxxxxxxxxxxxxxxxxxx
```

### 4. Run easy-oidc

```bash
# Load environment variables (if using direnv or similar)
export $(cat .env | xargs)

# Run the server with the example local development config
./bin/easy-oidc --config examples/config/config-local-dev.jsonc --debug
```

### 5. Test with kubelogin

```bash
# In another terminal
kubectl oidc-login setup \
  --oidc-issuer-url=http://localhost:8080 \
  --oidc-client-id=kubelogin-local \
  --oidc-extra-scope=email \
  --oidc-extra-scope=groups
```

## Environment Variables

The `.env` file should contain:

- `EASYOIDC_SIGNING_KEY` - Ed25519 private key in PEM format
- `EASYOIDC_OAUTH_CLIENT_ID` - OAuth client ID from Google/GitHub
- `EASYOIDC_OAUTH_CLIENT_SECRET` - OAuth client secret from Google/GitHub

**Important:** Do not commit `.env` to version control! It's already ignored in `.gitignore`.

## Alternative: Using direnv

For automatic environment loading:

```bash
# Install direnv
brew install direnv  # macOS

# Create .envrc
echo 'dotenv' > .envrc
direnv allow

# Now .env is automatically loaded when you cd into this directory
```

## Troubleshooting

**"environment variable not set" error:**
- Make sure you've exported the variables: `export $(cat .env | xargs)`
- Or use a tool like `direnv` for automatic loading

**"email not verified" error:**
- Make sure your Google account email is verified
- Check the email in your Google profile

**"unknown client_id" error:**
- Make sure the client_id in the kubelogin command matches the config file
