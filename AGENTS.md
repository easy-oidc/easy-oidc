# AGENTS.md

This file contains guidance for AI coding agents working on the easy-oidc project.

## Frequently Used Commands

### Build
```bash
make build          # Build the binary
make clean          # Clean build artifacts
```

### Testing
```bash
make test           # Run all tests with race detector
go test ./...       # Run tests
go test -v ./...    # Run tests verbosely
make e2e            # Run E2E test with Dex container as upstream
```

### Code Quality
```bash
make fmt            # Format code
make lint           # Run linter
make check          # Run fmt, lint, and test
```

### Development
```bash
# Run locally with example config
./bin/easy-oidc --config examples/config/config-local-dev.jsonc --debug

# Validate configuration
./bin/easy-oidc --config config.jsonc --validate

# Show version
./bin/easy-oidc --version
```

## Project Structure

```
.
├── cmd/easy-oidc/          # Main entry point
├── internal/
│   ├── buildvars/          # Build version info
│   ├── cmd/                # Cobra CLI commands
│   ├── config/             # Configuration loading and validation
│   ├── secrets/            # Secrets providers (AWS, GCP, Azure, env)
│   ├── oidc/               # OIDC server and handlers
│   ├── upstream/           # Google/GitHub connectors
│   └── tokens/             # Token signing, JWKS, groups
├── examples/               # Example configs and deployment files
└── scripts/                # Helper scripts
```

## Code Conventions

- Use `slog` for structured logging
- All errors should be wrapped with context using `fmt.Errorf`
- Configuration validation happens at startup
- Secrets are loaded once at startup (not on every request)
- Email addresses are always normalized to lowercase
- PKCE is mandatory for all clients
- No client secrets (public clients only)

## Key Design Decisions

- **Ed25519 signing only**: State-of-the-art, fast signing for ID tokens
- **Stateless auth codes**: Signed JWTs with ephemeral secret
- **No sessions or cookies**: OAuth state and auth codes are self-contained
- **Ephemeral secrets**: Generated at startup for state/auth codes
- **Email as `sub` claim**: Human-readable, stable across IdP changes
- **Single-use auth codes**: In-memory cache with expiry

## Upstream Connectors

easy-oidc supports multiple upstream OAuth2/OIDC providers:

- **Google**: Built-in Google OAuth2 with hosted domain support
- **GitHub**: Built-in GitHub OAuth2 with GitHub Enterprise support
- **Generic**: Generic OAuth2/OIDC provider support for Dex, Keycloak, Auth0, etc.

## Dependencies

- `github.com/lestrrat-go/jwx/v2` - JWT/JWK/JWKS handling
- `golang.org/x/oauth2` - OAuth2 client for Google/GitHub
- `github.com/tidwall/jsonc` - JSONC config parsing
- `github.com/spf13/cobra` - CLI framework
- Cloud SDKs for secrets management (AWS, GCP, Azure)

## Adding New Features

When adding features:
1. Update config types in `internal/config/types.go`
2. Add validation in `internal/config/loader.go`
3. Write tests for new functionality
4. Update example configs in `examples/config/`
5. Run `make check` before committing
