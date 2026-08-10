// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxFileSecretBytes = 1 << 20

// FileProvider reads secrets from files below a configured directory.
type FileProvider struct {
	// Keep the root open for the provider lifetime so replacing its path cannot
	// redirect later reads outside the directory opened at startup.
	root *os.Root
}

// NewFileProvider creates a file secrets provider rooted at directory.
func NewFileProvider(directory string) (*FileProvider, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open file secrets directory: %w", err)
	}
	return &FileProvider{root: root}, nil
}

// GetSecret retrieves a non-empty secret file beneath the configured directory.
func (p *FileProvider) GetSecret(ctx context.Context, name string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("read file secret %q: %w", name, err)
	}
	if !filepath.IsLocal(name) {
		return "", fmt.Errorf("file secret name %q must be a local relative path", name)
	}

	file, err := p.root.Open(name)
	if err != nil {
		return "", fmt.Errorf("open file secret %q: %w", name, err)
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat file secret %q: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("file secret %q is not a regular file", name)
	}
	value, err := io.ReadAll(io.LimitReader(file, maxFileSecretBytes+1))
	if err != nil {
		return "", fmt.Errorf("read file secret %q: %w", name, err)
	}
	if len(value) > maxFileSecretBytes {
		return "", fmt.Errorf("file secret %q exceeds %d bytes", name, maxFileSecretBytes)
	}
	if len(value) == 0 {
		return "", fmt.Errorf("file secret %q is empty", name)
	}
	return string(value), nil
}
