// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package templates

import (
	"fmt"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// publicAsset is a validated file served from the public template subtree.
type publicAsset struct {
	content     []byte
	contentType string
}

// loadPublic loads regular files beneath the optional public template subtree.
func loadPublic(dir string) (map[string]publicAsset, error) {
	assets := make(map[string]publicAsset)
	if dir == "" {
		return assets, nil
	}
	root := filepath.Join(dir, "public")
	info, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return assets, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect public templates: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("public templates path must be a directory, not a symlink")
	}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("public template %s must not be a symlink", path)
		}
		if entry.IsDir() {
			return nil
		}
		entryInfo, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		if !entryInfo.Mode().IsRegular() {
			return fmt.Errorf("public template %s must be a regular file", path)
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		relative, relativeErr := filepath.Rel(root, path)
		if relativeErr != nil {
			return relativeErr
		}
		contentType := mime.TypeByExtension(strings.ToLower(filepath.Ext(path)))
		switch strings.ToLower(filepath.Ext(path)) {
		case ".ico":
			contentType = "image/x-icon"
		case ".svg":
			contentType = "image/svg+xml"
		case ".webmanifest":
			contentType = "application/manifest+json"
		}
		if contentType == "" {
			contentType = http.DetectContentType(content)
		}
		assets["/"+filepath.ToSlash(relative)] = publicAsset{content: content, contentType: contentType}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("load public templates: %w", err)
	}
	return assets, nil
}

// HandlePublic serves an exact file loaded from the public template subtree.
func (m *Manager) HandlePublic(w http.ResponseWriter, r *http.Request) {
	asset, ok := m.public[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Length", strconv.Itoa(len(asset.content)))
	w.Header().Set("Content-Type", asset.contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodGet {
		_, _ = w.Write(asset.content)
	}
}
