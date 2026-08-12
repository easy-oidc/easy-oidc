#!/bin/sh
# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0

# Generates symlink-free AWS and Google OpenTofu/Terraform module trees from the canonical source.

set -eu

usage() {
  echo "Usage: $0 [--check EXPECTED_ROOT] OUTPUT_ROOT" >&2
  exit 2
}

check_root=
if [ "${1:-}" = "--check" ]; then
  [ "$#" -eq 3 ] || usage
  check_root=$2
  shift 2
fi
[ "$#" -eq 1 ] || usage

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
output_root=$1
marker=.truster-tf-modules
legacy_marker=.truster-terraform-modules

case "$output_root" in
  /|"$repo_root"|"$repo_root"/*) echo "Refusing unsafe output root: $output_root" >&2; exit 1 ;;
esac

if [ -e "$output_root" ]; then
  if [ ! -f "$output_root/$marker" ] && [ ! -f "$output_root/$legacy_marker" ]; then
    echo "Refusing to replace output without a generated-tree marker: $output_root" >&2
    exit 1
  fi
  rm -rf "$output_root"
fi
mkdir -p "$output_root"
touch "$output_root/$marker"

for provider in aws google; do
  mkdir -p "$output_root/$provider"
  cp -RL "$repo_root/deploy/tf/$provider/." "$output_root/$provider/"
  cp "$repo_root/deploy/tf/.gitignore" "$output_root/$provider/.gitignore"
  cp "$repo_root/LICENSE" "$output_root/$provider/LICENSE"
  cat > "$output_root/$provider/GENERATED.md" <<EOF
# Generated OpenTofu/Terraform module

This tree is generated from
[truster/truster](https://github.com/truster-dev/truster/tree/main/deploy/tf/$provider).
Do not edit it directly; make changes in the canonical application repository.
EOF
done

if find "$output_root" -type l -print | grep -q .; then
  echo "Generated output contains unresolved symlinks" >&2
  exit 1
fi

if [ -n "$check_root" ]; then
  for provider in aws google; do
    diff -ru --exclude=.git --exclude=.terraform \
      --exclude='*.tfstate' --exclude='*.tfstate.backup' \
      "$check_root/$provider" "$output_root/$provider"
  done
fi
