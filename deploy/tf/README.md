# OpenTofu/Terraform modules

For distribution/publishing, Easy OIDC OpenTofu/Terraform modules can be found at:

- https://github.com/easy-oidc/terraform-aws-easy-oidc for AWS
- https://github.com/easy-oidc/terraform-google-easy-oidc for Google

However, the source code for these modules is canonically maintained in
`deploy/tf/aws` and `deploy/tf/google`. Identical configuration schema,
rendering, release downloads, and userdata HCL is owned in `deploy/tf/common`
and linked into both provider trees. Distribution/publishing repositories
contain generated, symlink-free copies and must not be edited directly.

Generate both modules under an output directory:

```sh
scripts/generate-tf-modules.sh /tmp/easy-oidc-tf
```

The output directory may be new or a previous output from this script. To avoid
destructive mistakes, the generator refuses to replace any other existing
directory.

To compare output with directories arranged as `<root>/aws` and
`<root>/google`, use `--check <expected-root> <output-root>`. Validation should
run `fmt -check`, `init -backend=false`, `validate`, and `test` in each generated
directory, rather than in the canonical symlinked trees.

After the application release completes, the `tf-modules` job in
`.github/workflows/release.yaml` calls `.github/workflows/release-tf.yml` to
validate both generated modules and synchronize changed modules to
`easy-oidc/terraform-aws-easy-oidc` and
`easy-oidc/terraform-google-easy-oidc`. Configure a GitHub App with Contents
read/write access to those two repositories, set its app ID in the repository
variable `TF_SYNC_APP_ID`, and store its private key in the repository secret
`TF_SYNC_APP_KEY`.

For each provider independently, the workflow compares generated output with
the distribution repository's `main` branch. An unchanged module is skipped. A
changed module is committed to `main` and receives the same tag as the Easy
OIDC release; its branch and tag are pushed atomically. Before either repository
is changed, every changed module is checked for a conflicting tag. Module tags
therefore record the Easy OIDC release that published that module revision
without creating new versions for unchanged modules.
