# Release verification

Purple Wolf release artifacts are published from tag builds and signed with
keyless Cosign through GitHub OIDC. Verify artifacts before installing them in
production.

Set the release tag once:

```bash
export VERSION=v0.3.0
export REPO=guaracloud/purple-wolf
```

## Download release assets

```bash
mkdir -p "purple-wolf-${VERSION}"
gh release download "$VERSION" --repo "$REPO" --dir "purple-wolf-${VERSION}"
cd "purple-wolf-${VERSION}"
```

## Verify checksums

```bash
for sum in *.sha256; do
  sha256sum -c "$sum"
done
```

On macOS, use `shasum -a 256 -c <file>.sha256` if GNU `sha256sum` is not
installed.

## Verify Cosign blob signatures

```bash
for sig in *.sig; do
  artifact="${sig%.sig}"
  cosign verify-blob "$artifact" \
    --signature "$sig" \
    --certificate "${artifact}.pem" \
    --certificate-identity-regexp '^https://github\.com/guaracloud/purple-wolf/' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
done
```

## Verify container image signatures

Read exact image digests from `release-manifest.json`, then verify them:

```bash
relay_ref="$(jq -r '.images[] | select(.name=="ghcr.io/guaracloud/purple-wolf-relay") | .reference' release-manifest.json)"
wasm_ref="$(jq -r '.images[] | select(.name=="ghcr.io/guaracloud/purple-wolf-wasm") | .reference' release-manifest.json)"

cosign verify "$relay_ref" \
  --certificate-identity-regexp '^https://github\.com/guaracloud/purple-wolf/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'

cosign verify "$wasm_ref" \
  --certificate-identity-regexp '^https://github\.com/guaracloud/purple-wolf/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

Use the digest-pinned references from the manifest in production manifests.

## Verify SBOMs

Release SBOMs are SPDX JSON:

```bash
for sbom in *.spdx.json; do
  jq -e '.spdxVersion and .packages' "$sbom" >/dev/null
done
```

## Verify the Helm chart

```bash
helm pull oci://ghcr.io/guaracloud/charts/purple-wolf --version "${VERSION#v}"
sha256sum -c "purple-wolf-${VERSION#v}.tgz.sha256"
```

The chart digest is recorded in `release-manifest.json` under `helm_chart.digest`.

## Verify the release manifest

```bash
cosign verify-blob release-manifest.json \
  --signature release-manifest.json.sig \
  --certificate release-manifest.json.pem \
  --certificate-identity-regexp '^https://github\.com/guaracloud/purple-wolf/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'

jq -e '.schema == "purple-wolf.release-manifest/v1"' release-manifest.json
```
