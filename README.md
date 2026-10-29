# Shoham Images CDN

A flat, public-by-URL image CDN for `cdn.kiwi-kids.co.il`, backed by a **private** Cloudflare R2 bucket. Administrators use a separate Cloudflare Access-protected hostname `images.kiwi-kids.co.il`. A scheduled GitHub Actions runner recursively downloads FTP/SFTP images to R2.

## Address rules

FTP file `any/subfolders/171204412.jpg` becomes R2 object key `171204412`, served at `https://cdn.kiwi-kids.co.il/171204412` (also `/171204412.jpg`, subject to actual content type). The ID is the model number followed by the color code, as-is, including any leading zeros. Numeric basename must be 8–18 digits. The implementation assumes filenames already contain the complete concatenated ID; it does not attempt to split model and color. No public directory listings, search APIs, or R2 bucket domain are exposed.

## Deployment

1. In Cloudflare create R2 bucket `shoham-images`. Keep **r2.dev public access disabled** and do **not** add the R2 bucket directly as a public custom domain. The R2 binding is internal to the Worker.
2. Create `cdn.kiwi-kids.co.il` and `images.kiwi-kids.co.il` as **Worker Custom Domains** pointing to the same Worker in Cloudflare, in the `kiwi-kids.co.il` zone. Ensure DNS zone/control is compatible; do not disrupt existing apex/www records. If the domain is not on Cloudflare, delegate the DNS zone or use a supported setup approved by the domain owner.
3. Create a Cloudflare Zero Trust Access **self-hosted application** covering `images.kiwi-kids.co.il/*`; restrict policies to authorized admins and enable MFA. Record the application's **AUD tag** and your Access team domain (`your-team.cloudflareaccess.com`). Configure the `CF_ACCESS_AUD` and `CF_ACCESS_TEAM_DOMAIN` vars in `wrangler.jsonc`. The Worker verifies the JWT cryptographically even if Access proxy rules are misconfigured. Do NOT put Access on `cdn.kiwi-kids.co.il`.
4. Run `npm install`, `npx wrangler login`, `npm run deploy`. Configure Worker Custom Domains in dashboard (or Wrangler routes) after deploy. For testing on a workers.dev address, temporarily enable workers_dev and adapt hostname settings appropriately; do not expose admin API for such testing.
5. Configure GitHub Actions repository variables/secrets below. Trigger **Actions > Sync FTP or SFTP to R2 > Run workflow** with `DRY_RUN=true` first. Inspect results and resolve duplicate IDs. Change variable `DRY_RUN` to `false` only after verification.
6. Test `/`, `/models/`, `/api/list` (blocked) and `/171204412` (image), plus authenticated admin listing and upload.

## GitHub Actions repository VARIABLES

| Variable | Example | Purpose |
|---|---|---|
| `SOURCE_PROTOCOL` | `ftp` or `sftp` | Transfer protocol |
| `SOURCE_HOST` | `ftp.vendor.example` | Remote hostname |
| `SOURCE_PORT` | `21` or `22` | Remote port |
| `SOURCE_PATH` | `/images` | Recursively searched path |
| `SOURCE_SSH_SHA256` | `SHA256:...` | **Mandatory** for SFTP, confirm using trusted out-of-band fingerprint |
| `DRY_RUN` | `true` | Set to `false` to upload |

## GitHub Actions repository SECRETS

`SOURCE_USER`, `SOURCE_PASSWORD` (required for FTP and SFTP password login), `SOURCE_SSH_KEY_B64` (optional SFTP private key, base64 encoded, use INSTEAD of password), `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`. Create an R2 token scoped to the `shoham-images` bucket with Object Read & Write permission. **Never commit secrets**. Use a read-only source account. Ordinary FTP is plaintext: prefer SFTP.

## Sync behavior

- Recursively discover all image files from the remote root, including nested directories. Requires FTP `MLSD` support; if the FTP server does not support it, the current connector needs an FTP LIST fallback.
- Flatten to `<model><color>` key (no extension). Maintain source path/size/mtime in object metadata and skip unchanged files.
- Detect duplicate numeric IDs across folders and skip **all** matching duplicates until resolved (avoids unintended overwrite).
- Only JPG, JPEG, PNG, WEBP, GIF, up to 15 MB per file; enforce basic file signatures. Treat only image-related files as images.
- Source deletions do not delete R2 objects. No public listing, but URLs are guessable; do not store confidential images here.
- Content browser Cache-Control currently has `max-age=300` (five minutes); replacement can take five minutes to appear in clients. Cloudflare caching can be tuned separately and must respect the chosen invalidation policy.
- GitHub scheduled workflows are best-effort and may be delayed; they are not guaranteed to run at exact 15-minute intervals.

## Operations/security notes

- **Public URLs** are not access control. No listing only prevents direct enumeration. A scraper can guess model/color IDs.
- Admin JWT is verified against Access keys and configured audience. Ensure actual Access policy and custom hostname are set before exposing the service.
- The basic admin UI supports direct upload of single files and listing first 100 items. In bulk operations, use the sync connector.
- FTP source file inventories may be large and incur repeated listing operations. For 100k+ images, replace full inventory walk with a persistent index/incremental sync state.
- Avoid sharing an R2 bucket with an unrelated app. Rotate credentials; review Actions logs and R2 usage.
