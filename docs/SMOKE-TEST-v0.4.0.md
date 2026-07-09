# v0.4.0 live smoke test (AlmaLinux 10)

The P1–P6 redesign (custom document roots, project/subdomain grouping, adopt
of certbot-split vhosts, GitHub deploy with auto deploy keys, php/static/SPA
serving modes, and the Files tab) all touch code that only runs on Linux and
is **simulated in dev**. Nothing below has executed against real Apache,
certbot, git, or a real non-root tenant yet. Run this on the server once and
report pass/fail per step — v0.4.0 does not ship until this is green.

> Run as a user with sudo. The panel is at `https://<server-ip>:9443`.
> Have one throwaway DNS name pointed at the box for the SSL/GitHub steps
> (any subdomain of a domain you control works). Pick a **non-root** system
> user to own the test project — deploys refuse to run as root by design.

---

## 0. Install / upgrade the build under test

```bash
# from-source (matches what will be tagged); or install the RPM you want to test
curl -fsSL https://raw.githubusercontent.com/jaskaranvirk1/openpropanel/main/scripts/get.sh | sudo bash
openpropanel --version          # confirm the build you intend to test
sudo openpropanel doctor        # all checks should pass
systemctl status openpropanel   # active (running)
```

Log in at `https://<ip>:9443`. If this is a fresh box, complete the first-login
setup wizard (pick your own admin username + password).

---

## P1 — Custom document root

1. **Projects → + New project.** Domain `p1.<yourdomain>`, **Folder** =
   `/var/www/p1-custom/site` (a path that does not exist yet). Create.
2. Verify on disk:
   ```bash
   ls -la /var/www/p1-custom/site            # dir exists
   ls -la /var/www/p1-custom/site/.well-known/acme-challenge   # exists
   ```
   ✅ Expect: directory created, acme-challenge present, **no landing-page
   file seeded** and ownership left as-is (external roots are not chowned).
3. **Delete** the project in the UI (confirm dialog says files are kept).
   ```bash
   ls -la /var/www/p1-custom/site            # MUST still exist — data-loss guard
   ```
   ✅ Expect: the folder and its contents survive the delete. **If the custom
   folder was removed, STOP — that is a release blocker.**
4. Negative: try to create a project with Folder `/etc` or `/root/x` or
   `../../etc`. ✅ Expect: rejected ("document root must be inside …"), nothing
   created.

---

## P2 — Project + subdomain grouping, and adopt

1. **+ New project** `p2.<yourdomain>` (default folder). Then on its card,
   **+ Add subdomain** `blog` (→ `blog.p2.<yourdomain>`), optionally with a
   custom folder. ✅ Expect: the card shows the parent with `blog` nested under
   it, "1 subdomain".
2. Confirm the vhost files exist and Apache is happy:
   ```bash
   ls /etc/httpd/conf.d/ | grep p2
   sudo apachectl configtest        # Syntax OK
   ```
3. **Adopt of certbot-split configs** (the thenorthculture.com class of bug):
   - Pick or create a domain that certbot has split into `X.conf` +
     `X-le-ssl.conf` (enable SSL on a plain domain to produce the split).
   - Restart the panel so it re-imports, or hit **Scan server**.
   - The site should appear as **imported**. Click **Adopt**.
   ✅ Expect: adopt succeeds even though the domain spans multiple files; the
   site flips to managed; **the website keeps serving over HTTPS the whole
   time** (curl it before and after). Check no `.disabled-by-openpropanel`
   files were left behind on success:
   ```bash
   ls /etc/httpd/conf.d/ | grep disabled-by-openpropanel   # expect: none
   sudo apachectl configtest
   ```
   ✅ Negative/rollback: if adopt fails for any reason, confirm every renamed
   config is restored (no leftover `.disabled-by-openpropanel`, site still up).

---

## P3 + P5 — GitHub deploy with auto deploy key (as the tenant, not root)

Use a **private** GitHub repo you own (to exercise the deploy-key path; a
public repo skips the key and clones directly).

1. Create project `deploy.<yourdomain>` owned by a **non-root** system user.
2. On the card → **Deploy from GitHub** → paste `https://github.com/<you>/<repo>`,
   branch `main` → **Link repository**.
3. ✅ Expect: a read-only **deploy key** is shown (`ssh-ed25519 …`). Verify the
   private half is locked down and root-owned:
   ```bash
   sudo ls -l /var/lib/openpropanel/deploy/*/id_ed25519   # -rw------- root root (0600)
   ```
4. Add that public key to the repo (GitHub → repo → Settings → Deploy keys).
5. **Test connection** ✅ succeeds. **Clone / update** ✅ pulls the repo.
6. Verify the checkout is owned by the **tenant**, not root, and git ran as the
   tenant:
   ```bash
   sudo ls -la /var/www/deploy.<yourdomain>/repo        # owned by the tenant user
   sudo -u <tenant> git -C /var/www/deploy.<yourdomain>/repo log -1   # tenant can read it
   ```
   ✅ Expect: files owned by the tenant uid, **not root**. This is the core
   privilege-separation guarantee.
7. Push a commit to the repo, click **Redeploy**. ✅ Expect: fetch + reset to the
   new commit, last-commit/status update in the UI, PHP/web reload.
8. Negative: try linking `https://github.com/x/y; rm -rf /` or a branch named
   `$(reboot)`. ✅ Expect: rejected by URL/branch validation, no shell effect.

---

## P4 — Serving modes (php / static / SPA) + monorepo subfolders

1. On the deploy project, use **Folder in the repo** + **Serve as**:
   - Set subdir to a folder that exists in the repo (e.g. `frontend/dist`),
     mode **SPA** → **Set folder**.
   ```bash
   grep -i "FallbackResource\|SetHandler\|DirectoryIndex" \
     /etc/httpd/conf.d/deploy.<yourdomain>*.conf
   sudo apachectl configtest
   ```
   ✅ Expect SPA: `FallbackResource /index.html`, no PHP handler. Deep-link a
   non-existent path in the browser → still serves `index.html`.
   - Switch mode to **static** → no PHP handler, no fallback (404 on missing).
   - Switch mode to **php** → `SetHandler proxy:unix:…php-fpm…`, `.php` executes.
2. Map a **different subfolder** of the same repo to the `blog` subdomain
   (monorepo → subdomains). ✅ Expect: each subdomain serves its own subfolder.
3. Negative: set subdir to `../../etc` or an absolute path. ✅ Expect: rejected
   (stays within the checkout).

> If you run Nginx instead of Apache, repeat step 1 checking `try_files`
> (`/index.html` for SPA, `=404` for static, `/index.php?$query_string` + a
> fastcgi location for php) under `/etc/nginx/`.

---

## P6 — Files tab

1. **Files** in the sidebar with no site selected → chooser lists your sites.
   ✅ As a non-admin, confirm you see **only your own** sites, not others'.
2. Open a site → browse. Exercise each: **Upload**, **New folder**, **New file**,
   click a file to **edit + save**, **Rename**, **Chmod**, **Download**, **Delete**.
3. **Move**: create `a.txt` at the top, create folder `sub`, use the ⋯ menu →
   **Move** `a.txt` with dest `sub`. ✅ Expect: `a.txt` now under `sub/`.
4. Negative (jail escape): in Move **dest**, try `../../../../etc` or an absolute
   path; in New folder/file **name**, try `../evil`. ✅ Expect: all rejected /
   contained inside the site's document root. Confirm nothing appears outside:
   ```bash
   ls -la /var/www/p2.<yourdomain>/../   # no stray files climbed out
   ```

---

## Wrap-up

- `sudo apachectl configtest` (or `nginx -t`) → **Syntax OK**.
- `journalctl -u openpropanel -n 50` → no panics / repeated errors.
- `sudo cat /var/log/openpropanel/audit.log | tail` → deploy/adopt/file actions
  are recorded.

Report each section as **pass/fail** (paste any failing output). Once all pass,
I'll tag **v0.4.0** and GoReleaser will build the RPMs + tarballs.
