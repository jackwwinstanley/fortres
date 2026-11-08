# Deploying Fortres (fortres.us on Vultr)

The page is plain HTML, CSS and JS in `site/`; there is no build step. A small Vultr server copies this repo,
serves `site/` with [Caddy](https://caddyserver.com) (automatic HTTPS from Let's Encrypt), and pulls new commits
every 5 minutes, so merging to `main` updates https://fortres.us within about 5 minutes.

```
GitHub (main) ──git pull every 5 min──▶ Vultr server (Ubuntu 24.04, Caddy) ◀── fortres.us (DNS at Porkbun, .us registry)
```

## 1. Create the server (Vultr)
1. https://my.vultr.com → **Deploy +** → **Deploy New Server**.
2. Type: **Shared CPU** (Cloud Compute). Location: **Toronto**. Image: **Ubuntu 24.04 LTS x64**. Plan: the smallest one is plenty.
3. Open **Additional Features / Cloud-Init User-Data** and paste all of `deploy/vultr/cloud-init.yaml`.
4. Hostname: `fortres`. Click **Deploy**. Copy the server's **IPv4 address** when it shows.

## 2. Point the domain at it (Porkbun)
Porkbun → Domain Management → fortres.us → **DNS**:
1. Delete the default parking records (the `ALIAS` on the root and the `CNAME` for `*`), if there are any.
2. Add `A` record, host empty (root), answer = the Vultr IPv4, TTL 600.
3. Add `A` record, host `www`, answer = the same IPv4.

## 3. Check
- `https://fortres.us/healthz` returns `ok`. HTTPS starts working a minute or two after DNS resolves.
- The response header `X-Served-By: Vultr` confirms the page comes from the Vultr server.

## Showing a branch before it is merged
On the server: `echo b/my-branch | sudo tee /etc/fortres/branch && sudo fortres-update`. Set it back to `main` after the merge.

## Updating the picks shown on the page
`python scripts/export_site_picks.py` writes `site/data/picks.json` from `outputs/explanations.csv` and
`site/data/story.json` (`python -m src.b.export_story` writes that one).

## Local preview
`python -m http.server -d site 8765`, then open http://localhost:8765. (Opening `index.html` directly will not load the data.)
