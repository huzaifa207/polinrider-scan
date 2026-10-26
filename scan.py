"""polinrider-scan: a read-only check of your GitHub repos for the PolinRider force-push injection.

For every branch of every repo your token can see, it reports:
  - whether the latest commit carries the injection: a VS Code task that runs a file when the folder
    opens, fake Font Awesome files, code hidden at the end of a config file, `config.bat` added to
    .gitignore, or the push script (temp_auto_push.bat);
  - whether the branch was force-pushed recently, when, and by which account;
  - the commit that push replaced, and whether that one is clean (so the branch can go back to it);
  - whether a deployment (Vercel, Netlify, Railway, …) built an infected commit, so its secrets
    were exposed to the build.
It never changes anything. Python 3.10+, standard library only.

Usage (the token is read without echoing and isn't saved; zsh syntax, bash: read -rsp "…" GITHUB_TOKEN):
  read -rs "GITHUB_TOKEN?GitHub token: " && export GITHUB_TOKEN && python3 scan.py; unset GITHUB_TOKEN

Token: fine-grained, Repository access "All repositories", read-only permissions Contents,
Metadata and Deployments, a short expiry. Without a token it checks a user's public repos only
(GitHub allows 60 requests an hour then: enough for one or two repos, with --repo).

Options:
  --user NAME      without a token: whose public repos (default: the token's own account)
  --repo OWNER/N   check just this repo
  --days N         count force-pushes from the last N days (default 30)
  --out FILE       also write the findings as JSON
Exit status 1 if anything infected was found, so it can run on a schedule.
"""

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

API = "https://api.github.com"
TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()

# Fake fonts named in published reports; the real Font Awesome files are fa-brands-400,
# fa-regular-400 and fa-solid-900, which the campaign copies in alongside as camouflage.
FAKE_FONT = re.compile(r"(^|/)fa-(brand-400\.woff|solid-[45]00\.woff2)$")
# Config files that build tools and editors load, where code gets appended after a long run of
# spaces so it's off-screen in an editor.
CONFIG = re.compile(
    r"(^|/)((next|nuxt|astro|vite|vitest|svelte|tailwind|postcss|eslint|webpack|rollup|babel|"
    r"jest|prisma|tsup|remix)\.config\.(js|cjs|mjs|ts)|\.eslintrc\.(js|cjs)|api\.js)$"
)
# Strings from published indicators of compromise (the obfuscator's fingerprints).
MARKERS = ("global['!']", "global['_V']", "_$_1e42", "rmcej%otb%", "Cot%3t=shtP")
HIDDEN_AFTER_SPACES = re.compile(r"\S {150,}\S")  # code, then 150+ spaces, then more code
MAX_BLOB = 512 * 1024  # bigger files aren't config files; don't download them
calls = 0


def task_runs_on_open(text: str) -> bool:
    """A VS Code task that runs a command when the folder is opened, of the kind the campaign
    plants: node on a file, or a download piped into a shell."""
    return "folderOpen" in text and bool(re.search(r"\bnode\b|\bcurl\b|\bwget\b|\.woff", text))


def hidden_code(text: str) -> bool:
    """Code tucked after a long run of spaces, or the obfuscator's marker strings."""
    return bool(HIDDEN_AFTER_SPACES.search(text)) or any(m in text for m in MARKERS)


def gitignore_tampered(text: str) -> bool:
    return any(line.strip() == "config.bat" for line in text.splitlines())


def get(path: str, optional: bool = False):
    """One GET → (parsed JSON or None, Link header). None for 404/409 (missing, or an empty repo),
    and for 403 when optional (the token can't read that part)."""
    global calls
    calls += 1
    request = urllib.request.Request(path if path.startswith("http") else API + path)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    if TOKEN:
        request.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response), response.headers.get("Link", "")
    except urllib.error.HTTPError as e:
        out_of_calls = e.code in (403, 429) and e.headers.get("X-RateLimit-Remaining") == "0"
        if out_of_calls:
            sys.exit("GitHub's rate limit is used up (without a token it's 60 requests an hour).")
        if e.code in (404, 409) or (optional and e.code == 403):
            return None, ""
        sys.exit(f"GitHub answered {e.code} for {path}: {e.read()[:300].decode(errors='replace')}")


def pages(path: str, optional: bool = False) -> list | None:
    items, url = [], path + ("&" if "?" in path else "?") + "per_page=100"
    while url:
        data, link = get(url, optional)
        if data is None:
            return None if optional and not items else items
        items += data
        url = next((m[1] for m in re.finditer(r'<([^>]+)>;\s*rel="next"', link)), None)
    return items


def blob_text(repo: str, entry: dict) -> str:
    if entry.get("size", 0) > MAX_BLOB:
        return ""
    blob, _ = get(f"/repos/{repo}/git/blobs/{entry['sha']}")
    return base64.b64decode(blob["content"]).decode(errors="replace") if blob else ""


seen: dict[tuple[str, str], dict] = {}


def inspect(repo: str, sha: str) -> dict:
    """What a commit's files show: the injection's traces, if any."""
    if (repo, sha) in seen:
        return seen[repo, sha]
    commit, _ = get(f"/repos/{repo}/git/commits/{sha}")
    tree, _ = get(f"/repos/{repo}/git/trees/{commit['tree']['sha']}?recursive=1") if commit else (None, "")
    found = []
    for entry in (tree or {}).get("tree", []):
        path = entry["path"]
        if entry["type"] != "blob":
            continue
        if FAKE_FONT.search(path):
            found.append(f"fake font {path}")
        elif path.rsplit("/", 1)[-1] == "temp_auto_push.bat":
            found.append(f"push script {path}")
        elif path.endswith(".vscode/tasks.json") and task_runs_on_open(blob_text(repo, entry)):
            found.append(f"{path} runs a command when the folder opens")
        elif CONFIG.search(path) and hidden_code(blob_text(repo, entry)):
            found.append(f"code hidden in {path}")
        elif path == ".gitignore" and gitignore_tampered(blob_text(repo, entry)):
            found.append(".gitignore lists config.bat")
    result = {"infected": bool(found), "found": found, "truncated": bool(tree and tree.get("truncated"))}
    seen[repo, sha] = result
    return result


def scan(repo: dict, since: str) -> list[dict]:
    name = repo["full_name"]
    pushes, history = {}, pages(f"/repos/{name}/activity?activity_type=force_push", optional=True)
    for activity in history or []:  # newest first, so the first per branch is the latest
        if activity["timestamp"] >= since:
            pushes.setdefault(activity["ref"].removeprefix("refs/heads/"), activity)
    deployments = pages(f"/repos/{name}/deployments", optional=True)
    rows = []
    for branch in pages(f"/repos/{name}/branches") or []:
        tip = branch["commit"]["sha"]
        state = inspect(name, tip)
        row = {
            "repo": name,
            "private": repo["private"],
            "branch": branch["name"],
            "default": branch["name"] == repo["default_branch"],
            "tip": tip,
            **state,
            "force_push": None,
            "history_unreadable": history is None,
            "deployed_infected": [],
        }
        if push := pushes.get(branch["name"]):
            before = push.get("before") or ""
            earlier = inspect(name, before) if before.strip("0") else None
            row["force_push"] = {
                "at": push["timestamp"],
                "by": (push.get("actor") or {}).get("login", "?"),
                "replaced": before,
                "replaced_clean": earlier is not None and not earlier["infected"],
                "still_the_tip": push["after"] == tip,
            }
        bad = {tip} if state["infected"] else set()
        # The pushed commit counts only if it's infected: a cleanup's push points at a clean one.
        if row["force_push"] and push["after"] != tip and inspect(name, push["after"])["infected"]:
            bad.add(push["after"])
        row["deployed_infected"] = [
            {"environment": d["environment"], "by": (d.get("creator") or {}).get("login", "?"), "at": d["created_at"]}
            for d in deployments or []
            if d["sha"] in bad
        ]
        rows.append(row)
    return rows


def report(rows: list[dict], since: str) -> str:
    infected = [r for r in rows if r["infected"]]
    pushed = [r for r in rows if r["force_push"] and not r["infected"]]
    lines = [
        f"{len({r['repo'] for r in rows})} repos, {len(rows)} branches checked. "
        f"Infected: {len(infected)} branches in {len({r['repo'] for r in infected})} repos.",
        "",
    ]
    for r in infected:
        lines.append(f"INFECTED  {r['repo']} {r['branch']} ({r['tip'][:7]})")
        lines += [f"          - {f}" for f in r["found"]]
        if fp := r["force_push"]:
            lines.append(f"          force-pushed {fp['at'][:16].replace('T', ' ')} UTC by {fp['by']}")
            if not fp["still_the_tip"]:
                lines.append("          pushed to again since: check by hand before restoring")
            elif fp["replaced_clean"]:
                lines.append(f"          the commit it replaced is clean: {fp['replaced']}")
            else:
                lines.append(f"          the commit it replaced ({fp['replaced'][:7]}) isn't clean either")
        elif r["history_unreadable"]:
            lines.append("          force-push history unreadable (the token lacks access)")
        else:
            lines.append(f"          no force-push since {since[:10]} on record")
        for d in r["deployed_infected"]:
            lines.append(f"          DEPLOYED: {d['environment']} by {d['by']} on {d['at'][:10]}: rotate its secrets")
        if r["truncated"]:
            lines.append("          (the repo is too big to list fully; some files weren't checked)")
    for r in pushed:
        fp = r["force_push"]
        cleanup = "; it replaced an infected commit, so it looks like a cleanup" if not fp["replaced_clean"] else ""
        lines.append(f"pushed    {r['repo']} {r['branch']}: force-pushed {fp['at'][:10]} by {fp['by']}, no injection now{cleanup}")
    if not infected:
        lines.append("Nothing infected found.")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only check of GitHub repos for the PolinRider injection.")
    parser.add_argument("--user", help="without a token: whose public repos")
    parser.add_argument("--repo", help="check only this repo (owner/name)")
    parser.add_argument("--days", type=int, default=30, help="force-pushes from the last N days")
    parser.add_argument("--out", help="also write the findings as JSON to this file")
    args = parser.parse_args()
    since = (datetime.now(timezone.utc) - timedelta(days=args.days)).strftime("%Y-%m-%dT%H:%M:%S")

    if args.repo:
        repo, _ = get(f"/repos/{args.repo}")
        repos = [repo] if repo else sys.exit(f"Can't see {args.repo}")
    elif TOKEN:
        repos = pages("/user/repos?affiliation=owner,collaborator,organization_member&sort=full_name")
    elif args.user:
        print("No GITHUB_TOKEN: public repos only.", file=sys.stderr)
        repos = pages(f"/users/{args.user}/repos?type=owner&sort=full_name")
    else:
        sys.exit("Set GITHUB_TOKEN (see the top of this file), or give --user or --repo.")
    rows = []
    for n, repo in enumerate(repos, 1):
        print(f"[{n}/{len(repos)}] {repo['full_name']}", file=sys.stderr)
        rows += scan(repo, since)
    print(report(rows, since))
    if args.out:
        with open(args.out, "w") as f:
            json.dump(rows, f, indent=2)
    print(f"\n{calls} API requests.", file=sys.stderr)
    sys.exit(1 if any(r["infected"] for r in rows) else 0)


if __name__ == "__main__":
    main()
