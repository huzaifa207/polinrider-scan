# polinrider-scan

A read-only check of your GitHub repos for the **PolinRider** force-push injection: a campaign that uses stolen GitHub credentials to amend the latest commit of a repo, keep its author, message and date, and force-push it with malware added. It changes nothing; it only reads.

For every branch of every repo your token can see, it reports:

- **whether the latest commit is infected:**
  - a VS Code task that runs a file when the folder opens (`.vscode/tasks.json`);
  - fake Font Awesome files (JavaScript posing as `.woff`/`.woff2`);
  - code hidden at the end of a config file after a long run of spaces (`next.config.js`, `astro.config.mjs`, `eslint.config.mjs`, `prisma.config.ts`, `api.js`, …), or the obfuscator's marker strings;
  - `config.bat` added to `.gitignore`;
  - the push script `temp_auto_push.bat`;
- **whether the branch was force-pushed recently**, when, and by which account (an injected commit pushed with your credentials shows your own name);
- **the commit that push replaced**, and whether it's clean: that's the commit to put the branch back on;
- **whether a deployment built an infected commit** (Vercel, Netlify, Railway, anything that reports to GitHub's Deployments): if the injected code sits in a config file the build loads, it ran during that build, so that project's environment variables were exposed.

It also flags force-pushes that left no injection behind, including the ones that look like someone already cleaning up.

## Run it

Python 3.10 or later, no packages to install.

1. Create a token: GitHub → Settings → Developer settings → Fine-grained tokens → Generate new token. Repository access **All repositories**; repository permissions **Contents: Read-only** and **Deployments: Read-only** (Metadata is added automatically); expiry: a day. Delete it when you're done.
2. Run the scan. The token is read without echoing and never lands in your shell history.

   ```bash
   read -rs "GITHUB_TOKEN?GitHub token: " && export GITHUB_TOKEN && python3 scan.py; unset GITHUB_TOKEN
   ```

   That's zsh, the macOS default. In bash: `read -rsp "GitHub token: " GITHUB_TOKEN && export GITHUB_TOKEN && python3 scan.py; unset GITHUB_TOKEN`.

Options:

| Option | What it does |
|---|---|
| `--days N` | count force-pushes from the last N days (default 30) |
| `--repo owner/name` | check one repo |
| `--user name` | without a token, check a user's public repos (GitHub allows 60 requests an hour without one, enough for a repo or two) |
| `--out file.json` | also save the findings as JSON |

It exits with status 1 when it finds something infected, so you can run it on a schedule. Run it again a week after cleaning up: the campaign has been reported re-infecting repos it hit before.

## If it finds something

1. **Lock down GitHub first**, or the attacker can push again: revoke personal access tokens (especially classic ones with the `repo` scope), sign out OAuth apps you don't need, and replace your SSH keys. The personal security log doesn't list pushes; the scan does.
2. **Don't pull or check out the infected branches**, and don't open them in an editor: the VS Code task runs as soon as the folder opens.
3. **Put each branch back on the commit the push replaced.** The injection amends a single commit, so the replaced one is your original, and GitHub keeps it. In a bare clone (no files on disk), fetch it by its full id and push it back, with a lease so the push only goes through if the branch still points at the injected commit:

   ```bash
   git clone --bare git@github.com:OWNER/REPO.git && cd REPO.git
   git fetch origin <replaced commit>
   git push --force-with-lease=refs/heads/<branch>:<injected commit> origin <replaced commit>:refs/heads/<branch>
   ```

4. **Rotate the secrets of anything that built an infected commit**, then build it again from the clean commit. On Vercel that means **Redeploy**, not Promote or Instant Rollback, which reuse the old build and its old environment variables. A deployment platform may also skip a commit it has built before, so start the build yourself.
5. **Block force-pushes** on your default branches (a repository ruleset with "Block force pushes"). On GitHub's free plan that works for public repos only.

The full story, from noticing it to cleaning up, is at https://itshuzaifa.com/writing/polinrider-force-push/.

## Limits

- It recognises the variants published so far. A new disguise won't be flagged, so treat "nothing found" as "nothing known found", and check unexplained force-pushes by hand.
- It reads only the files it needs, so a huge repo's file list may come back truncated; it says when.
- Force-push history comes from GitHub's repository activity, which needs the token to see each repo.

## Further reading

- [PolinRider dossier](https://github.com/OpenSourceMalware/PolinRider) (OpenSourceMalware): how the malware works, indicators, affected repos.

MIT licence.
