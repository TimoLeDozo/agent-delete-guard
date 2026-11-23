# agent-delete-guard

A PreToolUse hook that stops coding agents from deleting or overwriting a repository by accident. One Python file, standard library only, shared by four agent harnesses: Claude Code, Codex CLI, Antigravity and Hermes Agent.

It reads the shell command the agent is about to run (bash, PowerShell, cmd, inline Python, node, perl, ruby, php), decides statically whether it destroys something inside the protected root, and refuses it before it runs. It never executes the command. If the guard itself crashes, it refuses: a broken guard lets nothing through.

## What it blocks

Run from inside the protected root, unless noted.

| Command | Verdict |
|---|---|
| `rm -rf ./build` | refused |
| `Remove-Item docs -Recurse` | refused |
| `git clean -fd`, `git reset --hard HEAD~1`, `git push --force` | refused |
| `git stash`, `git merge feature`, `git pull` on the main tree | refused (worktrees under `.ateliers/` may) |
| `python -c "import shutil; shutil.rmtree('docs')"` | refused |
| `echo docs \| xargs rm -rf`, `bash -c "rm -rf docs"` | refused |
| `find . -name '*.md' -delete` | refused |
| `echo x > CLAUDE.md`, `curl -o CLAUDE.md https://...` | refused (protected file) |
| `git config core.hooksPath /tmp/x` | refused (disarms hooks) |
| `rm -rf D:/work` from anywhere, when the root is `D:/work/project` | refused (ancestor of the root) |
| `git status`, `python -m pytest -q` | allowed |
| `rm -f /tmp/build.log` | allowed (absolute temporary target) |
| `mv docs/a.md docs/b.md` | allowed (move inside the repo) |
| `git commit -m "rm old files"` | allowed (quoted text is not a command) |
| `cat > notes.md <<'EOF'` with `rm -rf` in the body | allowed (a heredoc body is data) |
| `Remove-Item Env:FOO` | allowed (not a file) |

The rule: from inside the root, a deletion must name only absolute temporary targets. Ordinary writes and moves that stay in the repo are allowed. `CLAUDE.md`, `.git`, the guard itself, `.claude/settings.json` and `.codex/hooks.json` cannot be overwritten. The test suite holds about 590 cases, most of them taken from real refusals and from bypasses found by reviewers.

## Why it exists

An audit on 4 October 2026 checked whether the rule "no agent deletes anything in the repo without a human" actually held. It did not:

- Codex: the old hook ran `bash C:/...garde-suppression.sh`, which exited 127 (file not found) on 78 of 80 calls. The tolerant launcher around it returned 0. Codex in full-auto mode had no guard at all, and nothing said so.
- Claude Code: the hook only matched the `Bash` tool, while that workstation runs commands through `PowerShell`.
- Both: `Remove-Item .x -Recurse`, `rm -rf ./x` or `git clean -fd` run from inside the repo went through, because the check looked for the repo name in the command text.

The rewrite parses the command instead of grepping it, resolves relative paths against the working directory, follows launchers (`bash -c`, `pwsh -Command`, `xargs`, `Start-Process`, `python -c`, `find -exec`, aliases defined on the same line) and fails closed. Each later review pass, by several models, added the bypasses it found to the tests before the fix.

## A number you can argue with

The guard logs one line per refusal: timestamp, engine and rule, never the command. Output of `garde_suppression.py --bilan 30` on the author's workstation, run on 2026-11-23:

- 264 refusals, all dated between 2026-11-20 02:03 UTC and 2026-11-22 23:43 UTC (dated logging is recent, so the 30-day window really covers about three days).
- By engine: Codex 110, Antigravity 70, Claude Code 48, Hermes 36.
- By rule: plain command segment 236, guard failure (fail-closed) 18, all on Hermes, subshell in parentheses 6, `$( )` substitution 4.
- 378 older log lines carry no date and are not counted.

What this number does not say: how many of those refusals were real saves and how many were false positives. The log keeps no command text, on purpose. The 18 failures on Hermes mean the guard raised an error on the input it received there and refused by design, which is a bug to investigate, not a success.

## Install

Tested on Windows with Python 3.12 (older versions untested). Set `GARDE_RACINE` to the absolute path of the repository to protect. Without it, the guard protects the directory it was launched from. On Windows, give it a Windows-style path (`D:/work/project`): Git Bash rewrites `/srv/...` style values.

**Claude Code**, in `.claude/settings.json`:

```json
{
  "env": { "GARDE_RACINE": "D:/work/project" },
  "hooks": { "PreToolUse": [ { "matcher": "Bash|PowerShell",
    "hooks": [ { "type": "command", "command": "python /path/to/garde_suppression.py claude", "timeout": 10 } ] } ] }
}
```

Refusal: message on stderr, exit code 2.

**Codex CLI**, in `~/.codex/hooks.json` (export `GARDE_RACINE` in the shell that launches Codex):

```json
{ "hooks": { "PreToolUse": [ { "matcher": "Bash",
  "hooks": [ { "type": "command", "command": "python /path/to/garde_suppression.py codex", "timeout": 10 } ] } ] } }
```

Refusal: `hookSpecificOutput.permissionDecision = "deny"` on stdout, exit code 0. Exit code 2 or `{"continue": false}` did not block Codex 0.160 in testing.

**Antigravity**, in `.agents/hooks.json`:

```json
{ "delete-guard": { "PreToolUse": [ { "matcher": "run_command",
  "hooks": [ { "type": "command", "command": "python /path/to/garde_suppression.py antigravity", "timeout": 10 } ] } ] } }
```

Refusal: `{"decision": "deny"}`. Otherwise `{"decision": "ask"}`, which leaves the choice to Antigravity's own permission policy.

**Hermes Agent**: register `python /path/to/garde_suppression.py hermes` as a `pre_tool_call` shell hook. It reads `{"tool_name", "tool_input", "cwd"}` on stdin and prints `{"decision": "block", "reason": ...}` to refuse.

Refusals are appended to `~/.codex/hooks/garde_trace.jsonl` (or `GARDE_TRACE`). Summary: `python garde_suppression.py --bilan 7`.

## Tests

```
python -m pytest -q
```

The tests use a fictional root, `D:/Depot`, set in `tests/conftest.py`, and `tests/test_racine_configurable.py` checks the environment variable end to end with real temporary directories. Standard library and pytest only.

## Limits

From the module docstring: "Ce filtre n'est pas un interpreteur de shell ni une isolation du systeme de fichiers." This filter is not a shell interpreter and not a filesystem sandbox.

- It recognises known destructive forms. A command built at runtime (a variable it cannot resolve, `iex`, an encoded PowerShell command) is refused from inside the repo, but a sufficiently creative program can still delete files. Use it as a seatbelt against accidents, not as a security boundary against a hostile agent.
- The perimeter is name-based: any directory with the same name as the root (a clone, a worktree, a WSL mount) is treated as the repo. Pick a distinctive root name, or expect extra refusals.
- Inline scripts for node, perl, ruby and php are matched by keywords, not parsed. Python is parsed with `ast`.
- Comments and messages in the code are in French. That is where it was written, and translating them would erase the history they carry.
- Only Windows and Python 3.12 are exercised by the author. Linux paths are handled but untested in CI, and Python 3.13 changed `ntpath.isabs` for rooted paths without a drive.

## En francais

Hook PreToolUse qui empeche un agent de code (Claude Code, Codex, Antigravity, Hermes) d'effacer ou d'ecraser un depot par erreur. Un seul fichier Python, sans dependance. Il lit la commande avant son execution, l'analyse sans la lancer et la refuse si elle detruit quelque chose sous la racine protegee. Une garde en panne refuse aussi.

### Pourquoi

L'audit du 4 octobre 2026 a montre que la garde precedente ne gardait rien. Cote Codex, le script sortait en 127 (fichier introuvable) 78 fois sur 80 et le lanceur rendait 0. Cote Claude, le hook ne visait que l'outil Bash alors que le poste passe par PowerShell. Et `rm -rf ./x` lance depuis le depot passait, faute du nom du depot dans la commande.

### Installation

Poser `GARDE_RACINE` sur le chemin absolu du depot, puis brancher `python garde_suppression.py <moteur>` en hook PreToolUse du moteur (exemples ci-dessus).

### Limites

Ce filtre n'est pas un interpreteur de shell ni une isolation du systeme de fichiers. Il protege contre l'accident, pas contre un agent malveillant.

## License

MIT, see [LICENSE](LICENSE).
