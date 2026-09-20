"""Interactively complete a worktree: verify, push, and open a pull request.

Once the feature/fix is committed and a PR description has been written to
.local/PR.md, this walks through the remaining steps one at a time. Before each
action it shows what is about to happen and prompts for confirmation (y/n);
answering 'n' aborts without taking the remaining steps. The output of every
git and gh command is shown.

The procedure:
  1. Confirm we are on a wt/ branch in a worktree (never main/develop).
  2. Verify the working tree is clean — everything is committed.
  3. Resolve the PR base from the branch's UPSTREAM *before* pushing, since
     `git push -u` repoints tracking. Refuses to target main.
  4. Show the PR body and confirm the title.
  5. Push the branch with -u.
  6. Open the PR with `gh pr create --base <base> --body-file .local/PR.md`.
  7. Report the PR URL and stop. The worktree is NOT cleaned up; that is left
     to the user.

Pass -y/--yes to answer every prompt with 'y' for non-interactive use.

Pass --no-remote for a repository with no origin (or to stay local): instead of
pushing and opening a PR, the branch is merged into its base in the main
worktree, which is what merging the PR would have done. No PR body file is
needed and gh is not used. The worktree is still left in place.

Cross-device handoff (push on one device, open the PR on another) — for when
the device with the worktree has no authenticated gh, and nothing may leave the
repo:
  - On the device with the worktree, run --push-pr-to-notes. It verifies and
    pushes the branch, then attaches the PR body (with the base and title) as a
    per-slug git note (refs/notes/pr-body-<slug>) and pushes that note to
    origin. The note rides on the commit, so it never appears in the PR diff;
    one ref per slug means concurrent PRs never collide. No PR is created and
    gh is not required here.
  - On the other device, run --gh-from-notes --slug <slug> (creates the PR with
    gh) or --web-from-notes --slug <slug> (opens a prefilled PR form in the
    browser; no gh auth needed). Either fetches the branch and the note,
    recovers the base/title/body, creates the PR, and then offers to delete the
    note from origin.

Usage:
    python scripts/complete_worktree.py
    python scripts/complete_worktree.py --title "feat(auth): add SSO login" --draft
    python scripts/complete_worktree.py -y
    python scripts/complete_worktree.py --push-pr-to-notes
    python scripts/complete_worktree.py --web-from-notes --slug issue-42
    python scripts/complete_worktree.py --no-remote

Requirements:
    - Run from inside the worktree, on a wt/ branch with all work committed
      (the PR body file itself does not need to be committed).
    - `git` and `gh` installed and authenticated (gh is NOT needed for
      --push-pr-to-notes, --web-from-notes, or --no-remote).
    - A PR body file at .local/PR.md in the worktree, opening with fenced
      front-matter that sets the PR title (not needed with --no-remote).
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import webbrowser
from pathlib import Path
from urllib.parse import quote

import _cli as cli

# Version of this helper script itself. Bump on every change so copies in other
# repos can be compared: patch = bugfix, minor = new flag/behavior, major =
# breaking CLI change.
__version__ = "1.5.0"

# Default location of the PR description, relative to the worktree root and
# overridable with --body-file. It lives under .local/ so the repo's '*.local*'
# .gitignore rule keeps it untracked: the file only feeds `gh pr create` and
# must never land in the PR diff.
PR_FILE_PATH = ".local/PR.md"

# The cross-device PR-body handoff stores one note per slug
# (refs/notes/pr-body-<slug>) so concurrent PRs never share -- or force-push
# over -- a single ref. See notes_ref().
NOTES_REF_PREFIX = "pr-body"


def dirty_status_lines(status_lines: list[str], exempt_path: str | None) -> list[str]:
    """Filter ``git status --porcelain`` lines, ignoring the exempt PR body file.

    Args:
        status_lines: Output lines from ``git status --porcelain``.
        exempt_path: Repo-root-relative POSIX path allowed to stay uncommitted
            (the PR body file), or ``None`` when no path is exempt.

    Returns:
        The lines describing changes to any file other than ``exempt_path``.
    """
    dirty: list[str] = []
    for line in status_lines:
        if not line.strip():
            continue
        # Porcelain v1: two status letters, a space, then the path. Paths with
        # special characters are quoted; the plain strip covers the simple case.
        path = line[3:].strip().strip('"')
        if exempt_path is not None and path == exempt_path:
            continue
        dirty.append(line)
    return dirty


def parse_front_matter(content: str) -> tuple[str | None, str | None, str]:
    """Parse fenced front-matter (``base``/``title``) from a PR body or note.

    Both ``PR.md`` and the cross-device note use the same fenced YAML-style
    front-matter: the content opens with a ``---`` fence line, followed by
    ``key: value`` lines (``base:`` and/or ``title:``), a closing ``---`` fence
    line, then the body. ``PR.md`` carries only ``title:``; the note adds
    ``base:``.

    Requiring a *leading* fence (not just a trailing separator) is what makes
    this safe for hand-authored ``PR.md``: a body that merely contains a ``---``
    thematic break is not mistaken for front-matter. Content that does not open
    with a fence, or whose fence is never closed, is treated as having no
    front-matter and returned whole as the body.

    Args:
        content: The raw PR body or note text.

    Returns:
        ``(base, title, body)``; ``base`` and ``title`` are ``None`` when
        absent, and ``body`` has any leading blank lines trimmed.
    """
    lines = content.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, None, content
    close: int | None = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            close = i
            break
    if close is None:
        return None, None, content
    base: str | None = None
    title: str | None = None
    for line in lines[1:close]:
        base_match = re.match(r"base:\s*(.*)$", line)
        if base_match:
            base = base_match.group(1).strip()
            continue
        title_match = re.match(r"title:\s*(.*)$", line)
        if title_match:
            title = title_match.group(1).strip()
    body = "\n".join(lines[close + 1 :]).lstrip("\n")
    return base, title, body


def render_note(base: str, title: str, body: str) -> str:
    """Render fenced front-matter (base + title) plus body for a pr-body note.

    The inverse of :func:`parse_front_matter` for the note case: emits a leading
    ``---`` fence, the ``base:`` and ``title:`` lines, a closing ``---`` fence,
    then the body.

    Args:
        base: Resolved PR base branch.
        title: Confirmed PR title.
        body: PR body (already front-matter-stripped).

    Returns:
        The note text to attach with ``git notes add``.
    """
    return f"---\nbase: {base}\ntitle: {title}\n---\n{body}"


def origin_slug() -> str:
    """Parse ``owner/repo`` from origin's URL (SSH or HTTPS).

    Returns:
        The ``owner/repo`` portion, for building a github.com compare URL.
    """
    url = cli.capture(["git", "remote", "get-url", "origin"])
    match = re.search(r"github\.com[:/]+([^/]+)/(.+?)(?:\.git)?/?$", url)
    if not match:
        cli.die(f"Could not parse owner/repo from origin URL: {url}")
    return f"{match.group(1)}/{match.group(2)}"


def copy_to_clipboard(text: str) -> bool:
    """Best-effort copy to the OS clipboard via a platform tool (stdlib only).

    Args:
        text: Text to place on the clipboard.

    Returns:
        ``True`` if a clipboard tool ran successfully, ``False`` otherwise (the
        caller falls back to a file).
    """
    if sys.platform == "win32":
        command = ["clip"]
    elif sys.platform == "darwin":
        command = ["pbcopy"]
    else:
        command = ["xclip", "-selection", "clipboard"]
    try:
        result = subprocess.run(  # noqa: S603  (fixed argv list, no shell)
            command, input=text, encoding="utf-8"
        )
    except OSError:
        return False
    return result.returncode == 0


def open_web_pr(owner_repo: str, branch: str, base: str, title: str, body: str) -> None:
    """Open a github.com PR-compare page with the title and body prefilled.

    If the encoded URL is too long for a browser/GitHub to accept, fall back to
    opening the form with just the title and delivering the body another way
    (clipboard, or a temp file when no clipboard tool is available).

    Args:
        owner_repo: ``owner/repo`` for the compare URL.
        branch: The head branch to compare.
        base: The base branch to compare against.
        title: PR title to prefill.
        body: PR body to prefill.
    """
    compare_url = f"https://github.com/{owner_repo}/compare/{base}...{branch}?expand=1"
    enc_title = quote(title, safe="")
    full = f"{compare_url}&title={enc_title}&body={quote(body, safe='')}"
    if len(full) <= 8000:
        cli.echo("open <compare URL with prefilled title and body>")
        webbrowser.open(full)
        cli.success("  Opened the prefilled PR form in your browser.")
        return

    cli.echo("open <compare URL with prefilled title>")
    webbrowser.open(f"{compare_url}&title={enc_title}")
    if copy_to_clipboard(body):
        cli.warn(
            "  Body too long to prefill via URL; copied it to your clipboard - "
            "paste it into the form."
        )
    else:
        out = Path(tempfile.gettempdir()) / f"PR_body_{branch.replace('/', '-')}.md"
        out.write_text(body, encoding="utf-8")
        cli.warn(f"  Body too long to prefill via URL; saved it to {out} - paste it into the form.")


def notes_ref(slug: str) -> str:
    """Build the per-slug notes ref name (``pr-body-<slug>``).

    One ref per slug keeps concurrent PRs from sharing -- and force-pushing
    over -- each other's note. Slashes in the slug are flattened so the ref
    stays a single path segment.

    Args:
        slug: The worktree slug (the part after ``wt/``).

    Returns:
        The notes ref name (without the ``refs/notes/`` prefix).
    """
    return f"{NOTES_REF_PREFIX}-{slug.replace('/', '-')}"


def remove_pr_note(ref: str) -> None:
    """Delete a PR-body notes ref from origin and locally.

    Tolerates an already-gone ref (echoes the command, ignores the exit code)
    so cleanup is safe to run more than once.

    Args:
        ref: The notes ref name (without the ``refs/notes/`` prefix).
    """
    cli.echo(f"git push origin :refs/notes/{ref}")
    cli.exit_code(["git", "push", "origin", f":refs/notes/{ref}"])
    cli.echo(f"git update-ref -d refs/notes/{ref}")
    cli.exit_code(["git", "update-ref", "-d", f"refs/notes/{ref}"])


def cleanup_pr_note(ref: str, prompt: str) -> None:
    """Offer to delete the PR-body note from origin now the PR exists.

    Declining is not an abort -- the PR is already created -- so this prints how
    to remove the note later instead of stopping.

    Args:
        ref: The notes ref name (without the ``refs/notes/`` prefix).
        prompt: The yes/no question to show.
    """
    cli.section("Step: clean up PR body note")
    if cli.confirm(prompt):
        remove_pr_note(ref)
        cli.success("  Removed the PR body note from origin.")
    else:
        print(f"  {cli.GRAY}Left the note in place. Remove it later with:{cli.RESET}")
        print(f"    {cli.GRAY}git push origin :refs/notes/{ref}{cli.RESET}")


def parse_args() -> argparse.Namespace:
    """Parse the command line."""
    parser = argparse.ArgumentParser(
        description="Complete a worktree: verify it is committed, push the branch, and open a PR."
    )
    parser.add_argument(
        "--title",
        help="PR title (default: the 'title:' front-matter in the PR body file; "
        "always confirmed interactively)",
    )
    parser.add_argument(
        "--base",
        help="override the PR base branch (default: read from the branch's upstream)",
    )
    parser.add_argument(
        "--body-file",
        default=PR_FILE_PATH,
        help=f"path to the PR body file (default: {PR_FILE_PATH}, relative to the worktree root)",
    )
    parser.add_argument("--draft", action="store_true", help="open the PR as a draft")
    parser.add_argument(
        "--no-remote",
        action="store_true",
        help="work locally only: merge the branch into its base instead of pushing/opening a PR",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="assume 'yes' to every confirmation prompt (non-interactive)",
    )
    parser.add_argument(
        "--push-pr-to-notes",
        action="store_true",
        help="device A: push the branch and attach the PR body as a 'pr-body' note (no PR, no gh)",
    )
    parser.add_argument(
        "--gh-from-notes",
        action="store_true",
        help="device B: fetch the branch and note for --slug, then create the PR with gh",
    )
    parser.add_argument(
        "--web-from-notes",
        action="store_true",
        help="device B: fetch the branch and note for --slug, then open a prefilled PR form",
    )
    parser.add_argument(
        "--slug",
        help="worktree slug (after 'wt/') for the --*-from-notes modes; "
        "defaults to the current wt/ branch",
    )
    return parser.parse_args()


def create_from_notes(args: argparse.Namespace) -> None:
    """Device B: recover a PR from a pushed branch and its pr-body note.

    Fetches the branch and the note, reads the base/title/body from the note,
    then either creates the PR with gh (``--gh-from-notes``) or opens a
    prefilled browser form (``--web-from-notes``).

    Args:
        args: Parsed command line.
    """
    slug = args.slug
    if not slug:
        current = cli.capture_ok(["git", "symbolic-ref", "--short", "HEAD"])
        if current and current.startswith("wt/"):
            slug = current.removeprefix("wt/")
    if not slug:
        cli.die("Specify --slug to identify the worktree branch (e.g. --slug issue-42).")
    branch = f"wt/{slug}"
    ref = notes_ref(slug)

    if args.gh_from_notes and shutil.which("gh") is None:
        cli.die(
            "gh not found on PATH. Use --web-from-notes to create the PR in the browser instead."
        )

    cli.section("Fetch branch and PR note")
    cli.run(["git", "fetch", "origin", f"+refs/heads/{branch}:refs/remotes/origin/{branch}"])
    cli.run(["git", "fetch", "origin", f"+refs/notes/{ref}:refs/notes/{ref}"])

    note_raw = cli.capture_ok(["git", "notes", f"--ref={ref}", "show", f"origin/{branch}"])
    if not note_raw:
        cli.die(
            f"No '{ref}' note found on origin/{branch}. "
            "Run --push-pr-to-notes on the device that has the worktree first."
        )
    note_base, note_title, note_body = parse_front_matter(note_raw)

    base = args.base or note_base or "develop"
    if base in ("main", "master"):
        cli.die(
            f"Refusing to target '{base}'. This project uses git flow; PRs go to "
            "develop. Pass --base to override deliberately."
        )

    title = args.title or note_title
    if not title:
        cli.die(
            f"No PR title in the '{ref}' note (missing 'title:' front-matter). "
            f"Re-run --push-pr-to-notes with a {PR_FILE_PATH} whose front-matter "
            "sets the title."
        )

    cli.info("Slug", slug)
    cli.info("Branch", branch)
    cli.info("PR base", base)
    cli.info("PR title", title)
    print()
    print(f"{cli.GRAY}{note_body.rstrip()}{cli.RESET}")

    if args.web_from_notes:
        cli.section("Step: open pull request (web)")
        cli.step(f"Open the prefilled PR form for '{branch}' into '{base}' in your browser?")
        open_web_pr(origin_slug(), branch, base, title, note_body)
        cleanup_pr_note(
            ref, f"Once you've created the PR in the browser, delete the '{ref}' note from origin?"
        )
        return

    # --gh-from-notes: create the PR with gh, body delivered via a temp file.
    cli.section("Step: open pull request")
    draft_note = " (draft)" if args.draft else ""
    cli.step(f"Open a PR from '{branch}' into '{base}'?{draft_note}")
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as handle:
        handle.write(note_body)
        body_file = handle.name
    try:
        create_args = ["gh", "pr", "create", "--base", base, "--head", branch, "--title", title]
        create_args += ["--body-file", body_file]
        if args.draft:
            create_args.append("--draft")
        output = cli.capture(create_args, echo_cmd=True)
    finally:
        Path(body_file).unlink(missing_ok=True)
    pr_url = output.splitlines()[-1].strip() if output else "(unknown)"

    cleanup_pr_note(ref, f"Delete the '{ref}' note from origin now the PR is created?")

    cli.section("Done")
    cli.success("  Pull request opened.")
    cli.info("PR", pr_url)
    cli.info("Base", base)


def push_pr_note(base: str, title: str, body: str, body_name: str, branch: str) -> None:
    """Device A: attach the PR body as a pr-body note and push it to origin.

    The note carries the resolved base and title as fenced front-matter so the
    other device can recover them without any out-of-band communication.

    Args:
        base: Resolved PR base branch.
        title: Confirmed PR title.
        body: PR body (front-matter-stripped, as sent to ``gh``).
        body_name: PR body file name, for the prompt.
        branch: The wt/ branch the note rides on.
    """
    slug = branch.removeprefix("wt/")
    ref = notes_ref(slug)
    cli.section("Step: attach PR body note")
    note_body = render_note(base, title, body)
    cli.step(f"Attach {body_name} (with base/title) as a '{ref}' note and push it to origin?")
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as handle:
        handle.write(note_body)
        note_file = handle.name
    try:
        cli.run(["git", "notes", f"--ref={ref}", "add", "--force", "--file", note_file, "HEAD"])
        cli.run(["git", "push", "origin", f"+refs/notes/{ref}:refs/notes/{ref}"])
    finally:
        Path(note_file).unlink(missing_ok=True)

    cli.section("Done")
    cli.success(f"  Pushed branch and PR body note for '{slug}'.")
    cli.info("Branch", branch)
    print()
    print(f"  {cli.GRAY}On the other device, create the PR with one of:{cli.RESET}")
    script = "python scripts/complete_worktree.py"
    print(f"    {cli.GRAY}{script} --gh-from-notes --slug {slug}{cli.RESET}")
    print(f"    {cli.GRAY}{script} --web-from-notes --slug {slug}{cli.RESET}")


def main_worktree_path() -> str:
    """Return the path of the repository's main worktree.

    ``git worktree list --porcelain`` always reports the main worktree first,
    so its first ``worktree`` line is the checkout that owns the integration
    branches.

    Returns:
        The main worktree's path.
    """
    for line in cli.capture(["git", "worktree", "list", "--porcelain"]).splitlines():
        if line.startswith("worktree "):
            return line.removeprefix("worktree ")
    cli.die("Could not determine the main worktree (are you inside a git repository?).")


def merge_locally(branch: str, base: str) -> None:
    """--no-remote: merge the wt/ branch into its base in the main worktree.

    Stands in for merging the pull request. The merge runs in the main
    worktree rather than this one, because git allows a branch to be checked
    out in only one worktree at a time and the base normally lives there. This
    worktree is left in place, exactly as the PR flow leaves it.

    Args:
        branch: The wt/ branch to merge.
        base: The branch to merge it into.
    """
    main_repo = main_worktree_path()

    cli.section(f"Step: merge '{branch}' into '{base}'")
    cli.info("Main worktree", main_repo)

    # The merge writes to the main worktree's files, so anything uncommitted
    # there is at risk; refuse rather than merge on top of it.
    dirty = cli.capture_ok(["git", "-C", main_repo, "status", "--porcelain"])
    if dirty:
        cli.warn(f"  The main worktree at {main_repo} has uncommitted changes:")
        for line in dirty.splitlines():
            print(f"  {cli.GRAY}{line}{cli.RESET}")
        cli.die("Commit or stash them there first, then re-run.")

    current = cli.capture_ok(["git", "-C", main_repo, "branch", "--show-current"])
    if current != base:
        cli.step(f"Switch the main worktree from '{current or '(detached HEAD)'}' to '{base}'?")
        cli.run(["git", "-C", main_repo, "switch", base])

    cli.step(f"Merge '{branch}' into '{base}'?")
    cli.run(["git", "-C", main_repo, "merge", branch])

    cli.section("Done")
    cli.success(f"  Merged '{branch}' into '{base}' locally; nothing was pushed.")
    cli.info("Base", base)
    cli.info("Main worktree", main_repo)
    print()
    print(f"  {cli.GRAY}Worktree left in place for you to clean up.{cli.RESET}")


def main() -> None:
    """Run the interactive verify-push-PR flow."""
    args = parse_args()
    cli.set_assume_yes(args.yes)

    cli.info("Script version", __version__)
    print("")

    notes_modes = (args.push_pr_to_notes, args.gh_from_notes, args.web_from_notes)
    if sum(bool(m) for m in notes_modes) > 1:
        cli.die("Specify at most one of --push-pr-to-notes, --gh-from-notes, --web-from-notes.")
    # The notes modes exist to move a PR across devices via origin, so they are
    # the opposite of working with no remote at all.
    if args.no_remote and any(notes_modes):
        cli.die("--no-remote cannot be combined with the --*-notes cross-device modes.")

    # Device B never touches the local worktree; it works purely from origin.
    if args.gh_from_notes or args.web_from_notes:
        create_from_notes(args)
        return

    # --- gather state ----------------------------------------------------------

    cli.section("Worktree setup")

    branch = cli.capture_ok(["git", "symbolic-ref", "--short", "HEAD"])
    if not branch:
        cli.die("Not on a branch (detached HEAD?). Check out the wt/ branch first.")

    if branch in ("main", "master", "develop", "dev"):
        cli.die(
            f"On '{branch}'; this script is for wt/ feature branches, "
            "not the integration/release branch."
        )
    if not branch.startswith("wt/"):
        cli.warn(f"  Warning: branch '{branch}' does not look like a wt/ branch.")
        if not cli.confirm("  Continue anyway?"):
            sys.exit(1)

    repo_root = Path(cli.capture(["git", "rev-parse", "--show-toplevel"]))

    # Resolve the PR base. Read it from the branch's configured upstream,
    # because a later `git push -u` will repoint tracking to origin/<branch>
    # and lose it.
    base = args.base
    if not base:
        merge = cli.capture_ok(["git", "config", f"branch.{branch}.merge"])
        tracked_base = merge.removeprefix("refs/heads/") if merge else None
        if tracked_base == branch:
            # A prior `complete_worktree.py` run already pushed this branch
            # with `-u`, which repoints tracking to origin/<branch> itself
            # (e.g. completing a second PR from the same worktree). The
            # original base is gone; ask instead of targeting the branch
            # against itself.
            cli.warn(f"  '{branch}' tracks itself (already pushed by a prior run);")
            cli.warn("  original base is lost.")
            base = cli.prompt_value("  Enter the PR base branch", default="develop")
        elif not tracked_base:
            cli.warn(f"  No upstream configured for '{branch}'.")
            base = cli.prompt_value("  Enter the PR base branch", default="develop")
        else:
            base = tracked_base
        if base in ("main", "master"):
            cli.die(
                f"Refusing to target '{base}'. This project uses git flow; PRs go to "
                "develop. Pass --base to override deliberately."
            )

    cli.info("Worktree", str(repo_root))
    cli.info("Source branch", branch)
    cli.info("PR base", base if not args.no_remote else f"{base} (merge target)")
    cli.info("Remote", "skipped (--no-remote)" if args.no_remote else "origin")

    # --- PR body ---------------------------------------------------------------

    # With --no-remote there is no PR, so no body file and no title are needed;
    # the clean-tree check below then has nothing to exempt.
    body_path: Path | None = None
    body_name = ""
    title = ""
    body_text = ""
    if not args.no_remote:
        body_path, title, body_text = read_pr_body(args, repo_root)
        body_name = body_path.name

    # --- working tree status ---------------------------------------------------

    check_working_tree(repo_root, body_path)

    if args.no_remote:
        merge_locally(branch, base)
        return

    # --- existing PR guard (gh; skipped when only pushing the note) ------------

    existing_url = None
    if not args.push_pr_to_notes:
        cli.section("Existing PR check")
        # gh matches any PR ever associated with the branch (open, closed, or
        # merged); filter to OPEN so a past merged/closed PR doesn't block
        # opening a new one for the same branch name.
        existing_url = cli.capture_ok(
            [
                "gh",
                "pr",
                "view",
                branch,
                "--json",
                "url,state",
                "--jq",
                'select(.state == "OPEN") | .url',
            ]
        )
        if existing_url:
            cli.warn(f"  A pull request already exists for '{branch}':")
            print(f"  {existing_url}")
            cli.warn("  Pushing will update it; a new PR will not be created.")
        else:
            cli.success("  No existing open PR for this branch.")

    # --- push ------------------------------------------------------------------

    cli.section("Step: push branch")
    cli.step(f"Push '{branch}' to origin (with -u)?")
    cli.run(["git", "push", "-u", "origin", "HEAD"])

    # --- device A: attach the PR body as a note and stop -----------------------

    if args.push_pr_to_notes:
        push_pr_note(base, title, body_text, body_name, branch)
        return

    # --- open PR ---------------------------------------------------------------

    if existing_url:
        cli.section("Done")
        cli.success("  Branch pushed; existing PR updated.")
        cli.info("PR", existing_url)
        cli.info("Current branch", cli.capture(["git", "branch", "--show-current"]))
        print()
        print(f"  {cli.GRAY}Worktree left in place for you to clean up.{cli.RESET}")
        return

    open_pull_request(args, branch, base, title, body_text)


def read_pr_body(args: argparse.Namespace, repo_root: Path) -> tuple[Path, str, str]:
    """Read the PR body file, show it, and settle the PR title.

    Args:
        args: Parsed command line (``--body-file`` and ``--title``).
        repo_root: The worktree root, for resolving a relative body path.

    Returns:
        ``(body_path, title, body_text)`` — the resolved body file, the
        confirmed title, and the front-matter-stripped body.
    """
    cli.section("PR body")
    body_path = Path(args.body_file)
    if not body_path.is_absolute():
        body_path = repo_root / body_path

    if not body_path.exists():
        cli.die(
            f"PR body file not found: {body_path}. "
            f"Write the PR description to {PR_FILE_PATH} first."
        )
    raw_body = body_path.read_text(encoding="utf-8-sig")
    if not raw_body.strip():
        cli.die(f"PR body file is empty: {body_path}.")
    # The body file carries the title in fenced front-matter; the body sent to
    # gh is everything after the closing fence.
    _, fm_title, body_text = parse_front_matter(raw_body)
    cli.info("Body file", str(body_path))
    print()
    print(f"{cli.GRAY}{body_text.rstrip()}{cli.RESET}")

    # --- title -----------------------------------------------------------------

    title = args.title or fm_title
    if not title:
        cli.die(
            f"No PR title in {body_path.name}. Its first lines must be fenced "
            "front-matter setting the title, e.g.:\n"
            "  ---\n  title: feat(scope): summary\n  ---\n  <body...>"
        )
    cli.section("PR title")
    cli.info("PR title", title)
    if not cli.confirm("  Use this title?"):
        title = cli.prompt_value("  Enter the PR title")
    if not title.strip():
        cli.die("PR title cannot be empty.")

    return body_path, title, body_text


def check_working_tree(repo_root: Path, body_path: Path | None) -> None:
    """Refuse to continue unless everything in the worktree is committed.

    Args:
        repo_root: The worktree root.
        body_path: The PR body file, exempt from the check because it only
            feeds the PR and may stay uncommitted; ``None`` when there is no
            PR body (``--no-remote``), in which case nothing is exempt.
    """
    cli.section("Working tree status")
    cli.run(["git", "status", "--short", "--branch"])

    exempt: str | None = None
    body_name = body_path.name if body_path is not None else ""
    if body_path is not None:
        # Only exempt the body file when it actually lives inside the worktree.
        try:
            exempt = body_path.resolve().relative_to(repo_root.resolve()).as_posix()
        except ValueError:
            exempt = None
    status_lines = cli.capture(["git", "status", "--porcelain"]).splitlines()
    dirty = dirty_status_lines(status_lines, exempt)
    if dirty:
        print()
        if exempt is None:
            cli.warn("  Working tree is not clean. Commit everything before completing.")
        else:
            cli.warn(
                f"  Working tree is not clean. Commit everything except {body_name} "
                "before completing the worktree."
            )
        cli.die("Uncommitted changes present; refusing to continue.")
    if exempt is None:
        cli.success("  Working tree is clean; all changes committed.")
    else:
        cli.success(f"  Working tree is clean; all changes committed ({exempt} is exempt).")


def open_pull_request(
    args: argparse.Namespace, branch: str, base: str, title: str, body_text: str
) -> None:
    """Create the pull request with gh and report its URL.

    Args:
        args: Parsed command line (``--draft``).
        branch: The wt/ branch the PR comes from.
        base: The PR base branch.
        title: The confirmed PR title.
        body_text: The front-matter-stripped PR body.
    """
    cli.section("Step: open pull request")
    draft_note = " (draft)" if args.draft else ""
    cli.step(f"Open a PR from '{branch}' into '{base}'?{draft_note}")

    # Deliver the front-matter-stripped body via a temp file so the title/fence
    # lines never leak into the PR body (mirrors the --gh-from-notes path).
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as handle:
        handle.write(body_text)
        body_file = handle.name
    try:
        create_args = ["gh", "pr", "create", "--base", base, "--title", title]
        create_args += ["--body-file", body_file]
        if args.draft:
            create_args.append("--draft")
        # Capture stdout for the URL; gh's progress messages stream on stderr.
        output = cli.capture(create_args, echo_cmd=True)
    finally:
        Path(body_file).unlink(missing_ok=True)
    print(output)
    pr_url = output.splitlines()[-1].strip() if output else "(unknown)"

    # --- done ------------------------------------------------------------------

    cli.section("Done")
    cli.success("  Pull request opened.")
    cli.info("PR", pr_url)
    cli.info("Base", base)
    cli.info("Current branch", cli.capture(["git", "branch", "--show-current"]))
    print()
    print(f"  {cli.GRAY}Worktree left in place for you to clean up.{cli.RESET}")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):  # fmt: skip
        print()
        sys.exit(130)
