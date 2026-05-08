// check-upstream verifies upstream dependencies against their current state.
//
// It reads UPSTREAM.md from the repository root, extracts recorded commit hashes,
// queries each upstream repository for its current HEAD via git ls-remote, and
// reports whether updates are available.
//
// For BIP85 spec PRs it:
//   - Reads tracked PRs from UPSTREAM.md (format: "  - #NNN - STATE - description")
//   - Queries GitHub for each PR's current state
//   - Updates UPSTREAM.md if state changed (e.g. OPEN -> MERGED)
//   - Discovers new BIP85-related PRs on bitcoin/bips and adds them automatically
//
// Usage:
//
//	go run ./tools/check-upstream/
//
// Exit codes:
//
//	0 - all upstreams up to date
//	1 - updates available or errors occurred
package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type upstream struct {
	Name   string
	Repo   string
	Commit string
}

type trackedPR struct {
	Number int
	State  string
	Desc   string
}

func main() {
	root, err := findRepoRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	upstreamFile := filepath.Join(root, "UPSTREAM.md")
	entries, err := parseUpstream(upstreamFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing UPSTREAM.md: %v\n", err)
		os.Exit(1)
	}

	if len(entries) == 0 {
		fmt.Println("No upstream entries found in UPSTREAM.md")
		os.Exit(0)
	}

	hasUpdates := false
	hasFailed := false

	fmt.Println("=== Upstream Dependency Check ===")

	for _, entry := range entries {
		fmt.Printf("\n## %s\n", entry.Name)
		fmt.Printf("   Repo:            %s\n", entry.Repo)
		fmt.Printf("   Recorded commit: %s\n", shortHash(entry.Commit))

		currentHead, err := getRemoteHead(entry.Repo)
		if err != nil {
			fmt.Printf("   ERROR: could not query remote: %v\n", err)
			hasFailed = true
			continue
		}

		if entry.Commit == "" {
			fmt.Printf("   Status: NO COMMIT RECORDED (current HEAD: %s)\n", shortHash(currentHead))
			hasFailed = true
		} else if strings.HasPrefix(currentHead, entry.Commit) || strings.HasPrefix(entry.Commit, currentHead) {
			fmt.Printf("   Status: UP TO DATE (%s)\n", shortHash(currentHead))
		} else {
			fmt.Printf("   Status: UPDATE AVAILABLE\n")
			fmt.Printf("   Current HEAD:    %s\n", shortHash(currentHead))
			hasUpdates = true
		}
	}

	// Check and update spec PR statuses
	fmt.Println("\n=== BIP85 Spec PR Status ===")
	prChanges := checkAndUpdatePRs(upstreamFile, &hasFailed)
	if prChanges {
		hasUpdates = true
	}

	// Update last-checked dates
	today := time.Now().Format("2006-01-02")
	if err := updateLastChecked(upstreamFile, today); err != nil {
		fmt.Fprintf(os.Stderr, "\nWARNING: could not update last-checked dates: %v\n", err)
	} else {
		fmt.Printf("\nUpdated 'Last checked' dates to %s in UPSTREAM.md\n", today)
	}

	if hasFailed {
		fmt.Println("\nRESULT: ERRORS occurred during check")
		os.Exit(1)
	}
	if hasUpdates {
		fmt.Println("\nRESULT: Updates available. Review changes in UPSTREAM.md.")
		os.Exit(1)
	}
	fmt.Println("\nRESULT: All upstreams up to date.")
}

func findRepoRoot() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("not in a git repository: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func parseUpstream(path string) ([]upstream, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entries []upstream
	var current upstream

	reCommit := regexp.MustCompile(`\*\*Commit (?:used|checked):\*\*\s*([a-f0-9]+)`)
	reRepo := regexp.MustCompile(`\*\*Repo:\*\*\s*(https://\S+)`)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")

		if strings.HasPrefix(line, "## ") {
			if current.Name != "" && current.Repo != "" {
				entries = append(entries, current)
			}
			current = upstream{Name: strings.TrimPrefix(line, "## ")}
		}

		if m := reRepo.FindStringSubmatch(line); m != nil {
			current.Repo = m[1]
		}
		if m := reCommit.FindStringSubmatch(line); m != nil {
			current.Commit = m[1]
		}
	}
	if current.Name != "" && current.Repo != "" {
		entries = append(entries, current)
	}

	return entries, nil
}

// parsePRs extracts tracked PR entries from UPSTREAM.md.
// Format: "  - #NNN - STATE - description"
var rePR = regexp.MustCompile(`^\s+-\s+#(\d+)\s+-\s+(\S+)\s+-\s+(.+)$`)

func parsePRs(path string) ([]trackedPR, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var prs []trackedPR
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if m := rePR.FindStringSubmatch(line); m != nil {
			num, _ := strconv.Atoi(m[1])
			prs = append(prs, trackedPR{Number: num, State: m[2], Desc: m[3]})
		}
	}
	return prs, nil
}

func getRemoteHead(repo string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "ls-remote", repo, "HEAD")
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("timed out after 30s")
		}
		return "", fmt.Errorf("git ls-remote failed: %w", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 1 {
		return "", fmt.Errorf("empty response from git ls-remote")
	}
	return fields[0], nil
}

// checkAndUpdatePRs queries GitHub for each tracked PR, updates UPSTREAM.md
// if state changed, and discovers new BIP85-related PRs. Returns true if
// any PR had a state change or new PRs were discovered.
func checkAndUpdatePRs(upstreamFile string, hasFailed *bool) bool {
	if _, err := exec.LookPath("gh"); err != nil {
		fmt.Println("   gh CLI not found. Install GitHub CLI to check PR statuses.")
		fmt.Println("   Skipping PR checks.")
		return false
	}

	existing, err := parsePRs(upstreamFile)
	if err != nil {
		fmt.Printf("   ERROR parsing PRs: %v\n", err)
		*hasFailed = true
		return false
	}

	anyChanged := false

	// Check each existing tracked PR
	for i, pr := range existing {
		fmt.Printf("\n   PR #%d: %s\n", pr.Number, pr.Desc)

		state, title, url, err := queryPR("bitcoin/bips", pr.Number)
		if err != nil {
			fmt.Printf("      ERROR: %v\n", err)
			*hasFailed = true
			continue
		}

		fmt.Printf("      State: %s\n", state)
		fmt.Printf("      Title: %s\n", title)
		fmt.Printf("      URL:   %s\n", url)

		if state != pr.State {
			fmt.Printf("      >>> STATE CHANGED: %s -> %s\n", pr.State, state)
			existing[i].State = state
			anyChanged = true
		}
	}

	// Discover new BIP85-related PRs
	newPRs := discoverNewPRs("bitcoin/bips", existing)
	if len(newPRs) > 0 {
		fmt.Printf("\n   --- Discovered %d new BIP85-related PR(s) ---\n", len(newPRs))
		for _, pr := range newPRs {
			fmt.Printf("   PR #%d: %s (state: %s)\n", pr.Number, pr.Desc, pr.State)
		}
		existing = append(existing, newPRs...)
		anyChanged = true
	}

	// Write back if anything changed
	if anyChanged {
		if err := writePRs(upstreamFile, existing); err != nil {
			fmt.Fprintf(os.Stderr, "\n   WARNING: could not update PRs in UPSTREAM.md: %v\n", err)
		} else {
			fmt.Println("\n   Updated PR statuses in UPSTREAM.md")
		}
	}

	return anyChanged
}

// queryPR queries a single PR via gh CLI. Returns (state, title, url, error).
func queryPR(repo string, number int) (string, string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "gh", "pr", "view",
		strconv.Itoa(number),
		"--repo", repo,
		"--json", "state,title,url",
		"--jq", `.state + " | " + .title + " | " + .url`,
	)
	out, err := cmd.Output()
	if err != nil {
		return "", "", "", fmt.Errorf("gh pr view #%d: %w", number, err)
	}

	result := strings.TrimSpace(string(out))
	parts := strings.SplitN(result, " | ", 3)
	if len(parts) < 3 {
		return "", "", "", fmt.Errorf("unexpected gh output: %s", result)
	}
	return parts[0], parts[1], parts[2], nil
}

// discoverNewPRs searches bitcoin/bips for open PRs mentioning BIP85/bip-0085
// that are not already tracked.
func discoverNewPRs(repo string, existing []trackedPR) []trackedPR {
	knownNumbers := make(map[int]bool)
	for _, pr := range existing {
		knownNumbers[pr.Number] = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Search for open PRs mentioning bip85 or bip-0085
	cmd := exec.CommandContext(ctx, "gh", "pr", "list",
		"--repo", repo,
		"--state", "open",
		"--search", "bip85 OR bip-0085 in:title",
		"--json", "number,title,state",
		"--jq", `.[] | "\(.number) | \(.state) | \(.title)"`,
	)
	out, err := cmd.Output()
	if err != nil {
		// Not fatal - discovery is best-effort
		return nil
	}

	var discovered []trackedPR
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.SplitN(line, " | ", 3)
		if len(parts) < 3 {
			continue
		}
		num, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		if knownNumbers[num] {
			continue
		}
		discovered = append(discovered, trackedPR{
			Number: num,
			State:  parts[1],
			Desc:   parts[2],
		})
	}
	return discovered
}

// writePRs replaces the tracked PR list in UPSTREAM.md with updated entries.
func writePRs(path string, prs []trackedPR) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Sort PRs by number for stable output
	sort.Slice(prs, func(i, j int) bool {
		return prs[i].Number < prs[j].Number
	})

	// Build new PR block
	var buf strings.Builder
	buf.WriteString("- **Tracked PRs:**\n")
	for _, pr := range prs {
		buf.WriteString(fmt.Sprintf("  - #%d - %s - %s\n", pr.Number, pr.State, pr.Desc))
	}

	// Replace existing PR block in the file.
	// The block starts with "- **Tracked PRs:**" and ends at the next blank line
	// or the next "##" heading or EOF.
	content := string(data)
	start := strings.Index(content, "- **Tracked PRs:**")
	if start < 0 {
		return fmt.Errorf("could not find '- **Tracked PRs:**' in UPSTREAM.md")
	}

	// Find the end: next line that doesn't start with "  - #"
	end := start
	lines := strings.SplitAfter(content[start:], "\n")
	for i, line := range lines {
		if i == 0 {
			// Skip the "- **Tracked PRs:**" header line
			end += len(line)
			continue
		}
		trimmed := strings.TrimRight(line, "\n\r")
		if strings.HasPrefix(trimmed, "  - #") {
			end += len(line)
		} else {
			break
		}
	}

	updated := content[:start] + buf.String() + content[end:]
	return os.WriteFile(path, []byte(updated), 0644)
}

func shortHash(h string) string {
	if len(h) >= 12 {
		return h[:12]
	}
	return h
}

func updateLastChecked(path, date string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	re := regexp.MustCompile(`\*\*Last checked:\*\*\s*\d{4}-\d{2}-\d{2}[^\n]*`)
	updated := re.ReplaceAllString(string(data), "**Last checked:** "+date)

	if updated == string(data) {
		return nil
	}
	return os.WriteFile(path, []byte(updated), 0644)
}
