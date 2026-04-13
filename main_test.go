package main

import "testing"

func TestCurrentVersionPrefersGitTags(t *testing.T) {
	oldGitCommit, oldGitTags := gitCommit, gitTags
	t.Cleanup(func() {
		gitCommit = oldGitCommit
		gitTags = oldGitTags
	})

	gitCommit = "deadbeef"
	gitTags = "v2.5.0"

	if got := currentVersion(); got != "v2.5.0" {
		t.Fatalf("currentVersion() = %q, want %q", got, "v2.5.0")
	}
}

func TestCurrentVersionFallsBackToGitCommit(t *testing.T) {
	oldGitCommit, oldGitTags := gitCommit, gitTags
	t.Cleanup(func() {
		gitCommit = oldGitCommit
		gitTags = oldGitTags
	})

	gitCommit = "deadbeef"
	gitTags = ""

	if got := currentVersion(); got != "deadbeef" {
		t.Fatalf("currentVersion() = %q, want %q", got, "deadbeef")
	}
}

func TestCurrentVersionFallsBackToDevelopment(t *testing.T) {
	oldGitCommit, oldGitTags := gitCommit, gitTags
	t.Cleanup(func() {
		gitCommit = oldGitCommit
		gitTags = oldGitTags
	})

	gitCommit = "{STABLE_GIT_COMMIT}"
	gitTags = "{GIT_TAGS}"

	if got := currentVersion(); got != "development" {
		t.Fatalf("currentVersion() = %q, want %q", got, "development")
	}
}
