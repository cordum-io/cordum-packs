package services

import (
	"strings"
	"testing"
)

func assertErrMsg(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %q, got nil", want)
	}
	if err.Error() != want {
		t.Fatalf("expected error %q, got %q", want, err.Error())
	}
}

func assertErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected error containing %q, got %q", want, err.Error())
	}
}

func TestPageSizeParamClampsRange(t *testing.T) {
	t.Parallel()

	got, err := pageSizeParam(map[string]any{"page_size": maxListPageSize + 50})
	if err != nil {
		t.Fatalf("pageSizeParam returned error: %v", err)
	}
	if got != maxListPageSize {
		t.Fatalf("expected clamped page size %d, got %d", maxListPageSize, got)
	}
}
