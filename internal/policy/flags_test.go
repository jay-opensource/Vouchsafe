package policy

import (
	"errors"
	"testing"
)

func TestCheckFlags_UPMissingAlwaysRejected(t *testing.T) {
	for _, policy := range []UVPolicy{UVRequired, UVPreferred, UVDiscouraged} {
		for _, uv := range []bool{true, false} {
			_, err := CheckFlags(policy, false, uv)
			if !errors.Is(err, ErrUserNotPresent) {
				t.Fatalf("policy=%s uv=%v: got %v, want ErrUserNotPresent", policy, uv, err)
			}
		}
	}
}

func TestCheckFlags_Required_UVMissing(t *testing.T) {
	_, err := CheckFlags(UVRequired, true, false)
	if !errors.Is(err, ErrUserNotVerified) {
		t.Fatalf("got %v, want ErrUserNotVerified", err)
	}
}

func TestCheckFlags_Required_UVPresent(t *testing.T) {
	uvPerformed, err := CheckFlags(UVRequired, true, true)
	if err != nil {
		t.Fatalf("CheckFlags: %v", err)
	}
	if !uvPerformed {
		t.Fatalf("uvPerformed = false, want true")
	}
}

func TestCheckFlags_Preferred_AcceptsEitherUVState(t *testing.T) {
	uvPerformed, err := CheckFlags(UVPreferred, true, false)
	if err != nil {
		t.Fatalf("uv=false: %v", err)
	}
	if uvPerformed {
		t.Fatalf("uvPerformed = true, want false (reported state must match input)")
	}

	uvPerformed, err = CheckFlags(UVPreferred, true, true)
	if err != nil {
		t.Fatalf("uv=true: %v", err)
	}
	if !uvPerformed {
		t.Fatalf("uvPerformed = false, want true")
	}
}

func TestCheckFlags_Discouraged_AcceptsEitherUVState(t *testing.T) {
	if _, err := CheckFlags(UVDiscouraged, true, false); err != nil {
		t.Fatalf("uv=false: %v", err)
	}
	if _, err := CheckFlags(UVDiscouraged, true, true); err != nil {
		t.Fatalf("uv=true: %v", err)
	}
}

func TestCheckFlags_InvalidPolicy(t *testing.T) {
	_, err := CheckFlags(UVPolicy("bogus"), true, true)
	if !errors.Is(err, ErrInvalidUVPolicy) {
		t.Fatalf("got %v, want ErrInvalidUVPolicy", err)
	}
}

func TestEffectivePolicy_RequestedStricterWins(t *testing.T) {
	if got := EffectivePolicy(UVPreferred, UVRequired); got != UVRequired {
		t.Fatalf("got %q, want %q", got, UVRequired)
	}
}

func TestEffectivePolicy_RequestedWeakerIgnored(t *testing.T) {
	if got := EffectivePolicy(UVRequired, UVDiscouraged); got != UVRequired {
		t.Fatalf("got %q, want %q — a caller must never be able to loosen the server floor", got, UVRequired)
	}
}

func TestEffectivePolicy_RequestedEqualKeepsFloor(t *testing.T) {
	if got := EffectivePolicy(UVPreferred, UVPreferred); got != UVPreferred {
		t.Fatalf("got %q, want %q", got, UVPreferred)
	}
}

func TestEffectivePolicy_EmptyRequestedKeepsFloor(t *testing.T) {
	if got := EffectivePolicy(UVRequired, ""); got != UVRequired {
		t.Fatalf("got %q, want %q", got, UVRequired)
	}
}

func TestEffectivePolicy_InvalidRequestedIgnored(t *testing.T) {
	if got := EffectivePolicy(UVPreferred, UVPolicy("bogus")); got != UVPreferred {
		t.Fatalf("got %q, want %q — an unrecognized requested value must not override the floor", got, UVPreferred)
	}
}
