package policy

import (
	"errors"
	"fmt"
)

// UVPolicy controls how strictly user verification (a biometric or PIN,
// as opposed to mere user presence) is enforced.
type UVPolicy string

const (
	UVRequired    UVPolicy = "required"
	UVPreferred   UVPolicy = "preferred"
	UVDiscouraged UVPolicy = "discouraged"
)

var (
	ErrUserNotPresent  = errors.New("policy: user presence (UP) flag not set")
	ErrUserNotVerified = errors.New("policy: user verification (UV) required but not performed")
	ErrInvalidUVPolicy = errors.New("policy: invalid UV policy")
)

// CheckFlags enforces the UP/UV bits from authenticatorData against the
// configured policy. UP must always be set — that check is
// unconditional, not something any policy value can relax. UV is
// enforced only when policy is UVRequired; under UVPreferred or
// UVDiscouraged an unverified assertion is still accepted, but the
// caller gets back the actual UV state so it can record it on the
// session and make its own decision about lower-trust actions.
func CheckFlags(policy UVPolicy, up, uv bool) (uvPerformed bool, err error) {
	if !up {
		return false, ErrUserNotPresent
	}
	switch policy {
	case UVRequired:
		if !uv {
			return false, ErrUserNotVerified
		}
	case UVPreferred, UVDiscouraged:
		// Accepted regardless of uv; the actual state is still reported.
	default:
		return false, fmt.Errorf("%w: %q", ErrInvalidUVPolicy, policy)
	}
	return uv, nil
}
