package repository

import (
	"context"

	"github.com/roberveral/mimir/oauth/model"
)

// AuthorizationCodeRepository is the storage where information about
// used authorization codes is stored.
type AuthorizationCodeRepository interface {
	// StoreUsedAuthorizationCode stores a used authorization code in the storage.
	// It should not fail if the code is already stored.
	StoreUsedAuthorizationCode(ctx context.Context, code *model.OAuthAuthorizationCode) error

	// CheckAuthorizationCodeByID checks if the given tokenID is stored as used
	// in the persistence. If so, it returns true.
	CheckAuthorizationCodeByID(ctx context.Context, tokenID string) (bool, error)
}
