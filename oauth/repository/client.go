package repository

import (
	"context"

	"github.com/roberveral/mimir/oauth/model"
)

// ClientRepository is the storage where clients registered with the Authorization Server
// are stored.
type ClientRepository interface {
	// StoreClient stores a client in the persistence. If a client with the
	// same clientID already exists, it's overwritten. If something goes wrong
	// an error is returned.
	StoreClient(ctx context.Context, client *model.Client) (*model.Client, error)

	// GetClientByID obtains a client from the persistence with the given clientID.
	// If there isn't a client with the provided ID, (nil, nil) is returned.
	GetClientByID(ctx context.Context, clientID string) (*model.Client, error)

	// GetAllClientsByOwner obtains all the clients from the persistence which
	// owner is the given user. If there aren'y any clients owned by that user,
	// an empty slice is returned.
	GetAllClientsByOwner(ctx context.Context, owner string) ([]*model.Client, error)

	// DeleteClientByID removes the client with the given ID from the persistence.
	// It should not fail if the client was already removed.
	DeleteClientByID(ctx context.Context, clientID string) error

	// DeleteClient removes the given client from the persistence.
	// It should not fail if the client was already removed.
	DeleteClient(ctx context.Context, client *model.Client) error
}
