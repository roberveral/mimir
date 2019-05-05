package mongodb

import (
	"context"

	"github.com/roberveral/oauth-server/oauth/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Store implements ClientRepository and AuthCodeRepository
// storing data in MongoDB collections.
type Store struct {
	// Collection where clients are stored.
	client *mongo.Collection

	// Collection where used authorization codes are stored.
	authCode *mongo.Collection
}

// New creates a new Store which has implementations for all the repositories
// required by the Authorization Server.
func New(url string, dbName string) (*Store, error) {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(url))
	if err != nil {
		return nil, err
	}

	db := client.Database(dbName)

	return &Store{
		client:   db.Collection("client"),
		authCode: db.Collection("code"),
	}, nil
}

// StoreClient stores a client in the persistence. If a client with the
// same clientID already exists, it's overwritten. If something goes wrong
// an error is returned.
func (m *Store) StoreClient(ctx context.Context, client *model.Client) (*model.Client, error) {
	_, err := m.client.ReplaceOne(ctx,
		bson.D{
			{Key: "clientid", Value: client.ClientID},
		},
		client,
		options.Replace().SetUpsert(true))
	if err != nil {
		return nil, err
	}

	return client, nil
}

// GetClientByID obtains a client from the persistence with the given clientID.
// If there isn't a client with the provided ID, (nil, nil) is returned.
func (m *Store) GetClientByID(ctx context.Context, clientID string) (*model.Client, error) {
	var client model.Client
	err := m.client.FindOne(ctx,
		bson.D{
			{Key: "clientid", Value: clientID},
		}).Decode(&client)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return &client, nil
}

// GetAllClientsByOwner obtains all the clients from the persistence which
// owner is the given user. If there aren'y any clients owned by that user,
// an empty slice is returned.
func (m *Store) GetAllClientsByOwner(ctx context.Context, owner string) ([]*model.Client, error) {
	clients := make([]*model.Client, 0)
	cursor, err := m.client.Find(ctx, bson.D{
		{Key: "owner", Value: owner},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var client model.Client
		err := cursor.Decode(&client)
		if err != nil {
			return nil, err
		}
		clients = append(clients, &client)
	}

	if err := cursor.Err(); err != nil {
		return nil, err
	}

	return clients, nil
}

// DeleteClientByID removes the client with the given ID from the persistence.
// It should not fail if the client was already removed.
func (m *Store) DeleteClientByID(ctx context.Context, clientID string) error {
	_, err := m.client.DeleteOne(ctx,
		bson.D{
			{Key: "clientid", Value: clientID},
		})

	return err
}

// DeleteClient removes the given client from the persistence.
// It should not fail if the client was already removed.
func (m *Store) DeleteClient(ctx context.Context, client *model.Client) error {
	return m.DeleteClientByID(ctx, client.ClientID)
}

// StoreUsedAuthorizationCode stores a used authorization code in the storage.
// It should not fail if the code is already stored.
func (m *Store) StoreUsedAuthorizationCode(ctx context.Context, code *model.OAuthAuthorizationCode) error {
	_, err := m.authCode.ReplaceOne(ctx,
		bson.D{
			{Key: "tokenid", Value: code.TokenID},
		},
		code,
		options.Replace().SetUpsert(true))

	return err
}

// CheckAuthorizationCodeByID checks if the given tokenID is stored as used
// in the persistence. If so, it returns true.
func (m *Store) CheckAuthorizationCodeByID(ctx context.Context, tokenID string) (bool, error) {
	var code model.OAuthAuthorizationCode
	err := m.authCode.FindOne(ctx,
		bson.D{
			{Key: "tokenid", Value: tokenID},
		}).Decode(&code)
	if err == mongo.ErrNoDocuments {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return true, nil
}
