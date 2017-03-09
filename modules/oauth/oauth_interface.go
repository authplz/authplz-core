package oauth

// Client OAuth client interface

// Storer OAuth storage interface
type Storer interface {
	//AddClient(clientID, secret, scope string) (interface{}, error)
	//GetClient(id string) (interface{}, error)
	GetClientByID(clientID string) (interface{}, error)
	//GetClientsByUser(userID string) ([]interface{}, error)
	//UpdateClient(client interface{}) (interface{}, error)
	//RemoveClient(clientID string) error
	//GetAccessToken(signature string) (interface{}, error)
}
