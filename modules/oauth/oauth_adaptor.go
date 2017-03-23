package oauth

import (
	"context"
	"encoding/json"
	"github.com/ory-am/fosite"
	"strings"
)

// OauthAdaptor adapts a generic interface for osin compliance
type OauthAdaptor struct {
	Storer
}

// NewAdaptor creates a new wraper/adaptor around a Storer interface
func NewAdaptor(s Storer) *OauthAdaptor {
	return &OauthAdaptor{s}
}

func PackRequest(req *fosite.Request) (string, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func UnpackRequest(data string) (fosite.Request, error) {
	var req fosite.Request

	err := json.Unmarshal([]byte(data), &req)
	return req, err
}

// Client storage

func (oa *OauthAdaptor) GetClient(id string) (fosite.Client, error) {
	c, err := oa.Storer.GetClientByID(id)
	return c.(fosite.Client), err
}

// Access code storage (used by all implementations)

func (oa *OauthAdaptor) CreateAccessTokenSession(_ context.Context, signature string, req fosite.Requester) error {
	client := req.GetClient().(Client)

	requestedScopes := strings.Join(req.GetRequestedScopes(), ";")
	grantedScopes := strings.Join(req.GetGrantedScopes(), ";")

	_, err := oa.Storer.AddAccessTokenSession(client.GetID(), signature, req.GetID(), req.GetRequestedAt(), requestedScopes, grantedScopes, "")

	return err
}

/*
func (oa *OauthAdaptor) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error) {
	return nil, nil
}

func (oa *OauthAdaptor) DeleteAccessTokenSession(ctx context.Context, signature string) (err error) {
	return nil
}

func (oa *OauthAdaptor) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) (err error) {

}

func (oa *OauthAdaptor) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (request fosite.Requester, err error) {

}

func (oa *OauthAdaptor) DeleteAuthorizeCodeSession(ctx context.Context, code string) (err error) {

}


func (oa *OauthAdaptor) CreateRefreshTokenSession(ctx context.Context, signature string, request fosite.Requester) (err error) {

}

func (oa *OauthAdaptor) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error) {

}

func (oa *OauthAdaptor) DeleteRefreshTokenSession(ctx context.Context, signature string) (err error) {

}
*/
