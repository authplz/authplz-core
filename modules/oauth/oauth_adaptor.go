package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/ory-am/fosite"
	"golang.org/x/net/context"
	"strings"
)

// OauthAdaptor adapts a generic interface for osin compliance
type OauthAdaptor struct {
	Storer Storer
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
	if err != nil {
		return nil, err
	}

	if c == nil {
		return nil, fmt.Errorf("Could not locate client: %s", id)
	}

	cw := NewClientWrapper(c)

	return fosite.Client(cw), err
}

// Authorize code storage

/*
func (oa* OauthAdaptor) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) (err error) {

}

func (oa* OauthAdaptor) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (request fosite.Requester, err error) {

}

func (oa* OauthAdaptor) DeleteAuthorizeCodeSession(ctx context.Context, code string) (err error) {

}
*/

// Access code storage (used by all implementations)

func (oa *OauthAdaptor) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error) {
	a, err := oa.Storer.GetAccessBySignature(signature)
	if err != nil {
		return nil, err
	}

	return a.(fosite.Requester), nil
}

func (oa *OauthAdaptor) CreateAccessTokenSession(c context.Context, signature string, request fosite.Requester) (err error) {
	client := request.GetClient().(*ClientWrapper)

	requestedScopes := strings.Join(request.GetRequestedScopes(), ";")
	grantedScopes := strings.Join(request.GetGrantedScopes(), ";")

	_, err = oa.Storer.AddAccessTokenSession(client.GetID(), signature, request.GetID(), request.GetRequestedAt(), requestedScopes, grantedScopes, "")

	return err
}

func (oa *OauthAdaptor) DeleteAccessTokenSession(ctx context.Context, signature string) (err error) {
	return oa.Storer.RemoveAccessToken(signature)
}

// Refresh token storage

func (oa *OauthAdaptor) CreateRefreshTokenSession(ctx context.Context, signature string, request fosite.Requester) (err error) {
	client := request.GetClient().(*ClientWrapper)

	requestedScopes := []string(request.GetRequestedScopes())
	grantedScopes := []string(request.GetGrantedScopes())

	_, err = oa.Storer.AddRefreshTokenSession(client.GetID(), signature, request.GetID(), request.GetRequestedAt(), requestedScopes, grantedScopes)

	return err
}

func (oa *OauthAdaptor) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error) {
	a, err := oa.Storer.GetRefreshTokenBySignature(signature)
	if err != nil {
		return nil, err
	}

	return a.(fosite.Requester), nil
}

func (oa *OauthAdaptor) PersistRefreshTokenGrantSession(ctx context.Context, originalRefreshSignature, accessSignature, refreshSignature string, request fosite.Requester) error {
	if err := oa.DeleteRefreshTokenSession(ctx, originalRefreshSignature); err != nil {
		return err
	} else if err := oa.CreateAccessTokenSession(ctx, accessSignature, request); err != nil {
		return err
	} else if err := oa.CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
		return err
	}
	return fosite.ErrAccessDenied
}

func (oa *OauthAdaptor) DeleteRefreshTokenSession(ctx context.Context, signature string) (err error) {
	return oa.Storer.RemoveRefreshToken(signature)
}
