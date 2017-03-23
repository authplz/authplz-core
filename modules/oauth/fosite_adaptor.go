package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/ory-am/fosite"
	"golang.org/x/net/context"
)

// FositeAdaptor adapts a generic interface for osin compliance
type FositeAdaptor struct {
	Storer Storer
}

// NewAdaptor creates a new wraper/adaptor around a Storer interface
func NewAdaptor(s Storer) *FositeAdaptor {
	return &FositeAdaptor{s}
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

func (oa *FositeAdaptor) GetClient(id string) (fosite.Client, error) {
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

func (oa *FositeAdaptor) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) (err error) {
	client := request.GetClient().(*ClientWrapper)
	session := request.GetSession().(*SessionWrap)

	requestedScopes := []string(request.GetRequestedScopes())
	grantedScopes := []string(request.GetGrantedScopes())

	_, err = oa.Storer.AddAuthorizeCodeSession(session.GetUserID(), client.GetID(), code, request.GetID(), request.GetRequestedAt(),
		session.GetAuthorizeExpiry(), requestedScopes, grantedScopes)

	return err
}

func (oa *FositeAdaptor) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (request fosite.Requester, err error) {
	a, err := oa.Storer.GetAuthorizeCodeSession(code)
	if err != nil {
		return nil, err
	}

	return a.(fosite.Requester), nil
}

func (oa *FositeAdaptor) PersistAuthorizeCodeGrantSession(ctx context.Context, authorizeCode, accessSignature, refreshSignature string,
	request fosite.Requester) error {

	if err := oa.DeleteAuthorizeCodeSession(ctx, authorizeCode); err != nil {
		return err
	} else if err := oa.CreateAccessTokenSession(ctx, accessSignature, request); err != nil {
		return err
	} else if refreshSignature == "" {
		return nil
	} else if err := oa.CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
		return err
	}

	return nil
}

func (oa *FositeAdaptor) DeleteAuthorizeCodeSession(ctx context.Context, code string) (err error) {
	return oa.Storer.RemoveAuthorizeCodeSession(code)
}

// Access code storage (used by all implementations)

func (oa *FositeAdaptor) CreateAccessTokenSession(c context.Context, signature string, request fosite.Requester) (err error) {
	client := request.GetClient().(*ClientWrapper)
	session := request.GetSession().(*SessionWrap)

	requestedScopes := []string(request.GetRequestedScopes())
	grantedScopes := []string(request.GetGrantedScopes())

	_, err = oa.Storer.AddAccessTokenSession(session.GetUserID(), client.GetID(), signature, request.GetID(), request.GetRequestedAt(),
		session.GetAccessExpiry(), requestedScopes, grantedScopes)

	return err
}

func (oa *FositeAdaptor) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error) {
	a, err := oa.Storer.GetAccessTokenSession(signature)
	if err != nil {
		return nil, err
	}

	return a.(fosite.Requester), nil
}

func (oa *FositeAdaptor) RevokeAccessToken(ctx context.Context, requestID string) error {
	token, err := oa.Storer.GetAccessTokenSessionByRequestID(requestID)
	if err != nil {
		return err
	}

	t := token.(AccessTokenSession)

	return oa.DeleteAccessTokenSession(ctx, t.GetSignature())
}

func (oa *FositeAdaptor) DeleteAccessTokenSession(ctx context.Context, signature string) (err error) {
	return oa.Storer.RemoveAccessTokenSession(signature)
}

// Refresh token storage

func (oa *FositeAdaptor) CreateRefreshTokenSession(ctx context.Context, signature string, request fosite.Requester) (err error) {
	client := request.GetClient().(*ClientWrapper)
	session := request.GetSession().(*SessionWrap)

	requestedScopes := []string(request.GetRequestedScopes())
	grantedScopes := []string(request.GetGrantedScopes())

	_, err = oa.Storer.AddRefreshTokenSession(session.GetUserID(), client.GetID(), signature, request.GetID(), request.GetRequestedAt(),
		session.GetRefreshExpiry(), requestedScopes, grantedScopes)

	return err
}

func (oa *FositeAdaptor) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error) {
	a, err := oa.Storer.GetRefreshTokenBySignature(signature)
	if err != nil {
		return nil, err
	}

	return a.(fosite.Requester), nil
}

func (oa *FositeAdaptor) PersistRefreshTokenGrantSession(ctx context.Context, originalRefreshSignature, accessSignature,
	refreshSignature string, request fosite.Requester) error {

	if err := oa.DeleteRefreshTokenSession(ctx, originalRefreshSignature); err != nil {
		return err
	} else if err := oa.CreateAccessTokenSession(ctx, accessSignature, request); err != nil {
		return err
	} else if err := oa.CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
		return err
	}
	return fosite.ErrAccessDenied
}

func (oa *FositeAdaptor) RevokeRefreshToken(ctx context.Context, requestID string) error {
	token, err := oa.Storer.GetRefreshTokenSessionByRequestID(requestID)
	if err != nil {
		return err
	}

	t := token.(RefreshTokenSession)

	return oa.DeleteRefreshTokenSession(ctx, t.GetSignature())
}

func (oa *FositeAdaptor) DeleteRefreshTokenSession(ctx context.Context, signature string) (err error) {
	return oa.Storer.RemoveRefreshToken(signature)
}
