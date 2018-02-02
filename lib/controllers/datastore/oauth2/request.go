/* AuthPlz Authentication and Authorization Microservice
 * OAuth data store - requests
 *
 * Copyright 2018 Ryan Kurte
 */

package oauthstore

import (
	"time"
)

// OauthRequest Base Type
// This is not stored directly, but used in other oauth types
type OauthRequest struct {
	RequestID       string
	RequestedAt     time.Time
	ExpiresAt       time.Time
	RequestedScopes string
	GrantedScopes   string
	Form            string
	Client          OauthClient  `sql:"-"`
	Session         OauthSession `sql:"-"`
}

// Getters and Setters

func (or *OauthRequest) GetRequestID() string {
	return or.RequestID
}

func (or *OauthRequest) SetRequestID(id string) {
	or.RequestID = id
}

func (or *OauthRequest) GetClient() interface{} {
	return &or.Client
}

func (or *OauthRequest) GetSession() interface{} {
	return &or.Session
}

func (or *OauthRequest) GetRequestedAt() time.Time {
	return or.RequestedAt
}

func (or *OauthRequest) GetExpiresAt() time.Time {
	return or.ExpiresAt
}

func (c *OauthRequest) GetRequestedScopes() []string {
	return stringToArray(c.RequestedScopes)
}

func (c *OauthRequest) SetRequestedScopes(scopes []string) {
	c.RequestedScopes = arrayToString(scopes)
}

func (c *OauthRequest) AppendRequestedScope(scope string) {
	c.SetRequestedScopes(append(c.GetRequestedScopes(), scope))
}

func (c *OauthRequest) GetGrantedScopes() []string {
	return stringToArray(c.GrantedScopes)
}

func (c *OauthRequest) SetGrantedScopes(scopes []string) {
	c.GrantedScopes = arrayToString(scopes)
}

func (c *OauthRequest) GrantScope(scope string) {
	c.SetGrantedScopes(append(c.GetGrantedScopes(), scope))
}

func (c *OauthRequest) Merge(a interface{}) {
	request := a.(*OauthRequest)

	for _, scope := range request.GetRequestedScopes() {
		c.AppendRequestedScope(scope)
	}
	for _, scope := range request.GetGrantedScopes() {
		c.GrantScope(scope)
	}
	c.RequestedAt = request.GetRequestedAt()
	c.Client = *request.GetClient().(*OauthClient)
	c.Session = *request.GetSession().(*OauthSession)

	/*
		for k, v := range request.GetRequestForm() {
			c.Form[k] = v
		}
	*/
}
