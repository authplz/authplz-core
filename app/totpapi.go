package app

import "net/http"

import "github.com/gocraft/web"

func (c *AuthPlzTempCtx) TOTPEnrolGet(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusNotImplemented)
}

func (c *AuthPlzTempCtx) TOTPEnrolPost(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusNotImplemented)
}

func (c *AuthPlzTempCtx) TOTPBindAuthenticationRequest(rw web.ResponseWriter, req *web.Request, userid string) {
	rw.WriteHeader(http.StatusNotImplemented)
}

func (c *AuthPlzTempCtx) TOTPAuthenticateGet(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusNotImplemented)
}

func (c *AuthPlzTempCtx) TOTPAuthenticatePost(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusNotImplemented)
}
