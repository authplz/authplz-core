package appcontext

import (
	"log"
	"net/http"

	"github.com/gocraft/web"
)

// BindInst Binds an object instance to a session key and writes to the browser session store
// TODO: Bindings should probably time out eventually
func (c *AuthPlzCtx) BindInst(rw web.ResponseWriter, req *web.Request, sessionKey, dataKey string, inst interface{}) error {
	session, err := c.Global.SessionStore.Get(req.Request, sessionKey)
	if err != nil {
		log.Printf("AuthPlzCtx.Bind error fetching session-key:%s (%s)", sessionKey, err)
		rw.WriteHeader(http.StatusInternalServerError)
		return err
	}

	session.Values[dataKey] = inst
	session.Save(req.Request, rw)

	return nil
}

// GetInst Fetches an object instance by session key from the browser session store
func (c *AuthPlzCtx) GetInst(rw web.ResponseWriter, req *web.Request, sessionKey, dataKey string) (interface{}, error) {
	session, err := c.Global.SessionStore.Get(req.Request, sessionKey)
	if err != nil {
		log.Printf("AuthPlzCtx.GetInst error fetching session-key:%s (%s)", sessionKey, err)
		rw.WriteHeader(http.StatusInternalServerError)
		return nil, err
	}

	if session.Values[dataKey] == nil {
		log.Printf("AuthPlzCtx.GetInst error no dataKey: %s found in session: %s", dataKey, sessionKey)
		rw.WriteHeader(http.StatusInternalServerError)
		return nil, err
	}

	return session.Values[dataKey], nil
}
