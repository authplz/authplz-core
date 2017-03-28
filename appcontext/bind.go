package appcontext

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"

	"github.com/gocraft/web"
)

// BindInst Binds an object instance to a session key and writes to the browser session store
// TODO: Bindings should probably time out eventually
func (c *AuthPlzCtx) BindInst(rw web.ResponseWriter, req *web.Request, sessionKey, dataKey string, inst interface{}) {
	session, err := c.Global.SessionStore.Get(req.Request, sessionKey)
	if err != nil {
		log.Printf("AuthPlzCtx.Bind error fetching session-key:%s (%s)", sessionKey, err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Encode Data
	data, err := json.Marshal(inst)
	if err != nil {
		log.Printf("AuthPlzCtx.Bind encoding error: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	str := base64.StdEncoding.EncodeToString(data)

	session.Values[dataKey] = str
	session.Save(req.Request, rw)
}

// GetInst Fetches an object instance by session key from the browser session store
func (c *AuthPlzCtx) GetInst(rw web.ResponseWriter, req *web.Request, sessionKey, dataKey string, inst interface{}) error {
	session, err := c.Global.SessionStore.Get(req.Request, sessionKey)
	if err != nil {
		log.Printf("AuthPlzCtx.GetInst error fetching session-key:%s (%s)", sessionKey, err)
		rw.WriteHeader(http.StatusInternalServerError)
		return nil
	}

	if session.Values[dataKey] == nil {
		log.Printf("AuthPlzCtx.GetInst error no dataKey: %s found in session: %s", dataKey, sessionKey)
		rw.WriteHeader(http.StatusInternalServerError)
		return nil
	}

	str := session.Values[dataKey].(string)

	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		log.Printf("AuthPlzCtx.GetInst base64 decoding error: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return nil
	}

	err = json.Unmarshal(data, inst)
	if err != nil {
		log.Printf("AuthPlzCtx.GetInst JSON decoding error: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return nil
	}

	return nil
}
