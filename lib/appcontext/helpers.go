package appcontext

import (
	"encoding/json"
	"github.com/authplz/authplz-core/lib/api"
	"log"
	"net/http"
)

// WriteJSON Helper to write objects out as JSON
func (c *AuthPlzCtx) WriteJSON(w http.ResponseWriter, i interface{}) {
	js, err := json.Marshal(i)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

// WriteAPIResult Helper to write API result messages
func (c *AuthPlzCtx) WriteAPIResult(w http.ResponseWriter, code string) {
	apiResp := api.Response{Code: code}
	c.WriteJSON(w, apiResp)
}

// WriteAPIResultWithCode Helper to write API result messsages while setting the HTTP response code
func (c *AuthPlzCtx) WriteAPIResultWithCode(w http.ResponseWriter, status int, code string) {
	apiResp := api.Response{Code: code}

	js, err := json.Marshal(&apiResp)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	w.Write(js)
}

// WriteUnauthorized helper to write unauthorized status and message
func (c *AuthPlzCtx) WriteUnauthorized(w http.ResponseWriter) {
	c.WriteAPIResultWithCode(w, http.StatusUnauthorized, api.Unauthorized)
}

// WriteInternalError helper to write internal error status and message
func (c *AuthPlzCtx) WriteInternalError(w http.ResponseWriter) {
	c.WriteAPIResultWithCode(w, http.StatusInternalServerError, api.InternalError)
}
