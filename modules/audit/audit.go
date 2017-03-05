package audit

import (
	"log"
	"time"
)

// Controller instance
type Controller struct {
	store Storer
}

// NewController Instantiates an audit controller
func NewController(store Storer) *Controller {
	return &Controller{store: store}
}

// AddEvent adds an event to the audit log
func (ac *Controller) AddEvent(u interface{}, eventType string, eventTime time.Time, data map[string]string) error {
	user := u.(User)

	_, err := ac.store.AddAuditEvent(user.GetExtId(), eventType, eventTime, data)
	if err != nil {
		log.Printf("AuditController.AddEvent: error adding audit event (%s)", err)
		return err
	}

	log.Printf("AuditController.AddEvent: added event %s for user %s", eventType, user.GetExtId())

	return nil
}

// HandleEvent handles async events for go-async
func (ac *Controller) HandleEvent(event interface{}) error {
	auditEvent := event.(Event)
	ac.AddEvent(auditEvent.GetUser(), auditEvent.GetType(), auditEvent.GetTime(), auditEvent.GetData())
	return nil
}

// ListEvents fetches events for the provided userID
func (ac *Controller) ListEvents(userid string) ([]interface{}, error) {

	events, err := ac.store.GetAuditEvents(userid)
	if err != nil {
		log.Printf("AuditController.AddEvent: error adding audit event (%s)", err)
		return events, err
	}

	return events, err
}
