package audit

import (
	"log"
	"time"
)

// Audit controller interface
type AuditController struct {
	store AuditStoreInterface
}

// Instantiate an audit controller
func NewAuditController(store AuditStoreInterface) *AuditController {
	return &AuditController{store: store}
}

// Add an event to the audit log
func (ac *AuditController) AddEvent(u interface{}, eventType string, eventTime time.Time, data map[string]string) error {
	user := u.(AuditUserI)

	e, err := ac.store.AddAuditEvent(user.GetExtId(), eventType, eventTime, data)
	if err != nil {
		log.Printf("AuditController.AddEvent: error adding audit event (%s)", err)
		return err
	}

    log.Printf("AuditController.AddEvent: added event %+v", e)

	return nil
}

// Event handler function for go-async
func (ac *AuditController) HandleEvent(event interface{}) error {
	auditEvent := event.(AuditEventI)
	ac.AddEvent(auditEvent.GetUser(), auditEvent.GetType(), auditEvent.GetTime(), auditEvent.GetData())
	return nil
}

// List events
func (ac *AuditController) ListEvents(userid string) ([]interface{}, error) {

    events, err := ac.store.GetAuditEvents(userid)
    if err != nil {
        log.Printf("AuditController.AddEvent: error adding audit event (%s)", err)
        return events, err
    }

    return events, err
}
