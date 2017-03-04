package audit

// Audit controller interface
type AuditController struct {
	store AuditStoreInterface
}

// Constant event types
type AuditEventType string

const (
	CreationEvent       AuditEventType = "creation"
	LoginEvent          AuditEventType = "login"
	PasswordChangeEvent AuditEventType = "password change"
)

// Instantiate an audit controller
func NewAuditController(store AuditStoreInterface) *AuditController {
	return &AuditController{store: store}
}

// Add an event to the audit log
func (ac *AuditController) AddEvent(userid string, eventType AuditEventType) (err error) {

	return nil
}
