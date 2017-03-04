package audit


// Audit event type interface
// Underlying storage implementations must implement this interface
type AuditEvent interface {
    GetType() string
    GetMessage() string
    GetData() (map[string]string, error)
}

// Interface that datastore must implement to provide audit controller
type AuditStoreInterface interface {
    AddAuditEvent(userid, eventType, eventMessage string, data map[string]string) (interface{}, error)
    GetAuditEvents(userid string) ([]interface{}, error)
}