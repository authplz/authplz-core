package auditcontroller

import "github.com/ryankurte/authplz/datastore"

// Interface that datastore must implement to provide audit controller
type AuditStoreInterface interface {
    AddAuditEvent(u *datastore.User, token *datastore.AuditEvent) (user *datastore.User, err error)
    //GetAuditEvents(u *datastore.User) (user *[]datastore.AuditEvent, err error)
}

// Audit controller interface
type AuditController struct {
    auditStore AuditStoreInterface
}

type UserEvent string;

const CreationEvent         UserEvent = "creation"
const LoginEvent            UserEvent = "login"
const PasswordChangeEvent   UserEvent = "password change"

// Instantiate a mail controller
func NewAuditController(auditStore AuditStoreInterface) (*AuditController) {

    return &AuditController{auditStore: auditStore}
}

func (ac *AuditController) AddEvent(user *datastore.User, event UserEvent) (err error) {


    return nil
}



