package logcontroller

import "github.com/ryankurte/authplz/datastore"

// Interface that datastore must implement to provide audit controller
type LogStoreInterface interface {
    AddAuditEvent(u *datastore.User, token *datastore.AuditEvent) (user *datastore.User, err error)
    //GetAuditEvents(u *datastore.User) (user *[]datastore.AuditEvent, err error)
}

// Audit controller interface
type LogController struct {
    logStore LogStoreInterface
}

type UserEvent string;

const CreationEvent         UserEvent = "creation"
const LoginEvent            UserEvent = "login"
const PasswordChangeEvent   UserEvent = "password change"

// Instantiate a mail controller
func NewLogController(logStore LogStoreInterface) (*LogController) {

    return &LogController{logStore: logStore}
}

func (ac *LogController) AddEvent(user *datastore.User, event UserEvent) (err error) {


    return nil
}



