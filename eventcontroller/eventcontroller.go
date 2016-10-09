package eventcontroller


type EventString string;
const CreationEvent         EventString = "creation"
const LoginEvent            EventString = "login"
const PasswordChangeEvent   EventString = "password change"

type SystemEvent struct {
    EventType string
}

// Interface that datastore must implement to provide audit controller
type ServiceInterface interface {
    SendEvent(e SystemEvent) (err error)
    //GetAuditEvents(u *datastore.User) (user *[]datastore.AuditEvent, err error)
}

// Audit controller interface
type EventController struct {
    
}

type EventSink struct {
    c chan *SystemEvent
}

func NewEventSink() (EventSink){
    // Create inbound channel
    c := make(chan *SystemEvent, 100)

    // Create event sync object
    return EventSink{c: c}
}

func (ec *EventSink) GetEvent() (e *SystemEvent) {
    return <- ec.c
}

// Instantiate a mail controller
func NewEventController() (*EventController) {

    return &EventController{}
}

func (ec *EventController) SendEvent(event SystemEvent) (err error) {


    return nil
}



