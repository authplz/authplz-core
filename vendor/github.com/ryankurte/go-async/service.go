package async

// Asynchronous Service Interface
// Services should implement this interface for use with the AsyncService container
type AsyncServiceInterface interface {
	HandleEvent(event interface{}) error
}

// Asynchronous service container
type AsyncService struct {
	c chan interface{}
	i AsyncServiceInterface
}

// Create an asynchronous service container
// Consumes an AsyncServiceInterface to create a RunnableInterface
func NewAsyncService(i AsyncServiceInterface, channelSize uint) AsyncService {

	// Create inbound channel
	c := make(chan interface{}, channelSize)

	// Create event sync object
	return AsyncService{c: c, i: i}
}

// Send an event to an asynchronous service via the internal channel
func (svc *AsyncService) SendEvent(e interface{}) error {
	svc.c <- e
	return nil
}

// Exit an asynchronous service routine
func (svc *AsyncService) Exit() error {
	// Close channel, triggering runner to exit
	close(svc.c)
	return nil
}

// Internal service run function
// Waits on channel, calls HandleEvent when events are received and exits the runner when the channel closes
func (svc *AsyncService) Run() error {
	for {
		e, open := <-svc.c
		if open {
			// Call event handler
			svc.i.HandleEvent(e)
		} else {
			// Exit runner
			break
		}
	}
	return nil
}
