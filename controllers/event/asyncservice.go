package event

import "fmt"

// Async services must implement an event handling interface
type AsyncServiceInterface interface {
	HandleEvent(event interface{}) error
}

// Asynchronous service object
type AsyncService struct {
	c chan interface{}
	i AsyncServiceInterface
}

// Create an async service routine
func NewAsyncService(i AsyncServiceInterface) AsyncService {

	// Create inbound channel
	c := make(chan interface{}, 100)

	// Create event sync object
	return AsyncService{c: c, i: i}
}

// Send an event to an asynchronous service
func (svc *AsyncService) SendEvent(e interface{}) error {
	svc.c <- e
	return nil
}

// Exit an async service routine
func (svc *AsyncService) Exit() error {
	// Close channel, triggering runner to exit
	close(svc.c)
	return nil
}

// Internal service run function
func (svc *AsyncService) Run() error {
	fmt.Println("Started runner")

	for {
		e, open := <-svc.c
		if open {
			// Call event handler
			svc.i.HandleEvent(e)
		} else {
			// Exit runner
			fmt.Println("Exiting runner")
			break
		}
	}

	return nil
}
