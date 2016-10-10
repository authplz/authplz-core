package eventcontroller

import "sync"
import "fmt"

type SystemEvent interface{}

// Interface that services must implement
type ServiceInterface interface {
	Run() error
	Exit() error
	SendEvent(e SystemEvent) error
}

// Asynchronous service / event sink
type AsyncService struct {
	c chan SystemEvent
}

func NewAsyncService() AsyncService {
	// Create inbound channel
	c := make(chan SystemEvent, 100)

	// Create event sync object
	return AsyncService{c: c}
}

func (sink *AsyncService) GetEvent() (SystemEvent, bool) {
	e, open := <-sink.c
	return e, open
}

func (sink *AsyncService) SendEvent(e SystemEvent) error {
	sink.c <- e
	return nil
}

func (sink *AsyncService) Exit() error {
	// Close channel, triggering runner to exit
	close(sink.c)
	return nil
}

// Event controller interface
type EventController struct {
	in       chan SystemEvent
	services []ServiceInterface
	wg       sync.WaitGroup
}

// Instantiate a mail controller
func NewEventController() *EventController {

	in := make(chan SystemEvent, 100)

	return &EventController{in: in}
}

// Send an event to all bound services
func (ec *EventController) SendEvent(event SystemEvent) {
	ec.in <- event
}

// Bind a service to the event controller
func (ec *EventController) BindService(service ServiceInterface) {
	ec.services = append(ec.services, service)
}

func (ec *EventController) execute(service ServiceInterface) {
	fmt.Println("Starting service")
	service.Run()
	defer ec.wg.Done()
}

// Event loop / distribution routine
func (ec *EventController) EventLoop() (err error) {
	// Run event loop
	for {
		// Await event on global channel
		event, open := <-ec.in

		if open {
			// Dispatch to bound services
			for _, s := range ec.services {
				s.SendEvent(event)
			}
		} else {
			// Close service channels
			fmt.Println("Exiting services")
			for _, s := range ec.services {
				s.Exit()
			}
			break
		}
	}
	return nil
}

func (ec *EventController) Exit() (err error) {
	close(ec.in)

	ec.wg.Wait()

	return nil
}

// Run the event controller
func (ec *EventController) Run() (err error) {

	// Launch services
	for _, s := range ec.services {
		ec.wg.Add(1)
		go ec.execute(s)
	}

	// Start event loop
	go ec.EventLoop()

	return nil
}
