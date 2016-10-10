package eventcontroller

import "sync"
import "fmt"

// Interface that services must implement
type ServiceInterface interface {
	Run() error
	Exit() error
	SendEvent(e interface{}) error
}

// Event controller interface
type ServiceManager struct {
	in       chan interface{}
	services []ServiceInterface
	wg       sync.WaitGroup
}

// Instantiate a mail controller
func NewServiceManager() *ServiceManager {

	in := make(chan interface{}, 100)

	return &ServiceManager{in: in}
}

// Send an event to all bound services
func (ec *ServiceManager) SendEvent(event interface{}) {
	ec.in <- event
}

// Bind a service to the event controller
func (ec *ServiceManager) BindService(service ServiceInterface) {
	ec.services = append(ec.services, service)
}

// Event loop / distribution routine
func (ec *ServiceManager) EventLoop() (err error) {
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
			for _, s := range ec.services {
				s.Exit()
			}
			break
		}
	}
	return nil
}

// Exit the event controller
func (ec *ServiceManager) Exit() (err error) {
    fmt.Println("Exiting services")

    // Close input channel (causing child services to exit)
	close(ec.in)

    // Await exit of subroutines
	ec.wg.Wait()

    fmt.Println("Exited services")

	return nil
}

// Run the event controller
func (ec *ServiceManager) Run() (err error) {

	// Launch services
	for _, s := range ec.services {
		ec.wg.Add(1)
		go ec.execute(s)
	}

	// Start event loop
	go ec.EventLoop()

	return nil
}

// Execute a service
func (ec *ServiceManager) execute(service ServiceInterface) {
    fmt.Println("Starting service")
    service.Run()
    defer ec.wg.Done()
}


