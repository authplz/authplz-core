package async

import (
	"sync"
)

// Interface that services must implement
type RunnableInterface interface {
	Run() error
	SendEvent(e interface{}) error
	Exit() error
}

// Service Manager
type ServiceManager struct {
	in       chan interface{}
	services []RunnableInterface
	wg       sync.WaitGroup
}

// Instantiate a Service Manger
func NewServiceManager(channelSize uint) *ServiceManager {

	in := make(chan interface{}, channelSize)

	return &ServiceManager{in: in}
}

// Bind a service to the service manager
func (ec *ServiceManager) BindService(service RunnableInterface) {
	ec.services = append(ec.services, service)
}

// Run the event controller
func (ec *ServiceManager) Run() (err error) {

	// Launch services
	for _, s := range ec.services {
		ec.wg.Add(1)
		go ec.execute(s)
	}

	// Start event loop
	go ec.eventLoop()

	return nil
}

// Send an event to all bound services
func (ec *ServiceManager) SendEvent(event interface{}) {
	ec.in <- event
}

// Exit the service manager
// This will gracefully exit all child services
func (ec *ServiceManager) Exit() (err error) {

	// Close input channel (causing child services to exit)
	close(ec.in)

	// Await exit of subroutines
	ec.wg.Wait()

	return nil
}

// Event loop / distribution routine
func (ec *ServiceManager) eventLoop() (err error) {
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

// Execute a service
func (ec *ServiceManager) execute(service RunnableInterface) {
	service.Run()
	defer ec.wg.Done()
}
