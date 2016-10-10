package eventcontroller

import "testing"
import "fmt"
import "time"

type FakeRunner struct {
	AsyncService
}

func NewFakeRunner() FakeRunner {
	es := NewAsyncService()
	return FakeRunner{AsyncService: es}
}

func (r *FakeRunner) Run() error {
	fmt.Println("Started runner")

	for {
		c, open := r.GetEvent()
		if open {
			fmt.Println(c)
		} else {
			fmt.Println("Exiting runner")
			break
		}
	}

	return nil
}

func TestEventController(t *testing.T) {
	// Create controllers
	ec := NewEventController()

	es := NewFakeRunner()

	// Run tests
	t.Run("Send event", func(t *testing.T) {
		ec.BindService(&es)
		ec.SendEvent("test")
		ec.Run()
		time.Sleep(1000)
		ec.Exit()
	})

	// Tear down user controller

}
