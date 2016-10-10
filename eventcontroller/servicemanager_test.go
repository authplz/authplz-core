package eventcontroller

import "testing"
import "fmt"
import "time"

type FakeWorker struct {}

func (fw *FakeWorker) HandleEvent(event interface{}) error {
	fmt.Println(event)
	return nil
}

func TestServiceManager(t *testing.T) {
	// Create controllers
	ec := NewServiceManager()

	es := NewAsyncService(&FakeWorker{})

	// Run tests
	t.Run("Send event", func(t *testing.T) {
		ec.BindService(&es)
		ec.SendEvent("test")
		ec.Run()
		time.Sleep(1000)
		ec.Exit()
        t.Error("boop")
	})

	// Tear down user controller

}
