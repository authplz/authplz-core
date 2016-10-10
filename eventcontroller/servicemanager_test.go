package eventcontroller

import "testing"
import "fmt"
import "time"

type FakeWorker struct {
    id int
}

func (fw *FakeWorker) HandleEvent(event interface{}) error {
	fmt.Printf("Worker ID: %d event: %s\n", fw.id, event)
	return nil
}

func TestServiceManager(t *testing.T) {
	// Create controllers
	ec := NewServiceManager()

	es1 := NewAsyncService(&FakeWorker{id: 1})
    es2 := NewAsyncService(&FakeWorker{id: 2})

	// Run tests
	t.Run("Send event", func(t *testing.T) {
		ec.BindService(&es1)
        ec.BindService(&es2)
		ec.SendEvent("test")
		ec.Run()
		time.Sleep(1000)
		ec.Exit()
        t.Error("boop")
	})

	// Tear down user controller

}
