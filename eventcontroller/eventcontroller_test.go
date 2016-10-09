package eventcontroller


import "testing"


type FakeRunner struct {
    EventSink
}



func TestEventController(t *testing.T) {
    // Create controllers
    ec := NewEventController()

    // Run tests
    t.Run("Add login event", func(t *testing.T) {
        err := lc.AddEvent(u, LoginEvent);
        if err != nil {
            t.Error(err)
            return
        }
    })


    // Tear down user controller

}
