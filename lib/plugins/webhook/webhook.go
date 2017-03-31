package webhook

// Controller manages and executes webhooks
type Controller struct {
	urls []string
}

// NewWebhookController creates a new webhook controller plugin
func NewWebhookController(urls []string) *Controller {
	return &Controller{urls}
}

// HandleEvent receives a system event and calls attached webhooks
func (wc *Controller) HandleEvent(userid string, u interface{}) error {

	// TODO: call webhooks in goroutines with the event payload

	return nil
}
