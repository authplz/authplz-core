package test

import (
	"github.com/ryankurte/authplz/lib/events"
)

type MockEventEmitter struct {
	Event *events.AuthPlzEvent
}

func (m *MockEventEmitter) SendEvent(e interface{}) {
	m.Event = e.(*events.AuthPlzEvent)
}
