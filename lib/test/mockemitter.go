package test

import (
	"github.com/authplz/authplz-core/lib/events"
)

type MockEventEmitter struct {
	Event *events.AuthPlzEvent
}

func (m *MockEventEmitter) SendEvent(e interface{}) {
	m.Event = e.(*events.AuthPlzEvent)
}
