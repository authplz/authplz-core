package test

import (
	"github.com/ryankurte/authplz/lib/api"
)

type MockEventEmitter struct {
	Event *api.AuthPlzEvent
}

func (m *MockEventEmitter) SendEvent(e interface{}) {
	m.Event = e.(*api.AuthPlzEvent)
}
