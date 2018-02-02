/*
 * Mock event emitter for test use
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2017 Ryan Kurte
 */

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
