package datastore

import (
	"encoding/json"
	"github.com/jinzhu/gorm"
	"time"
)

// AuditEvent for a user account
type AuditEvent struct {
	gorm.Model
	UserID uint
	Type   string
	Time   time.Time
	Data   string
}

// GetType fetches the type of the event
func (ae *AuditEvent) GetType() string { return ae.Type }

// GetTime fetches the time at which the event occured
func (ae *AuditEvent) GetTime() time.Time { return ae.Time }

// GetData fetches a map of the associated data
func (ae *AuditEvent) GetData() (map[string]string, error) {
	data := make(map[string]string)

	err := json.Unmarshal([]byte(ae.Data), &data)

	return data, err
}

// AddAuditEvent creates an audit event in the database
func (dataStore *DataStore) AddAuditEvent(userid, eventType string, eventTime time.Time, data map[string]string) (interface{}, error) {

	u, err := dataStore.GetUserByExtID(userid)
	if err != nil {
		return nil, err
	}
	user := u.(*User)

	encodedData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	auditEvent := AuditEvent{
		UserID: user.ID,
		Type:   eventType,
		Time:   eventTime,
		Data:   string(encodedData),
	}

	user.AuditEvents = append(user.AuditEvents, auditEvent)
	_, err = dataStore.UpdateUser(user)
	return user.AuditEvents, err
}

// GetAuditEvents fetches a list of audit events for a given userr
func (dataStore *DataStore) GetAuditEvents(userid string) ([]interface{}, error) {
	var auditEvents []AuditEvent

	// Fetch user
	u, err := dataStore.GetUserByExtID(userid)
	if err != nil {
		return nil, err
	}

	user := u.(*User)

	err = dataStore.db.Model(user).Related(&auditEvents).Error

	interfaces := make([]interface{}, len(auditEvents))
	for i, t := range auditEvents {
		interfaces[i] = &t
	}

	return interfaces, err
}
