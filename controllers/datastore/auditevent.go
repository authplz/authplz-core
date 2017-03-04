package datastore

import (
	"encoding/json"
	"github.com/jinzhu/gorm"
)

// Audit events for a login account
type AuditEvent struct {
	gorm.Model
	UserID       uint
	Type         string
	Message      string
	Data         string
	OriginIP     string
	ForwardedFor string
}

func (ae *AuditEvent) GetType() string    { return ae.Type }
func (ae *AuditEvent) GetMessage() string { return ae.Message }

func (ae *AuditEvent) GetData() (map[string]string, error) {
	data := make(map[string]string)

	err := json.Unmarshal([]byte(ae.Data), &data)

	return data, err
}

func (dataStore *DataStore) AddAuditEvent(userid, eventType, eventMessage string, data map[string]string) (interface{}, error) {

	u, err := dataStore.GetUserByExtId(userid)
	if err != nil {
		return nil, err
	}
	user := u.(*User)

	encodedData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	auditEvent := AuditEvent{
		UserID:  user.ID,
		Type:    eventType,
		Message: eventMessage,
		Data:    string(encodedData),
	}

	user.AuditEvents = append(user.AuditEvents, auditEvent)
	_, err = dataStore.UpdateUser(user)
	return user.AuditEvents, err
}

func (dataStore *DataStore) GetAuditEvents(userid string) ([]interface{}, error) {
	var auditEvents []AuditEvent

	// Fetch user
	u, err := dataStore.GetUserByExtId(userid)
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
