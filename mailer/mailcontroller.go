package datastore

import "text/template"

//import "github.com/asaskevich/govalidator"

// Mail controller object
type MailController struct {
}

func (mc *MailController) SendMail(email string, data map[string]string, template string) error {
	var out string

	t, err := template.New("foo").Parse(`{{define "T"}}Hello, {{.}}!{{end}}`)
	err = t.ExecuteTemplate(out, "T", "<script>alert('you have been pwned')</script>")

	return nil
}
