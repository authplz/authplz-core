package mailcontroller

import "html/template"
import "bytes"
import "fmt"
import "log"

import "gopkg.in/mailgun/mailgun-go.v1"

//import "github.com/asaskevich/govalidator"



// Mail controller object
type MailController struct {
    domain string
    templateDir string
    templates map[string]template.Template
    mg mailgun.Mailgun
    testMode bool
}

// Fields required for a signup email
type SignupFields struct {
    Domain string
    UserName string
    ServiceName string
    ActivationUrl string
}

// Standard mailing templates (required for MailController creation)
var templateNames  = [...]string{ "signup", "passwordreset", "loginnotice" }

// Instantiate a mail controller
func NewMailController(domain string, mgApiKey string, mgPriKey string, templateDir string) (*MailController, error) {
    var templates map[string]template.Template = make(map[string]template.Template)

    // Load templates from specified directory
    for _, name := range templateNames {
        tpl, err := template.ParseFiles(templateDir + "/" + name + ".tmpl")
        if(err != nil) {
            return nil, err
        }
        templates[name] = *tpl
    }

    // Attempt connection to mailgun
    mg := mailgun.NewMailgun(domain, mgApiKey, mgPriKey)

    return &MailController{domain: domain, templateDir: templateDir, templates: templates, mg: mg, testMode: false}, nil
}

// Enable test mode (blocks mail sending)
func (mc *MailController) SetTestMode() {
    mc.testMode = true;
}

// Send an item of mail
func (mc *MailController) SendMail(email string, subject string, body string) error {

    // Build message
    m := mc.mg.NewMessage("noreply@" + mc.domain, subject, "", email)
    m.SetTracking(true)
    m.SetHtml(body)

    if mc.testMode == true {
        m.EnableTestMode();
    }

    // Attempt sending
    _, id, err := mc.mg.Send(m)
    if err != nil {
        log.Fatal(err)
        return err
    }
    log.Printf("Sent message id=%s", id)

	return nil
}

func (mc *MailController) SendSignup(email string, data SignupFields) error {
    buf := new(bytes.Buffer)
    tmpl, ok := mc.templates["signup"]
    if !ok {
        return fmt.Errorf("template %s not found", "signup");
    }
    err := tmpl.Execute(buf, data)
    if err != nil {
        return err;
    }

    return mc.SendMail(email, data.ServiceName + " account activation", buf.String());
}







