package mailcontroller

import "testing"
import "fmt"
import "os"

func TestMailController(t *testing.T) {

    var mc *MailController

    mgDomain := os.Getenv("MG_DOMAIN")
    mgApiKey := os.Getenv("MG_APIKEY")
    mgPriKey := os.Getenv("MG_PRIKEY")

    // Run tests
    t.Run("Create mail controller", func(t *testing.T) {
        lmc, err := NewMailController(mgDomain, mgPriKey, mgApiKey, "../templates")
        if err != nil {
            fmt.Println(err)
            t.Error(err)
        }
        lmc.SetTestMode()
        mc = lmc
    })

    t.Run("Can send emails", func(t *testing.T) {
        err := mc.SendMail("test@" + mgDomain, "test subject", "test body");
        if err != nil {
            fmt.Println(err)
            t.Error(err)
        }
    })

    t.Run("Can send signup emails", func(t *testing.T) {

        sf := SignupFields{
            UserName: "TestUser",
            ServiceName: "AuthPlzTest",
            ActivationUrl: "https://not.a.url/kfaksbderubg",
        }

        err := mc.SendSignup("test@" + mgDomain, sf);
        if err != nil {
            fmt.Println(err)
            t.Error(err)
        }
    })

}
