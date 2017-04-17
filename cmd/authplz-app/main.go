package main

import (
	"fmt"

	"github.com/getlantern/systray"
)

func main() {
	// Should be called at the very beginning of main().
	systray.Run(onReady)
}

func onReady() {
	systray.SetIcon(IconData)
	systray.SetTitle("Awesome App")
	systray.SetTooltip("Pretty awesome")
	mQuit := systray.AddMenuItem("Quit", "Quit the app")

	<-mQuit.ClickedCh
	systray.Quit()
	fmt.Println("Quit now...")

}
