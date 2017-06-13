package config

// MailerConfig Mailer configuration options
type MailerConfig struct {
	Driver  string            `yaml:"driver"`
	Options map[string]string `yaml:"options"`
}
