package main

import (
	"github.com/BurntSushi/toml"
)

var config configuration

type configuration struct {
	Database databaseConfig
	Server   serverConfig
	Captcha  captchaConfig
}

type databaseConfig struct {
	Username string
	Password string
	Database string
}

type serverConfig struct {
	Address string
}

type captchaConfig struct {
	HCaptchaSiteKey   string
	HCaptchaSecretKey string
}

func configure() {
	_, err := toml.DecodeFile("config.toml", &config)
	if err != nil {
		panic(err)
	}
}
