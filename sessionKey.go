package main

import (
	"io/ioutil"
	"os"

	"github.com/gorilla/sessions"
)

var store *sessions.CookieStore

func prepareSessionKey() {
	var sessionKey []byte
	if _, fileError := os.Stat("session-key"); fileError == nil {
		var err error
		sessionKey, err = ioutil.ReadFile("session-key")
		if err != nil {
			panic(fileError)
		}
	} else if os.IsNotExist(fileError) {
		keyString, err := generateRandomString(32)
		if err != nil {
			panic(err)
		}
		sessionKey = []byte(keyString)
		file, err := os.Create("session-key")
		if err != nil {
			panic(err)
		}
		_, err = file.Write(sessionKey)
		if err != nil {
			panic(err)
		}
	} else {
		panic(fileError)
	}

	store = sessions.NewCookieStore(sessionKey)
}
