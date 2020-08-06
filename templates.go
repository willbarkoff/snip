package main

import "html/template"

var templates = map[string]*template.Template{
	"error":   template.Must(template.ParseFiles("static/error.html")),
	"login":   template.Must(template.ParseFiles("static/login.html")),
	"setup":   template.Must(template.ParseFiles("static/setup.html")),
	"preview": template.Must(template.ParseFiles("static/preview.html")),
	"home":    template.Must(template.ParseFiles("static/home.html")),
}

type homePageData struct {
	Links []shortenedLink
}

type shortenedLink struct {
	ID     string
	Key    string
	URL    string
	Clicks int
}

type errorPageData struct {
	Error      string
	StackTrace string
}

type loginPageData struct {
	ShowError       bool
	Error           string
	HCaptchaSiteKey string
}

type setupPageData struct {
	HCaptchaSiteKey string
}

type previewPageData struct {
	Key string
	URL string
}
