package httpapi

import (
	_ "embed"
	"html/template"
	"net/http"
)

//go:embed templates/demo.html.tmpl
var demoPageSource string

var demoPageTmpl = template.Must(template.New("demo").Parse(demoPageSource))

type demoPageData struct {
	RPID string
}

// handleDemoPage serves the zero-JS-dependency demo page: html/template
// plus vanilla fetch, no build step, no front-end framework.
func (s *Server) handleDemoPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := demoPageTmpl.Execute(w, demoPageData{RPID: s.RPID}); err != nil {
		s.logErr("demo page", err)
	}
}
