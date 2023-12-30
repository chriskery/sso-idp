package ui

import (
	log "github.com/sirupsen/logrus"
	"net/http"

	"github.com/spf13/viper"
)

func UI() http.Handler {
	assetsPath := viper.GetString("assets-path")

	var filesystem http.FileSystem
	if assetsPath != "" {
		log.Infof("using ui assets path:%s", assetsPath)
		filesystem = http.Dir(assetsPath)
	} else {
		log.Info("using the built-in ui assets")
		filesystem = assetFS()
	}

	h := http.FileServer(filesystem)
	return &idpUI{h, http.StripPrefix("/idp/static", h)}
}

type idpUI struct {
	h             http.Handler
	prefixHandler http.Handler
}

func (s *idpUI) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if "/favicon.ico" == req.URL.Path {
		s.h.ServeHTTP(w, req)
		return
	}
	if "/ui/login.html" == req.URL.Path {
		// 5 minute cache for the login HTML page
		w.Header().Add("Cache-Control", "public, max-age=600")
	} else {
		// Encourage caching of UI
		w.Header().Add("Cache-Control", "public, max-age=31536000")
	}
	s.prefixHandler.ServeHTTP(w, req)
}
