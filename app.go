package main

import (
	"fmt"
	"net/http"

	"github.com/julienschmidt/httprouter"

	"github.com/MFahrurR/govwa/setting"
	"github.com/MFahrurR/govwa/setup"
	"github.com/MFahrurR/govwa/user"
	"github.com/MFahrurR/govwa/util"
	"github.com/MFahrurR/govwa/util/config"
	"github.com/MFahrurR/govwa/util/middleware"
	"github.com/MFahrurR/govwa/vulnerability/csa"
	"github.com/MFahrurR/govwa/vulnerability/idor"
	"github.com/MFahrurR/govwa/vulnerability/sqli"
	"github.com/MFahrurR/govwa/vulnerability/xss"
)

const (
	banner = `
     ÛÛÛÛÛÛÛÛÛ           ÛÛÛÛÛ   ÛÛÛÛÛ ÛÛÛÛÛ   ÛÛÛ   ÛÛÛÛÛ   ÛÛÛÛÛÛÛÛÛ  
    ÛÛÛ°°°°°ÛÛÛ         °°ÛÛÛ   °°ÛÛÛ °°ÛÛÛ   °ÛÛÛ  °°ÛÛÛ   ÛÛÛ°°°°°ÛÛÛ 
   ÛÛÛ     °°°   ÛÛÛÛÛÛ  °ÛÛÛ    °ÛÛÛ  °ÛÛÛ   °ÛÛÛ   °ÛÛÛ  °ÛÛÛ    °ÛÛÛ 
  °ÛÛÛ          ÛÛÛ°°ÛÛÛ °ÛÛÛ    °ÛÛÛ  °ÛÛÛ   °ÛÛÛ   °ÛÛÛ  °ÛÛÛÛÛÛÛÛÛÛÛ 
  °ÛÛÛ    ÛÛÛÛÛ°ÛÛÛ °ÛÛÛ °°ÛÛÛ   ÛÛÛ   °°ÛÛÛ  ÛÛÛÛÛ  ÛÛÛ   °ÛÛÛ°°°°°ÛÛÛ 
  °°ÛÛÛ  °°ÛÛÛ °ÛÛÛ °ÛÛÛ  °°°ÛÛÛÛÛ°     °°°ÛÛÛÛÛ°ÛÛÛÛÛ°    °ÛÛÛ    °ÛÛÛ 
   °°ÛÛÛÛÛÛÛÛÛ °°ÛÛÛÛÛÛ     °°ÛÛÛ         °°ÛÛÛ °°ÛÛÛ      ÛÛÛÛÛ   ÛÛÛÛÛ
     °°°°°°°°°   °°°°°°       °°°           °°°   °°°      °°°°°   °°°°° `
)

//index and set cookie

func indexHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

	util.SetCookieLevel(w, r, "low") //set cookie Level default to low

	data := make(map[string]interface{})
	data["title"] = "Index"

	util.SafeRender(w, r, "template.index", data)
}

//index and set cookie
func adminHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

	util.SetCookieLevel(w, r, "low") //set cookie Level default to low

	data := make(map[string]interface{})
	data["title"] = "Index"

	util.SafeRender(w, r, "template.index", data)
}

func main() {

	fmt.Println(banner)

	mw := middleware.New()
	router := httprouter.New()
	user := user.New()
	sqlI := sqli.New()
	xss := xss.New()
	idor := idor.New()
	csa := csa.New()
	setup := setup.New()
	setting := setting.New()

	router.ServeFiles("/public/*filepath", http.Dir("public/"))
	router.GET("/", mw.LoggingMiddleware(mw.AuthCheck(indexHandler)))
	router.GET("/index", mw.LoggingMiddleware(mw.DetectSQLMap(mw.AuthCheck(indexHandler))))
	router.GET("/wp-admin", mw.LoggingMiddleware(mw.DetectSQLMap(mw.AuthCheck(adminHandler))))

	user.SetRouter(router)
	sqlI.SetRouter(router)
	xss.SetRouter(router)
	idor.SetRouter(router)
	csa.SetRouter(router)
	setup.SetRouter(router)
	setting.SetRouter(router)

	s := http.Server{
		Addr:    ":8888",
		Handler: router,
	}

	fmt.Printf("Server running at port %s\n", s.Addr)
	fmt.Printf("Open this url %s on your browser to access GoVWA", config.Fullurl)
	fmt.Println("")
	err := s.ListenAndServe()
	if err != nil {
		panic(err)
	}

}
