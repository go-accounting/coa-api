package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"

	oidc "github.com/coreos/go-oidc"
	"github.com/go-accounting/coa"
	"github.com/go-accounting/config"
	"github.com/julienschmidt/httprouter"
)

var cfg config.Config

var provider *oidc.Provider
var verifier *oidc.IDTokenVerifier

type repository struct {
	*coa.CoaRepository
	user string
}

var repositoryPool = sync.Pool{
	New: func() interface{} {
		r := &repository{}
		v, err := cfg.Run("NewKeyValueStore", &r.user)
		if err != nil {
			panic(err)
		}
		r.CoaRepository = coa.NewCoaRepository(v.(coa.KeyValueStore))
		return r
	},
}

type decoder func(interface{}) error

func handler(
	f func(*repository, httprouter.Params, decoder) (interface{}, error),
) func(http.ResponseWriter, *http.Request, httprouter.Params) {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		user, err := user(r)
		if check(err, w) {
			return
		}
		cr := repositoryPool.Get().(*repository)
		cr.user = user
		defer repositoryPool.Put(cr)
		v, err := f(cr, ps, func(v interface{}) error {
			return json.NewDecoder(r.Body).Decode(v)
		})
		if check(err, w) {
			return
		}
		if v != nil {
			w.Header().Set("Content-Type", "application/json")
			check(json.NewEncoder(w).Encode(v), w)
		}
	}
}

func chartsOfAccounts(cr *repository, _ httprouter.Params, _ decoder) (interface{}, error) {
	return cr.AllChartsOfAccounts()
}

func getChartOfAccounts(cr *repository, ps httprouter.Params, _ decoder) (interface{}, error) {
	return cr.GetChartOfAccounts(ps.ByName("coa"))
}

func saveChartsOfAccounts(cr *repository, ps httprouter.Params, d decoder) (interface{}, error) {
	c := &coa.ChartOfAccounts{}
	if err := d(c); err != nil {
		return nil, err
	}
	if ps.ByName("coa") != "" {
		c.Id = ps.ByName("coa")
	}
	c.User = cr.user
	return cr.SaveChartOfAccounts(c)
}

func accounts(cr *repository, ps httprouter.Params, _ decoder) (interface{}, error) {
	return cr.AllAccounts(ps.ByName("coa"))
}

func getAccount(cr *repository, ps httprouter.Params, _ decoder) (interface{}, error) {
	return cr.GetAccount(ps.ByName("coa"), ps.ByName("account"))
}

func saveAccount(cr *repository, ps httprouter.Params, d decoder) (interface{}, error) {
	a := &coa.Account{}
	if err := d(a); err != nil {
		return nil, err
	}
	if ps.ByName("account") != "" {
		a.Id = ps.ByName("account")
	}
	a.User = cr.user
	return cr.SaveAccount(ps.ByName("coa"), a)
}

func check(err error, w http.ResponseWriter) bool {
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	return err != nil
}

func user(r *http.Request) (string, error) {
	var token string
	tokens, ok := r.Header["Authorization"]
	if ok && len(tokens) >= 1 {
		token = tokens[0]
		token = strings.TrimPrefix(token, "Bearer ")
	}
	idtoken, err := verifier.Verify(r.Context(), token)
	if err != nil {
		return "", err
	}
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := idtoken.Claims(&claims); err != nil {
		return "", err
	}
	if !claims.Verified {
		return "", fmt.Errorf("email not verified")
	}
	return claims.Email, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("usage: %v settings", path.Base(os.Args[0]))
		return
	}
	var err error
	cfg, err = config.New(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	provider, err = oidc.NewProvider(context.Background(), cfg["OpenId/Provider"].(string))
	if err != nil {
		log.Fatal(err)
	}
	verifier = provider.Verifier(&oidc.Config{ClientID: cfg["OpenId/ClientId"].(string)})
	router := httprouter.New()
	router.GET("/charts-of-accounts", handler(chartsOfAccounts))
	router.POST("/charts-of-accounts", handler(saveChartsOfAccounts))
	router.GET("/charts-of-accounts/:coa", handler(getChartOfAccounts))
	router.PUT("/charts-of-accounts/:coa", handler(saveChartsOfAccounts))
	router.GET("/charts-of-accounts/:coa/accounts", handler(accounts))
	router.POST("/charts-of-accounts/:coa/accounts", handler(saveAccount))
	router.GET("/charts-of-accounts/:coa/accounts/:account", handler(getAccount))
	router.PUT("/charts-of-accounts/:coa/accounts/:account", handler(saveAccount))
	log.Fatal(http.ListenAndServe(":8080", router))
}
