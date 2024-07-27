package router

import (
	"github.com/fastjack-it/conductor/handlers"
	"github.com/gin-gonic/gin"
)

type router struct {
	*gin.Engine
}

func Init() *router {
	return &router{gin.Default()}
}

func (r *router) SetRoutes() {
	r.POST("/oauth/token", handlers.Auth.InitiateTokenRequest)
	r.GET("/oauth/token", handlers.Auth.IssueToken)
	r.POST("/oauth/login", handlers.Auth.Authenticate)
	r.GET("/oauth/login", handlers.Auth.LoginPage)
}
