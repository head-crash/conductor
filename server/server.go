package server

import (
	"github.com/fastjack-it/conductor/handlers"
	"github.com/fastjack-it/conductor/models"
	"github.com/gin-gonic/gin"
)

type RestServer struct {
	*gin.Engine
	Auth *handlers.AuthHandler
	User *handlers.UserHandler
}

func NewServer(db models.Database) *RestServer {
	server := &RestServer{
		gin.Default(),
		handlers.NewAuthHandler(db).StartCleanUp(),
		handlers.NewUserHandler(db),
	}
	return server.SetRoutes()
}

func (s *RestServer) SetRoute(httpMethod string, path string, handlers ...gin.HandlerFunc) *RestServer {
	s.Handle(httpMethod, path, handlers...)
	return s
}
