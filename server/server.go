package server

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/head-crash/conductor/handlers"
	"github.com/head-crash/conductor/models"
	"github.com/head-crash/logger"
)

// RestServer represents the REST server with its handlers and Gin engine.
type RestServer struct {
	*gin.Engine
	Auth   *handlers.AuthHandler
	User   *handlers.UserHandler
	Client *handlers.ClientHandler
}

// NewServer initializes a new RestServer with the provided database.
// It sets up the necessary handlers, middleware, and routes.
func NewServer(db models.Database) *RestServer {
	server := &RestServer{
		gin.New(),
		handlers.NewAuthHandler(db).
			Init().
			StartCleanUp(),
		handlers.NewUserHandler(db),
		handlers.NewClientHandler(db),
	}

	// Add the custom logger middleware
	server.Use(CustomLogger(logger.Default))

	// Add the recovery middleware to handle panics
	server.Use(gin.Recovery())

	// Add default routes defined in routes.go
	server.SetRoutes()

	return server
}

// SetRoute sets a route for the server with the specified HTTP method, path, and handlers.
func (s *RestServer) SetRoute(httpMethod string, path string, handlers ...gin.HandlerFunc) *RestServer {
	s.Handle(httpMethod, path, handlers...)
	return s
}

// GetLogger returns the default Gin logger middleware.
func (s *RestServer) GetLogger() gin.HandlerFunc {
	return gin.Logger()
}

// CustomLogger is a middleware that generates additional log outputs using the provided logger.
func CustomLogger(logger *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		end := time.Now()
		latency := end.Sub(start)
		// logger.Debug(fmt.Sprintf("[CUSTOM LOG] %v | %3d | %13v | %15s |%-7s %#v\n%s",
		// 	end.Format("2006/01/02 - 15:04:05"),
		// 	c.Writer.Status(),
		// 	latency,
		// 	c.ClientIP(),
		// 	c.Request.Method,
		// 	c.Request.URL.Path,
		// 	c.Errors.String(),
		// ))

		// Output standard Gin log
		gin.DefaultWriter.Write([]byte(
			fmt.Sprintf("[GIN LOG] %v | %3d | %13v | %15s |%-7s %#v\n%s",
				end.Format("2006/01/02 - 15:04:05"),
				c.Writer.Status(),
				latency,
				c.ClientIP(),
				c.Request.Method,
				c.Request.URL.Path,
				c.Errors.String(),
			),
		))
	}
}
