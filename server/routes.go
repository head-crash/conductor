package server

// InitRoutes initializes the routes for the server
func (s *RestServer) SetRoutes() {
	s.SetRoute("GET", "/oauth/token", s.Auth.IssueToken).
		SetRoute("POST", "/oauth/login", s.Auth.Authenticate).
		SetRoute("GET", "/oauth/login", s.Auth.LoginPage).
		SetRoute("POST", "/users", s.User.Create).
		SetRoute("POST", "/clients", s.Client.Create)
}
