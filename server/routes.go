package server

// InitRoutes initializes the routes for the server
func (s *RestServer) SetRoutes() {
	s.SetRoute("GET", "/oauth/token", s.Auth.IssueToken).
		SetRoute("POST", "/oauth/login", s.Auth.AuthenticateOauth).
		SetRoute("GET", "/oauth/login", s.Auth.LoginPage).
		SetRoute("POST", "/auth/login", s.Auth.Authenticate).
		SetRoute("GET", "/users", s.Auth.ValidateAuthorization, s.User.IsAdmin, s.User.GetUsers).
		SetRoute("POST", "/users", s.User.Create).
		SetRoute("DELETE", "/users/:userId", s.Auth.ValidateAuthorization, s.User.IsAdmin, s.User.Delete).
		SetRoute("POST", "/clients", s.Auth.ValidateAuthorization, s.User.IsAdmin, s.Client.Create).
		SetRoute("GET", "/clients", s.Auth.ValidateAuthorization, s.User.IsAdmin, s.Client.GetClients).
		SetRoute("DELETE", "/clients/:clientId", s.Auth.ValidateAuthorization, s.User.IsAdmin, s.Client.Delete)
}
