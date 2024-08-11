# Conductor OAuth Server

Conductor OAuth Server is an open-source OAuth 2.0 server implementation written in Go. It provides a robust and secure way to handle user authentication, authorization, and client management. This server is designed to be easily integrated into your existing applications and services.

## Features

- OAuth 2.0 compliant
- User registration and authentication
- Password reset functionality
- Client management (create, update, delete)
- Token issuance and renewal
- Role-based access control (Admin and User roles)
- SMTP configuration for sending emails
- Configurable via environment variables

## Getting Started

### Prerequisites

- Go 1.22 or higher
- SQLite3
- SMTP server for sending emails

### Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/head-crash/conductor.git
    cd conductor
    ```

2. Install dependencies:

    ```sh
    go mod tidy
    ```

3. Build the project:

    ```sh
    go build -o conductor
    ```

### Configuration

The server is configured using environment variables. You can create a `.env` file in the root directory of the project to set these variables. Below is a list of the required and optional environment variables:

- `PORT` (default: `8080`): The port on which the server will run.
- `DB_FILE_PATH` (default: `./conductor.db`): Path to the SQLite database file.
- `SECRET_KEY` (required): Secret key for JWT signing.
- `ENDPOINT_URL` (default: `http://localhost:8080`): URL of the server endpoint.
- `EXPIRY_SECONDS` (default: `3600`): Token expiry time in seconds.
- `AUTH_TIMEOUT_SECONDS` (default: `300`): Authentication timeout in seconds.
- `SMTP_HOST` (required): SMTP server address.
- `SMTP_PORT` (required): SMTP server port.
- `SMTP_USER` (required): SMTP username.
- `SMTP_PASSWORD` (required): SMTP password.
- `ADMIN_USER_NAME` (default: `admin`): Default admin username.
- `LOG_LEVEL` (default: `DEBUG`): Log level for the application.

### Running the Server

1. Ensure your `.env` file is properly configured.
2. Run the server:

    ```sh
    ./conductor
    ```

### API Endpoints

#### Authentication

- `POST /oauth/login`: Authenticate a user and redirect to the client redirect URL.
- `GET /oauth/token`: Issue a token for the client.
- `POST /auth/login`: Basic authentication and token issuance.
- `GET /auth/renew`: Renew an access token.

#### User Management

- `GET /users`: Retrieve a list of users (Admin only).
- `POST /users`: Create a new user.
- `POST /users/register`: Register a new user from a form.
- `DELETE /users/:userId`: Delete a user (Admin only).
- `POST /users/reset-password`: Request a password reset.
- `GET /users/reset-password`: Display the password reset page.
- `POST /users/password`: Reset a user's password.
- `PUT /users/:userId/password`: Set a new password for a user (Admin only).

#### Client Management

- `POST /clients`: Create a new client (Admin only).
- `GET /clients`: Retrieve a list of clients (Admin only).
- `DELETE /clients/:clientId`: Delete a client (Admin only).

### Middleware

- `ValidateAuthorization`: Validates the authorization header and sets the user in the context.
- `IsAdmin`: Checks if the user in the context is an admin.

### Templates

The server uses HTML templates for rendering the login and password reset pages. The main template is located at `templates/main.html`.

### Logging

The server uses the `logger` package for logging. The log level can be configured using the `LOG_LEVEL` environment variable.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [Gin](https://github.com/gin-gonic/gin) - HTTP web framework
- [JWT](https://github.com/dgrijalva/jwt-go) - JSON Web Tokens
- [bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt) - Password hashing
- [SQLite](https://www.sqlite.org/index.html) - Database engine
- [godotenv](https://github.com/joho/godotenv) - Environment variable loader

---

Thank you for using Conductor OAuth Server! If you have any questions or need further assistance, please feel free to open an issue on GitHub.
