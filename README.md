# 2Auth

<p>
  <a href="https://opensource.org/licenses/BSD-3-Clause"><img src="https://img.shields.io/badge/License-BSD%203--Clause-blue.svg" alt="License: BSD 3-Clause"></a>
  <a href="https://spring.io/"><img src="https://img.shields.io/badge/Spring%20Boot-3.x-brightgreen.svg" alt="Spring Boot Version"></a>
</p>

**2Auth** is a robust and comprehensive authentication and authorization solution built with Java Spring Boot 3.

## Overview

This project aims to simplify the integration of advanced authentication and authorization mechanisms into Spring Boot applications.

There are 2 components that work together: a **Backend** and an **API Gateway**:
- **API Gateway**: a user can directly communicate only with this component. It's responsible to maintain a session in memory (if you want, you can change this to maintain the session in another component like Redis). 
The session ID is generated and saved together with the user email and a Signed JWT (created by the Backend component);
- **Backend**: this component is responsible to authenticate a user by email and password, to register a new user with password hashing and salting, to generate a Signed JWT for the authenticated user to be saved with 
the session in the API Gateway component, and to create, store and rotate the JWT signing Key.

### Key concepts

1. Authentication with **Email** and **Password**. Password **hashing** and **salting**;
2. Registration sends a secure unique token via **e-mail** to complete validate the email and the user. This behavior can be fully customized;
3. API Gateway stores the Session in a HttpOnly cookie. The cookie is like that:
   - **__Host-** name prefix;
   - **Session ID** as value, 36 characters; 
   - **Path=/**; 
   - **HTTPOnly**; 
   - **SameSite=Strict**;
   - **Secure** if SSL is enabled.
4. HttpOnly cookie protection with CSRF token (Double-Submit Cookie Pattern) with an additional BREACH attack protection (by Spring Security **XorCsrfTokenRequestAttributeHandler**). 
The token is generated and handled by the API Gateway;
5. The *optional* filter **ChangeSessionId**, in the API Gateway, changes the Session ID at every http request;
6. The *optional* filter **LogoutIfUnauthorized**, in the API Gateway, logs out the user and clears the user session if the proxied request returns a 401 UNAUTHORIZED response;
7. **Logout** + **Complete-Logout** as separate endpoints. Complete-Logout invalidates each session of a user;
8. Backend is stateless and handles Authentication and Authorization with **signed JWT** (Json Web Token). JWT are generated and signed by the Backend, then is stored in the Session by API Gateway;
The **JwtTokenRelay** filter must be used, in the API Gateway, for requests proxied to the Backend to exchange the session cookie with the associated JWT and send it as Bearer Token to the Backend;
9. The signed JWT has a customizable duration;
10. The signing key for the JWT has a customizable rotation.

## Getting Started

### Prerequisites

* Java Development Kit (JDK) 17 or higher
* Maven 3.6+

### Installation

```bash
# Clone the repository
git clone https://github.com/GiannettaGerardo/2Auth.git
cd 2Auth

# Build the project
mvn clean install
```

### Running the Application

```bash
mvn spring-boot:run
```

### Customization

You can customize the application changing directly the code, but there are some configurations that can be done from the **application.yml** file:

- **API Gateway**
    ```yaml
    2Auth:
      # Default is localhost.
      backend-domain: localhost
      # Default is no port number.
      backend-port: 8081
      # To configure CORS policy. Default is "*".
      allowedOrigins: "*"
      # To configure the only allowed http methods. Default are GET, POST, PUT, DELETE.
      allowedHttpMethods: GET, POST, PUT, DELETE
      # This name is combined with the secure cookie prefix "__Host-". Default is XYZ_S.
      customSessionIdName: XYZ_S
    ```
- **Backend**
    ```yaml
    2Auth:
      # Can be one between <NONE, EMAIL_FOR_FRONTEND, EMAIL_FOR_API, TEST_FOR_FRONTEND, TEST_FOR_API>.
      # Default is TEST_FOR_API.
      registration-confirmation: TEST_FOR_API
      jwt:
        # Time before the JWT expires (in milliseconds). Default is 8 hours.
        time-validity-in-millis: 28800000
        # Time before renewing the key used to sign JWTs (in milliseconds). Default is 24 hours.
        key-time-validity-in-millis: 86400000
    ```

How to use the special filters in the API Gateway application.yml file:
```yaml
spring:
  cloud:
  gateway:
    routes:
      - id: backend
        uri: https://my.domain.com
        predicates:
          - Path=/api/**
        filters:
          - JwtTokenRelay # special filter
          - ChangeSessionId # special filter
          - LogoutIfUnauthorized # special filter
          - StripPrefix=1
          - DedupeResponseHeader=Access-Control-Allow-Credentials Access-Control-Allow-Origin
```

## REST API Endpoints

This section provides an overview of the main REST API endpoints exposed by the 2Auth application.

### Authentication

* **`POST /login`**: endpoint for user authentication. Accepts user credentials (email and password) and returns a session cookie upon successful login.

* **`POST /registration`**: endpoint for new user registration. Accepts user details (email, password, firstName, lastName, permissions) and creates a new user account.

* **`POST /logout`**: endpoint to log out the currently authenticated user from their current session. This invalidate the current session.

* **`POST /complete-logout`**: endpoint to perform a complete logout for the currently authenticated user, invalidating all active sessions associated with the user (e.g., across multiple devices).

### User Management

Paths for accessing and managing user resources:
* `GET /api/users/{email}`: retrieve details for a specific user.
* `POST /api/users`: add a new user.
* `PUT /api/users`: update details for a specific user.
* `DELETE /api/users/{email}`: delete a specific user account.