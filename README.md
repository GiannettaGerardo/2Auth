# 2Auth

<p>
  <a href="https://www.gnu.org/licenses/gpl-3.0"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg" alt="License: GPL v3"></a>
  <a href="https://spring.io/"><img src="https://img.shields.io/badge/Spring%20Boot-3.x-brightgreen.svg" alt="Spring Boot Version"></a>
</p>

**2Auth** is a robust and comprehensive authentication and authorization solution built with Java Spring Boot 3.

## Overview

This project aims to simplify the integration of advanced authentication and authorization mechanisms into Spring Boot applications.

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