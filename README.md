# Sky Genesis Enterprise API

Welcome to the Sky Genesis Enterprise API! This API provides a robust backend service for managing users, products, orders, and more. It is built using Node.js with Express and uses PostgreSQL as the database.

## Table of Contents

- [Getting Started](#getting-started)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running the Server](#running-the-server)
- [API Endpoints](#api-endpoints)
- [Database Schema](#database-schema)
- [Contributing](#contributing)
- [License](#license)

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

## Prerequisites

Make sure you have the following installed on your machine:

- Node.js (v14 or later)
- npm (v6 or later)
- PostgreSQL (v12 or later)

## Installation

1. Clone the repository:

```sh
git clone https://github.com/skygenesisenterprise/api-service.git
cd api-service
```

2. Install the dependencies:

```sh
pnpm install
```

3. Set up the PostgreSQL database:

- Create a new database in PostgreSQL.
- Update the database configuration in the `.env` file (create this file if it doesn't exist):

```env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=your_database_name
DB_USER=your_database_user
DB_PASSWORD=your_database_password
```

4. Run the database migrations to set up the schema:

```sh
npm run migrate
```

## Running the Server

To start the server, run the following command:

```sh
npm start
```

The server will start on `http://localhost:3000`.

## API Endpoints

Here are some of the main API endpoints available:

- **GET /api/users**: Get a list of all users.
- **POST /api/users**: Create a new user.
- **GET /api/products**: Get a list of all products.
- **POST /api/products**: Create a new product.
- **GET /api/orders**: Get a list of all orders.
- **POST /api/orders**: Create a new order.

For detailed API documentation, please refer to the [API Documentation](./docs/README.md).

## Database Schema

The database schema includes the following tables:

- **users**: Stores user information.
- **products**: Stores product information.
- **orders**: Stores order information.
- **order_items**: Stores order item details.
- **addresses**: Stores user addresses.
- **roles**: Stores user roles.
- **permissions**: Stores permissions.
- **role_permissions**: Stores role-permission associations.
- **user_roles**: Stores user-role associations.

For the complete database schema, please refer to the [Database Schema](./data/schema-pgsql.sql).

## Contributing

Please read [CONTRIBUTING.md](./.github/CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE) file for details.