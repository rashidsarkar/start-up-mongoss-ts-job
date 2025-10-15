# Blog-API-Server

A feature-rich and secure RESTful API for managing blogs and user accounts. Built with Node.js, Express, TypeScript, and MongoDB, this application supports blog creation, updates, deletion, user management, and authorization using JWT.

---

## Features

- **Blog Management**:
  - Add, update, delete, and retrieve blogs.
  - Search functionality for blogs by title or content.
  - Role-based access control for managing blogs.

- **User Management**:
  - User registration and login with secure password handling.
  - Admin functionality to block users.

- **Authorization**:
  - JWT-based authentication for secure access.
  - Role-based authorization to control access to sensitive operations.

- **Error Handling**:
  - Centralized error handling for validation and server errors.
  - Detailed error messages for debugging.

- **Query Builder**:
  - Dynamic query handling for search, filter, and sort operations.

---

## Technologies

- **Backend**: Node.js, Express
- **Database**: MongoDB (using Mongoose)
- **Validation**: Zod
- **Language**: TypeScript
- **Authentication**: JSON Web Tokens (JWT)
- **Environment Variables**: Dotenv

---

## Prerequisites

Ensure you have the following installed:

- **Node.js** (v16+)
- **MongoDB Atlas Account** or a local MongoDB setup
- **npm** (Node Package Manager)

---

## Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/rashidsarkar/Blog-API-Server.git
cd Blog-API-Server
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Configure Environment Variables
Create a `.env` file in the root directory and add the following:

```env
PORT=5000
DATABASE_URL=DB_URL
JWT_SECRET=your_jwt_secret
NODE_ENV=development
```

### 4. Start the Server
Run the following command to start the application:

```bash
npm run start:dev
```

The server will start on `http://localhost:5000`.


---

## API Endpoints

### Auth Endpoints
- **POST** `/api/auth/register` - Register a new user.
- **POST** `/api/auth/login` - Login to get access tokens.

### Blog Endpoints
- **POST** `/api/blogs` - Create a new blog.
- **GET** `/api/blogs` - Retrieve all blogs with search, filter, and sort.
- **GET** `/api/blogs/:id` - Retrieve a specific blog by ID.
- **PATCH** `/api/blogs/:id` - Update an existing blog.
- **DELETE** `/api/blogs/:id` - Delete a blog by ID.

### Admin Endpoints
- **PATCH** `/api/admin/users/:userId/block` - Block a user (Admin only).
- **DELETE** `/api/admin/blogs/:id` - Delete any blog (Admin only).

---

## Contributing

We welcome contributions! Follow these steps:

1. Fork the repository.
2. Create a new branch: `git checkout -b feature-name`.
3. Make your changes and commit: `git commit -m 'Add feature-name'`.
4. Push to the branch: `git push origin feature-name`.
5. Open a pull request.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

## Author

**MD Rashid Sarkar**  
- [GitHub](https://github.com/rashidsarkar)  
- [Portfolio](https://fabulous-meringue-442652.netlify.app)  
- [Email](mailto:rashidsarkar558@gmail.com)

