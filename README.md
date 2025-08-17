# 🔐 Authentication System API

A simple and secure **Authentication API** built with **Node.js**, **Express**, and **MongoDB**. It includes all the essentials like user sign-up, login, password reset, and email notifications.

---

## ✅ Features

- User registration & login with **JWT**
- Access & Refresh token flow
- Password reset via email
- Email verification (HTML templates)
- Input validation using **express-validator**
- Secure password hashing with **bcryptjs**
- Environment-based configuration using **dotenv**

---

## 🛠 Tech Stack

- **Backend:** Node.js, Express
- **Database:** MongoDB (Mongoose)
- **Email Service:** Nodemailer + Mailgen
- **Validation:** express-validator
- **Auth:** JWT (Access & Refresh tokens)

---

## 📂 Folder Structure

AuthenticationSystem/

```bash
├── src/
│ ├── config/ # DB & SMTP configs
│ ├── controllers/ # Auth logic
│ ├── middlewares/ # Error handler, validation
│ ├── models/ # Mongoose schemas
│ ├── routes/ # API routes
│ ├── utils/ # Helpers (email, tokens)
│ ├── app.js # Express app setup
│ └── server.js # Entry point
├── .env # Environment variables
├── package.json
└── README.md
```

---

## ⚙️ Installation

### 1️⃣ Clone the repository

```bash

git clone https://github.com/your-username/authentication-system.git
cd authentication-system
```

### 2️⃣ Install dependencies

```bash
npm install
```

### 3️⃣ Setup .env file

```bash
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
ACCESS_TOKEN_EXPIRY=1d
REFRESH_TOKEN_EXPIRY=10d
SMTP_HOST=smtp.yourmail.com
SMTP_PORT=587
SMTP_USER=your_email@example.com
SMTP_PASS=your_email_password
```

### ▶️ Run the App

```bash
npm start
```

Starts the server with nodemon for auto-reload.

### 🔗 API Endpoints

| Method | Endpoint                       | Description              |
| ------ | ------------------------------ | ------------------------ |
| POST   | `/api/v1/auth/register`        | Register a new user      |
| POST   | `/api/v1/auth/login`           | Login user               |
| POST   | `/api/v1/auth/logout`          | Logout user              |
| POST   | `/api/v1/auth/refresh`         | Refresh JWT tokens       |
| POST   | `/api/v1/auth/forgot-password` | Send password reset link |
| POST   | `/api/v1/auth/reset-password`  | Reset user password      |
| GET    | `/api/v1/auth/verify/:id`      | Verify user email        |

### ✉️ Email Templates

Emails are generated using Mailgen for a professional look:

Welcome Email

Password Reset Email

Email Verification

### 🚀 Future Improvements

Google & GitHub OAuth

Rate limiting for brute-force protection

Two-Factor Authentication (2FA)

### ✒️ by Shouvik Sarkar
