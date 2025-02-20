# Full Authentication System in Node.js

A complete authentication system built using **Node.js, Express, MongoDB, and Passport.js**, featuring **JWT-based authentication, email verification, password reset, and Google OAuth**.

## 🚀 Features
- User registration with email & password
- Email and Password Validation
- Email verification using OTP (Zoho Mail & Nodemailer)
- Login with JWT-based authentication
- Google OAuth authentication
- Refresh token implementation
- Password reset functionality
- Secure authentication using bcrypt password hashing
- User session handling with cookies
- Logout functionality

## 🛠️ Tech Stack
- **Backend:** Node.js, Express.js
- **Database:** MongoDB with Mongoose
- **Authentication:** Passport.js, JWT, Google OAuth
- **Email Services:** Nodemailer (Zoho Mail)
- **Templating Engine:** EJS

## 📂 Project Setup

### 1️⃣ Clone the repository
```sh
$ git clone https://github.com/SalonRaut7/Full_Auth_Node.git
$ cd Full_Auth_Node
```

### 2️⃣ Install dependencies
```sh
$ npm install
```

### 3️⃣ Configure Environment Variables
Create a `.env` file in the root directory and add the following:
```env
PORT=8000
CONNECTION_STRING=your_mongodb_url
ACCESS_TOKEN_SECRET=your_secret_key
REFRESH_TOKEN_SECRET=your_refresh_token_secret
ACCESS_TOKEN_EXPIRY=your_access_token_expiry_time
REFRESH_TOKEN_EXPIRY=your_refresh_token_expiry_time
EMAIL_USER=username@zohomail.com
EMAIL_PASS=your_zoho_app_password
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
SESSION_SECRET=your_session_secret
```

### 4️⃣ Start the server
```sh
$ npm start
```

The server will run at: `http://localhost:8000`

## 🔑 API Endpoints
### **Authentication Routes**
| Method | Endpoint                | Description                      |
|--------|-------------------------|----------------------------------|
| POST   | `/register`              | Register a new user             |
| POST   | `/login`                 | Login user and issue JWT token  |
| GET    | `/auth/google`           | Google OAuth authentication     |
| GET    | `/auth/google/callback`  | Google OAuth callback           |
| POST   | `/logout`                | Logout and clear session        |
| POST   | `/verify-email`          | Verify user email OTP           |
| POST   | `/forgot-password`       | Send password reset email       |
| POST   | `/reset-password`        | Reset password                  |
| GET    | `/dashboard`             | User dashboard                   |

## 📝 Usage Instructions
1. **Signup/Login:** Users can sign up with email & password or authenticate via Google OAuth.
2. **Email Verification:** An OTP will be sent to verify the email.
3. **JWT Authentication:** Upon login, an access token is issued and stored in cookies.
4. **Password Reset:** Users can reset their passwords if forgotten.
5. **Refresh Tokens:** Access tokens can be refreshed securely.

---
### 💻 Developed by [Salon Raut](https://github.com/SalonRaut7)
