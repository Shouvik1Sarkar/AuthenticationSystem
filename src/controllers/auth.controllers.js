import asyncHandler from "../utils/asyncHandler.utils.js";
import { ApiError } from "../utils/api-error-handler.utils.js";
import { ApiResponse } from "../utils/api-response.utils.js";
import { User } from "../models/user.models.js";
import mailSender, { resetPasswordEmail } from "../utils/mail.utils.js";
import { registrationEmail } from "../utils/mail.utils.js";
// import { jwt_token } from "../middlewares/tokenValidation.middlewares.js";

import jwt from "jsonwebtoken";

const registerUser = asyncHandler(async (req, res) => {
  const { userName, email, password } = req.body;
  console.log("UserName: ", userName);
  console.log("email: ", email);
  console.log("password: ", password);

  if (!userName || !email || !password) {
    throw new ApiError(500, "All credentials are required");
  }
  // const existiedUser = await User.findOne({ email });

  // if (existiedUser) {
  //   throw new ApiError(500, "User already exists");
  // }

  const user = await User.create({
    userName,
    email,
    password,
  });

  if (!user) {
    throw new ApiError(500, "Failed to create user.");
  }
  const token = await user.generateRandomToken();
  const verificationToken = `${process.env.API_STRUCTURE}/verify/${token}`;

  // 3. Save user (hashed password and hashed token stored in DB)

  await user.save();
  console.log("VERIFICATION TOKEN: ", verificationToken);

  const emailContent = registrationEmail(userName, verificationToken);

  mailSender({
    email,
    subject: "Authentication Verification Link",

    mailGenContent: emailContent,
  });

  return res.status(200).json(new ApiResponse(200, "Collected success"));
});

const emailVerification = asyncHandler(async (req, res) => {
  const { token } = req.params;

  if (!token) {
    throw new ApiError(500, "URL not found");
  }

  const user = await User.findOne({
    verificationToken: token,
    verificationTokenExpiryDate: { $gt: Date.now() },
  });

  if (!user) {
    throw new ApiError(500, "User not found");
  }
  user.isEmailVerified = true;
  user.verificationToken = undefined;
  user.verificationTokenExpiryDate = undefined;

  await user.save();
  return res.status(200).json(new ApiResponse(200, "Email Verified"));
});

const logInUser = asyncHandler(async (req, res) => {
  const { userName, email, password } = req.body;
  if (!password) {
    throw new ApiError(500, "Password field can not be empty.");
  }
  if (!email && !userName) {
    throw new ApiError(500, "Email or userName required.");
  }

  const user = await User.findOne({
    $or: [{ email }, { userName }],
  });
  if (!user) {
    throw new ApiError(522, "User does not exit.");
  }
  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    throw new ApiError(522, "Password did not match.");
  }

  const access_token = await user.generateAccessToken();

  // console.log("ACCHESSTOKEN: ", access_token);
  const cookieData = {
    httpOnly: true, // prevents client JS from accessing the cookie
    secure: process.env.NODE_ENV === "production", // only on HTTPS in production
    sameSite: "strict", // CSRF protection
    maxAge: 24 * 60 * 60 * 1000, // 1 day
  };
  res.cookie("accessToken", access_token, cookieData);

  user.isLoggedIn = true;
  await user.save();

  // const token = req.cookies?.accessToken; // retrieve cookie

  // if (!token) {
  //   return res.status(401).json({ message: "No token found, please log in" });
  // }
  // const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
  // console.log("decoded", decoded);

  return res.status(200).json(new ApiResponse(200, "LogIn Successful"));
});

const getMe = asyncHandler(async (req, res) => {
  const jwt_data = req.access_token_data;
  console.log("jwt_data: ", jwt_data);
  console.log("now time: ", Date.now() / 1000);
  console.log("expiry time: ", jwt_data.exp);

  // not required though bcz it jwt.verify() already checks it.

  if (jwt_data.exp < Date.now() / 1000) {
    throw new ApiError(500, "Token session expired");
  }
  const user = await User.findById({
    _id: jwt_data.id,
  });
  console.log("USER:", user);
  if (!user.isLoggedIn) {
    throw new ApiError(500, "User not Logged In");
  }
  return res
    .status(200)
    .json(new ApiResponse(200, "Get me is done successfully."));
});

const logOut = asyncHandler(async (req, res) => {
  const jwt_data = req.access_token_data;
  console.log("jwt_data: ", jwt_data);
  const user = await User.findById({ _id: jwt_data.id }).select(" -password ");

  if (!user) {
    throw new ApiError(404, "User not found");
  }
  console.log("USER:", user);
  if (!user.isLoggedIn) {
    throw new ApiError(500, "User not Logged In");
  }
  user.isLoggedIn = false;
  user.accessToken = undefined;
  user.accessTokenExpiryDate = undefined;
  res.clearCookie("accessToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  });
  await user.save();
  return res.status(200).json(new ApiResponse(200, "User Logged Out"));
});
const reset = asyncHandler(async (req, res) => {
  const { email, userName } = await req.body;
  if (!email && !userName) {
    throw new ApiError(500, "Username and Email both can not be empty");
  }
  const user = await User.findOne({
    $or: [{ email }, { userName }],
  });
  if (!user) {
    throw new ApiError(500, "Not found user");
  }
  const resetPasswordToken = await user.generateRandomToken();
  const resetUrl = `${process.env.API_STRUCTURE}/changepassword/${resetPasswordToken}`;

  mailSender({
    email,
    subject: "Reset Your Password",
    mailGenContent: resetPasswordEmail(user.userName, resetUrl),
  });

  user.resetPasswordToken = resetPasswordToken;
  user.resetPasswordTokenExpiry = Date.now() + 1000 * 60 * 10;
  await user.save();

  return res
    .status(200)
    .json(new ApiResponse(200, "Reset token sent via email"));
});

const changePass = asyncHandler(async (req, res) => {
  const token = req.params;
  if (!token) {
    throw new ApiError(500, "reset token not found");
  }

  const user = await User.findOne({ resetPasswordToken: token });
  if (!user) {
    throw new ApiError(500, "User does not exist");
  }
});

export { registerUser, emailVerification, logInUser, getMe, logOut, reset };
