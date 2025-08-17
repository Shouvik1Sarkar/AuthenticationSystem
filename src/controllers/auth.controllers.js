import asyncHandler from "../utils/asyncHandler.utils.js";
import { ApiError } from "../utils/api-error-handler.utils.js";
import { ApiResponse } from "../utils/api-response.utils.js";
import { User } from "../models/user.models.js";
import mailSender, {
  forgotPasswordEmail,
  twoFactorEmail,
} from "../utils/mail.utils.js";
import { registrationEmail } from "../utils/mail.utils.js";
import speakeasy from "speakeasy";
import {
  generateSecrets,
  generateToken,
  verifyTwoFactor,
} from "../utils/twoFactor.utils.js";
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

  if (user.twoFactorVerification) {
    const token = generateToken(user.twoFactorSecret);
    console.log("TOKEN: ", token);
    console.log(" TWO FACTOR SECRET TOKEN: ", user.twoFactorSecret);
    mailSender({
      email,
      subject: "Twofactor secret token",
      mailGenContent: twoFactorEmail(user.userName, token),
    });

    return res
      .status(200)
      .json(
        new ApiResponse(
          200,
          "successfully generated and sent login token token"
        )
      );
  }

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

const twoStepLogin = asyncHandler(async (req, res) => {
  const jwt_token_data = req.access_token_data;
  console.log("ttttt: ", jwt_token_data);
  const user = await User.findById({ _id: jwt_token_data.id });
  if (!user) {
    throw new ApiError(500, "Jwt data not found");
  }

  const secret = user.twoFactorSecret;

  const { otp } = req.body;

  console.log("TOKEN: ", otp);
  console.log(" TWO FACTOR SECRET TOKEN: ", user.twoFactorSecret);

  const tokenValidates = verifyTwoFactor(secret, otp);
  console.log("pppppp", tokenValidates);
  if (!tokenValidates) {
    throw new ApiError(500, "OTP did not match");
  }
  user.isLoggedIn = true;
  await user.save();
  return res.status(200).json(new ApiResponse(200, "LogIn Successful"));
});
const enableTwoFactor = asyncHandler(async (req, res) => {
  const jwt_token_data = req.access_token_data;
  console.log("ttttt: ", jwt_token_data);
  const user = await User.findById({ _id: jwt_token_data.id });
  if (!user) {
    throw new ApiError(500, "Jwt data not found");
  }
  if (!user.isLoggedIn) {
    throw new ApiError(500, "not logged in");
  }

  // const secret = speakeasy.generateSecret({ length: 20 });
  // const token = speakeasy.totp({
  //   secret: secret.base32,
  //   encoding: "base32",
  //   step: 120,
  // });
  const secret = generateSecrets();
  const twoSteptoken = generateToken(secret);
  console.log("TwoStep token1: ", twoSteptoken);
  console.log("secret: ", secret.base32);
  console.log("secret HASHED: ", twoSteptoken);
  const email = user.email;
  mailSender({
    email,
    subject: "Twofactor secret token",
    mailGenContent: twoFactorEmail(user.userName, twoSteptoken),
  });

  user.twoFactorSecret = secret.base32;
  // user.twoFactorSecretOtpExpiry = Date.now() + 10 * 60 * 1000;
  await user.save();
  return res
    .status(200)
    .json(new ApiResponse(200, "successfully generated token"));
});

const twoFactorOtpSend = asyncHandler(async (req, res) => {
  const jwt_token_data = req.access_token_data;
  console.log("ttttt: ", jwt_token_data);
  const user = await User.findById({ _id: jwt_token_data.id });
  if (!user) {
    throw new ApiError(500, "Jwt data not found");
  }

  // if (Date.now() >= user.twoFactorSecretOtpExpiry) {
  //   throw new ApiError(500, "otp expired");
  // }

  const secret = user.twoFactorSecret;

  const { otp } = req.body;
  // const tokenValidates = speakeasy.totp.verify({
  //   secret: secret,
  //   encoding: "base32",
  //   token: otp,
  //   step: 120,
  //   window: 1, // adds extra 2 mins
  // });

  const tokenValidates = verifyTwoFactor(secret, otp);
  console.log("pppppp", tokenValidates);
  if (!tokenValidates) {
    throw new ApiError(500, "OTP did not match");
  }

  user.twoFactorVerification = true;
  await user.save();
  return res
    .status(200)
    .json(new ApiResponse(200, "successfully enabled two factor token"));
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
const forgotPassword = asyncHandler(async (req, res) => {
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
  const token = await user.generateRandomToken();
  const resetUrl = `${process.env.API_STRUCTURE}/changepassword/${token}`;

  mailSender({
    email,
    subject: "Reset Your Password",
    mailGenContent: forgotPasswordEmail(user.userName, resetUrl),
  });

  user.forgotPassord = token;
  user.forgotPassordExpiry = Date.now() + 1000 * 60 * 10;
  await user.save();

  return res
    .status(200)
    .json(new ApiResponse(200, "Reset token sent via email"));
});

const changePass = asyncHandler(async (req, res) => {
  const { token } = req.params;
  if (!token) {
    throw new ApiError(500, "reset token not found");
  }

  const user = await User.findOne({
    forgotPassord: token,
    forgotPassordExpiry: { $gt: Date.now() },
  });
  if (!user) {
    throw new ApiError(500, "User does not exist");
  }
  const { newPassword, repeatPassword } = req.body;
  if (newPassword !== repeatPassword) {
    throw new ApiError(500, "New password and repeat password does not match.");
  }

  user.password = newPassword;
  user.forgotPassord = undefined;
  user.forgotPassordExpiry = undefined;
  await user.save();
  return res.status(200).json(new ApiResponse(200, "password changed"));
});

const resetPassword = asyncHandler(async (req, res) => {
  const jwt_data = req.access_token_data;
  console.log("JWT DATA: ", jwt_data);
  if (!jwt_data) {
    throw new ApiError(500, "jwt data was not found");
  }
  const user = await User.findById({ _id: jwt_data.id });
  if (!user) {
    throw new ApiError(500, "User not found");
  }
  if (!user.isLoggedIn) {
    throw new ApiError(500, "User not LoggedIn");
  }

  const { password, newPassword, repeatPassword } = req.body;
  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    throw new ApiError(500, "Password not Matched");
  }
  if (newPassword !== repeatPassword) {
    throw new ApiError(500, "New password and repeat password does not match.");
  }

  user.password = newPassword;
  user.isLoggedIn = false;
  user.accessToken = undefined;
  user.accessTokenExpiryDate = undefined;
  res.clearCookie("accessToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  });
  await user.save();
  return res.status(200).json(new ApiResponse(200, "password reset Done"));
});

export {
  registerUser,
  emailVerification,
  logInUser,
  getMe,
  logOut,
  forgotPassword,
  changePass,
  resetPassword,
  enableTwoFactor,
  twoFactorOtpSend,
  twoStepLogin,
};
