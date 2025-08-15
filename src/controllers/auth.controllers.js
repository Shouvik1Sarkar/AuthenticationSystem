import asyncHandler from "../utils/asyncHandler.utils.js";
import { ApiError } from "../utils/api-error-handler.utils.js";
import { User } from "../models/user.models.js";
import mailSender from "../utils/mail.utils.js";
import { registrationEmail } from "../utils/mail.utils.js";
import crypto from "crypto";

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
  const verificationToken = await user.generateVerificationToken();

  // 3. Save user (hashed password and hashed token stored in DB)
  await user.save();

  console.log("VERIFICATION TOKEN: ", verificationToken);

  const emailContent = registrationEmail(userName, verificationToken);

  mailSender({
    email,
    subject: "Authentication Verification Link",

    mailGenContent: emailContent,
  });

  return res.status(200).json({
    message: "Collected Success",
  });
});

export { registerUser };
