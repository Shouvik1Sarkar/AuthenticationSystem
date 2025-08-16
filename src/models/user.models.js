import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { type } from "os";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
    },
    userName: {
      type: String,
      // required: true,
      trim: true,
      lowercase: true,
      unique: true,
    },
    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
      trim: true,
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    verificationToken: {
      type: String,
    },
    verificationTokenExpiryDate: {
      type: Date,
    },
    isLoggedIn: {
      type: Boolean,
      default: false,
    },
    accessToken: {
      type: String,
    },
    accessTokenExpiryDate: {
      type: Date,
    },
    refreshToken: {
      type: String,
    },
    refreshTokenExpiryDate: {
      type: Date,
    },
    resetPasswordToken: {
      type: String,
    },
    resetPasswordTokenExpiry: {
      type: Date,
    },
    forgotPassord: {
      type: String,
    },
    forgotPassordExpiry: {
      type: Date,
    },
  },
  {
    timestamps: true,
  }
);

// save and hash the password

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// compare the saved password
userSchema.methods.comparePassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

userSchema.methods.generateAccessToken = async function () {
  return jwt.sign(
    {
      id: this._id,
      email: this.email,
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
    }
  );
};
userSchema.methods.generateRefreshToken = async function () {
  return jwt.sign(
    {
      id: this._id,
      email: this.email,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
    }
  );
};
userSchema.methods.generateRandomToken = async function () {
  const unHashedVerificationToken = crypto.randomBytes(20).toString("hex");
  const hashedVerificationToken = crypto
    .createHash("sha256")
    .update(unHashedVerificationToken)
    .digest("hex");

  // this.verificationToken = hashedVerificationToken;
  this.verificationToken = unHashedVerificationToken;

  this.verificationTokenExpiryDate = Date.now() + 20 * 60 * 1000;

  return unHashedVerificationToken;
};
export const User = mongoose.model("User", userSchema);
// JWT is stateless bcz it posseses the exp info and doesn't require dn query before every operation

// console.log("TYPE OF: ", userSchema);
