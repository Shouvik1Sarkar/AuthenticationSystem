import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import jwt from "jsonwebtoken";
const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
    },
    userName: {
      type: String,
      required: true,
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
  },
  { timestamps: true }
);
export const User = mongoose.model("User", userSchema);

// save and hash the password

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) next();

  this.password = await bcrypt.hash(this.password, 10);
});

// compare the saved password
userSchema.methods.comparePassword = async (password) => {
  return await bcrypt.compare(password, this.password);
};

userSchema.methods.generateAccessToken = async () => {
  jwt.sign(
    {
      id: this._id,
      email: this.email,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
    }
  );
};
userSchema.methods.generateRefreshToken = async () => {
  jwt.sign(
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
userSchema.methods.verificationToken = async () => {
  const verificationToken = crypto.randomBytes(20).toString("hex");
  const hasedVerificationToken = crypto
    .createHash("sha256")
    .update(verificationToken)
    .digest("hex");

  const verificationTokenExpiry = Date.now() + 20 * 60 * 1000;

  return { verificationToken, hasedVerificationToken, verificationTokenExpiry };
};

// JWT is stateless bcz it posseses the exp info and doesn't require dn query before every operation
