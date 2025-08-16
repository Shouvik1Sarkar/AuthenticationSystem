import jwt from "jsonwebtoken";
import { ApiError } from "../utils/api-error-handler.utils.js";
import asyncHandler from "../utils/asyncHandler.utils.js";

const jwt_token = asyncHandler(async (req, res, next) => {
  const token = req.cookies?.accessToken;

  if (!token) {
    throw new ApiError(522, "JWT Token not found.(MIDDLEWARE)");
  }
  const retrieved_data = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
  console.log("Retrieved Data: ", retrieved_data);
  if (!retrieved_data) {
    throw new ApiError(
      522,
      "DATA could not be retrieved from JWT.(MIDDLEWARE)"
    );
  }

  req.access_token_data = retrieved_data;
  next();
});

export { jwt_token };
