import { ApiError } from "../utils/api-error-handler.utils.js";
import { validationResult } from "express-validator";
export const validate = async (req, res, next) => {
  const errors = validationResult(req);

  if (errors.isEmpty()) {
    return next();
  }

  const extractedError = [];

  errors.array().forEach((err) => {
    extractedError.push({
      [err.param]: err.msg,
    });
  });
  throw new ApiError(
    522,
    "Recieved data not valid. validators validation error",
    extractedError
  );
};
