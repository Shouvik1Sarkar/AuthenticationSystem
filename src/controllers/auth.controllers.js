import asyncHandler from "../utils/asyncHandler.utils.js";
import { ApiError } from "../utils/api-error-handler.utils.js";

const registerUser = asyncHandler(async (req, res) => {
  const { userName, email, password } = req.body;
  console.log("UserName: ", userName);
  console.log("email: ", email);
  console.log("password: ", password);

  if (!userName || !email || !password) {
    throw new ApiError(500, "All credentials are required");
  }
  return res.status(200).json({
    message: "Collected Success",
  });
});

export { registerUser };
