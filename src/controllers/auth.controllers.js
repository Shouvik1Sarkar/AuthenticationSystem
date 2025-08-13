import asyncHandler from "../utils/asyncHandler.utils.js";

const registerUser = asyncHandler(async (req, res) => {
  const { userName, email, password } = req.body;
  console.log("UserName: ", userName);
  console.log("email: ", email);
  console.log("password: ", password);
  return res.status(200).json({
    message: "Collected Success",
  });
});

export { registerUser };
