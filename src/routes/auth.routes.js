import { Router } from "express";
import {
  emailVerification,
  getMe,
  logInUser,
  logOut,
  registerUser,
} from "../controllers/auth.controllers.js";
import {
  userLogIn,
  userRegister,
} from "../validators/validateInputs.validators.js";
import { validate } from "../middlewares/validators.middlewares.js";
import { jwt_token } from "../middlewares/tokenValidation.middlewares.js";

const authRoute = Router();

authRoute.route("/register").post(userRegister(), validate, registerUser);
authRoute.route("/verify/:token").get(emailVerification);
authRoute.route("/login").post(userLogIn(), validate, logInUser);
authRoute.route("/getMe").get(jwt_token, getMe);
authRoute.route("/logout").get(jwt_token, logOut);

export default authRoute;
