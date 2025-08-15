import { Router } from "express";
import {
  emailVerification,
  logInUser,
  registerUser,
} from "../controllers/auth.controllers.js";
import {
  userLogIn,
  userRegister,
} from "../validators/validateInputs.validators.js";
import { validate } from "../middlewares/validators.middlewares.js";

const authRoute = Router();

authRoute.route("/register").post(userRegister(), validate, registerUser);
authRoute.route("/verify/:token").get(emailVerification);
authRoute.route("/login").post(userLogIn(), validate, logInUser);

export default authRoute;
