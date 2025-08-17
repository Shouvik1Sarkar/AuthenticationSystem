import { Router } from "express";
import {
  changePass,
  disableTwoFactor,
  emailVerification,
  enableTwoFactor,
  forgotPassword,
  getMe,
  logInUser,
  logOut,
  registerUser,
  resetPassword,
  twoFactorOtpSend,
  twoStepLogin,
} from "../controllers/auth.controllers.js";
import {
  changePassword,
  forgotPassordValidator,
  resetPassordValidator,
  userLogIn,
  userRegister,
} from "../validators/validateInputs.validators.js";
import { validate } from "../middlewares/validators.middlewares.js";
import { jwt_token } from "../middlewares/tokenValidation.middlewares.js";

const authRoute = Router();

authRoute.route("/register").post(userRegister(), validate, registerUser);
authRoute.route("/verify/:token").get(emailVerification);
authRoute.route("/login").post(userLogIn(), validate, logInUser);
authRoute.route("/twoStepLogin").post(jwt_token, twoStepLogin);
authRoute.route("/twofactor").get(jwt_token, enableTwoFactor);
authRoute.route("/twofactorotpsend").post(jwt_token, twoFactorOtpSend);
authRoute.route("/disableTwoFactor").post(jwt_token, disableTwoFactor);
authRoute.route("/getMe").get(jwt_token, getMe);
authRoute.route("/logout").post(jwt_token, logOut);
authRoute
  .route("/forgot")
  .post(forgotPassordValidator(), validate, forgotPassword);
authRoute
  .route("/changepassword/:token")
  .post(changePassword(), validate, changePass);
authRoute
  .route("/reset")
  .post(resetPassordValidator(), validate, jwt_token, resetPassword);

export default authRoute;
