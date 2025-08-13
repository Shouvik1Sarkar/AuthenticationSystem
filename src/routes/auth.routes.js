import { Router } from "express";
import { registerUser } from "../controllers/auth.controllers.js";
import { userRegister } from "../validators/validateInputs.validators.js";
import { validate } from "../middlewares/validators.middlewares.js";

const authRoute = Router();

authRoute.route("/register").post(userRegister(), validate, registerUser);

export default authRoute;
