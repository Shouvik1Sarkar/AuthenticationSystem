import { Router } from "express";
import { registerUser } from "../controllers/auth.controllers.js";

const authRoute = Router();

authRoute.route("/register").post(registerUser);

export default authRoute;
