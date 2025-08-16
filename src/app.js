import express from "express";

import cookieParser from "cookie-parser";

import authRoute from "./routes/auth.routes.js";
import global_error_handler from "./middlewares/global-error-handler.middlewares.js";

const app = express();
app.use(express.json());
app.use(cookieParser());

app.use("/api/v1/users", authRoute);

app.use(global_error_handler);

export default app;
