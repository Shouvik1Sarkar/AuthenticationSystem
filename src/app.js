import express from "express";

import authRoute from "./routes/auth.routes.js";

const app = express();
app.use(express.json());

app.use("/api/v1/users", authRoute);

export default app;
