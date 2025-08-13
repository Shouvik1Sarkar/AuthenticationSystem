import app from "./app.js";

import dotenv from "dotenv";
import dbConnect from "./db/connected.db.js";
dotenv.config({
  path: "./.env",
});

const port = process.env.PORT || 3000;

dbConnect();

app.listen(port, () => {
  console.log("Example app running at port: ", port);
});
