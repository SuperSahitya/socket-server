import express, { Express, Request, Response } from "express";
import dotenv from "dotenv";

dotenv.config();

const app = express();

app.get("/", (req: Request, res: Response) => {
  res.send("hello, world!");
});

app.listen(3000, () => {
  console.log("http://localhost:3000");
});
