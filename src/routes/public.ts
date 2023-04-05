import express, { Request, Response } from "express";

export const publicRoute = express.Router();

publicRoute.get("/health", (req: Request, res: Response): void => {
  res.send("App Running!");
});
