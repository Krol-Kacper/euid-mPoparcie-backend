import express, { type Router } from "express";
import { zkprequestuserHash, zkpregister } from "./zkp-users.controller.js";
import { zkpregisterSchema } from "./zkp-users.schema.js";
import { zkpTreeDump } from "./zkp-users.controller.js";

import { verifyToken } from "../../shared/middleware/jwt.middleware.js";
import { validateData } from "../../shared/middleware/validation.middleware.js";

import { generateLink } from "./zkp-users.controller.js";

const router: Router = express.Router();

// init presentation (creates transaction + QR)
router.get("/register/1", generateLink);
// poll presentation status by transaction id
router.get("/register/2/:transaction_id", zkprequestuserHash);
router.post(
  "/register/3",
  verifyToken,
  validateData(zkpregisterSchema),
  zkpregister,
);
// legacy Identt webhook removed - using eudi-verifier polling flow instead
router.get("/tree-dump", zkpTreeDump);

export default router;
