import { type Request, type Response, type NextFunction } from "express";
import {
  zkprequestuserHashService,
  zkpregisterService,
} from "./zkp-users.service.js";
import type { RegisterDTO } from "./zkp-users.schema.js";
import { zkpTreeDumpService } from "./zkp-users.service.js";
import crypto from "crypto";
import { generateLinkService } from "./zkp-users.service.js";

export const zkprequestuserHash = async (
  req: Request<{ transaction_id: string }, any, any>,
  res: Response,
  next: NextFunction,
) => {
  try {
    const transaction_id = req.params.transaction_id;

    // UWAGA: Ta linia zatrzyma wykonanie kontrolera (zawiesi żądanie HTTP z frontendu)
    // na tak długo, aż użytkownik kliknie przycisk w telefonie lub minie 5 minut.
    const token = await zkprequestuserHashService(transaction_id);

    // Kiedy kod tu dotrze, oznacza to, że mamy już gotowy token
    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: 5 * 60 * 1000, // 5 minut
    });

    return res.status(201).json({
      status: "success",
      message: "Rejestracja/2 udana, token wygenerowany",
    });
  } catch (error) {
    next(error);
  }
};

export const zkpregister = async (
  req: Request<any, any, RegisterDTO>,
  res: Response,
  next: NextFunction,
) => {
  try {
    const userHash = (req as any).user?.userId;
    const commitment = req.body?.commitment;

    if (!userHash) {
      return res.status(400).json({ error: "Brak userHash w tokenie" });
    }

    const state = await zkpregisterService(userHash, commitment);
    return res
      .status(201)
      .json({ status: "success", message: "Rejestracja/3 udana" });
  } catch (error) {
    next(error);
  }
};

export const generateLink = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const linkData = await generateLinkService();
    return res.status(200).json({
      status: "success",
      message: "Rejestracja/1 udana",
      transactionId: linkData.transactionId,
      qr: linkData.qr,
    });
  } catch (error) {
    next(error);
  }
};

export const webhookReceiver = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    // Webhook-based flow is deprecated for eudi-verifier; polling is used instead.
    return res.status(501).json({
      error: "Webhook not supported. Use polling to check transaction status.",
    });
  } catch (error) {
    next(error);
  }
};

export const zkpTreeDump = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const treeData = await zkpTreeDumpService();
    return res.status(200).json({ status: "success", data: treeData });
  } catch (error) {
    next(error);
  }
};
