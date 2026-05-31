import axios from "axios";
import { ZkpUserModel } from "./zkp-users.model.js";
import { generateToken } from "../../shared/utils/jwt.util.js";
import { ZkpMetadataModel, ZkpCommitmentModel } from "./merkle-tree.model.js";
import {
  addMemberToTree,
  buildSemaphoreGroup,
} from "./merkle-tree-functions.js";
import crypto from "crypto";

const getVerifierBaseUrl = () => {
  const verifierHost =
    process.env.VERIFIER_URL ?? "https://dev.verifier-backend.eudiw.dev";
  return verifierHost;
};

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export const generateLinkService = async () => {
  const body = {
    dcql_query: {
      credentials: [
        {
          id: "query_1",
          format: "dc+sd-jwt",
          meta: {
            vct_values: ["urn:eudi:pid:1"],
          },
          claims: [{ path: ["family_name"] }, { path: ["given_name"] }, { path: ["personal_administrative_number"] }],
        },
      ],
    },
    nonce: crypto.randomUUID(),
    request_uri_method: "post_get",
    profile: "openid4vp",
    authorization_request_uri: "openid4vp://",
  };

  const baseUrl = getVerifierBaseUrl();
  const response = await axios.post(`${baseUrl}/ui/presentations/v2`, body, {
    headers: { "Content-Type": "application/json" },
  });
  const data = response.data || {};
  console.log(data.transaction_id);
  console.log(data.request_uri);
  return {
    transactionId: data.transaction_id,
    qr: data.authorization_request_uri,
  };
};


export const zkprequestuserHashService = async (
  transactionId: string,
): Promise<string> => {
  const timeoutMs = 5 * 60 * 1000;
  const intervalMs = 3000;
  const started = Date.now();
  const baseUrl = getVerifierBaseUrl();


  while (Date.now() - started < timeoutMs) {
    try {
      const resp = await axios.get(
        `${baseUrl}/ui/presentations/${transactionId}`,
        {
          headers: { accept: "application/json" },
        },
      );

      const sdJwt: string = resp.data.vp_token.query_1[0];

      const utilitiesResp = await axios.post(
        `${baseUrl}/utilities/process/sdJwtVc`,
        `sd_jwt_vc=${encodeURIComponent(sdJwt)}`,
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } },
      );

      const claims = utilitiesResp.data;
      const familyName = claims.family_name;
      const givenName = claims.given_name;
      const adminNumber = claims.personal_administrative_number;

      const userHash = crypto
        .createHash("sha256")
        .update(`${familyName}${givenName}${adminNumber}`)
        .digest("hex");

      return generateToken({
        username: "registrar",
        userId: userHash,
        role: "zkp-user",
      });
    } catch (err: any) {
      const status = err?.response?.status;

      if (status === 400) {
        console.log(
          `[Polling] Transakcja ${transactionId} wciąż oczekuje (Status HTTP: ${status})...`,
        );
      } else {
        throw err;
      }
    }

    await sleep(intervalMs);
  }

  throw new Error(
    "Timeout: Użytkownik nie potwierdził weryfikacji w EUDI Wallet w wymaganym czasie.",
  );
};

export const zkpregisterService = async (
  userHash: string,
  commitment: string,
) => {
  const existing = await ZkpUserModel.findOne({ userHash });
  if (existing) throw new Error("Taka osoba już jest zarejestrowana");

  const created = await ZkpUserModel.create({ userHash });
  if (!created) throw new Error("Nie udało się zarejestrować użytkownika");

  try {
    await addMemberToTree(commitment);
    const group = await buildSemaphoreGroup();
    const root = (group && (group as any).root) ?? null;
    console.log("Nowy korzeń drzewa Merkle'a:", root);
    return true;
  } catch (error) {
    console.error("Błąd podczas rejestracji ZKP:", error);
    try {
      if (created && created._id) {
        await ZkpUserModel.deleteOne({ _id: created._id }).exec();
        console.log("Rollback udany: usunięto użytkownika z bazy");
      }
    } catch (rollbackErr) {
      console.error("Rollback nie powiódł się:", rollbackErr);
    }
    throw error;
  }
};

export const zkpTreeDumpService = async (groupId: string = "1") => {
  try {
    const root = await ZkpMetadataModel.find({ groupId }).sort("index").exec();
    const members = await ZkpCommitmentModel.find({ groupId })
      .sort("index")
      .exec();
    return { root, members };
  } catch (error) {
    console.error("Błąd podczas dumpowania drzewa:", error);
    throw new Error("Nie udało się pobrać danych drzewa");
  }
};
