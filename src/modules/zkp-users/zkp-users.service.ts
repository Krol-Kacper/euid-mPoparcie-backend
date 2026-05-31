import axios from "axios";
import { ZkpUserModel } from "./zkp-users.model.js";
import { generateToken } from "../../shared/utils/jwt.util.js";
import { ZkpMetadataModel, ZkpCommitmentModel } from "./merkle-tree.model.js";
import { addMemberToTree, buildSemaphoreGroup } from "./merkle-tree-functions.js";
import crypto from "crypto";

const getVerifierBaseUrl = () => {
  const verifierHost = process.env.VERIFIER_URL ?? "https://dev.verifier-backend.eudiw.dev";
  return verifierHost
};

export const generateLinkService = async () => {

  const body = {
    dcql_query: {
      credentials: [
        {
          id: "query_1",
          format: "dc+sd-jwt",
          meta: {
            vct_values: ["urn:eudi:pid:1"]
          },
          claims: [
            { path: ["family_name"] },
            { path: ["given_name"] }
          ]
        }
      ]
    },
    nonce: crypto.randomUUID(), 
    request_uri_method: "post_get",
    profile: "openid4vp",
    authorization_request_uri: "openid4vp://"
  };

  const baseUrl = getVerifierBaseUrl();
  const response = await axios.post(`${baseUrl}/ui/presentations/v2`, body, {
    headers: { "Content-Type": "application/json" },
  });
  
  const data = response.data || {};
  console.log(data);
  return { 
    transactionId: data.transaction_id, 
    qr: data.request_uri, 
    raw: data 
  };
};

/**
 * STRZELA TYLKO RAZ. Jeśli użytkownik zatwierdził -> zwraca Token. 
 * Jeśli nadal czeka -> zwraca null. Zapobiega to blokowaniu Node.js.
 */
export const zkprequestuserHashService = async (transactionId: string): Promise<string | null> => {
  try {
    const baseUrl = getVerifierBaseUrl();
    const resp = await axios.get(`${baseUrl}/ui/presentations/v2/${transactionId}`);
    
    // Sprawdzamy czy kontener odpowiedział statusem 200 i stan transakcji to "Submitted"
    if (resp.status === 200 && resp.data && resp.data.status === "Submitted") {
      const payload = resp.data;

      // NAPRAWA 2: Dopasowanie wyciągania danych do struktury v2 (DCQL)
      // W API v2 dane z portfela lądują w obiekcie wallet_response
      const walletResponse = payload?.get_wallet_response || payload?.wallet_response;
      
      // Wyciągamy claims w zależności od tego, czy telefon przysłał mdoc czy sd-jwt
      const sdJwtClaims = walletResponse?.verifiable_presentations?.[0]?.claims;
      
      const walletData = sdJwtClaims;
      
      // Szukamy unikalnego identyfikatora (PESEL / PAN)
      const personalId = walletData?.personal_administrative_number 
                      || walletData?.personal_number 
                      || walletData?.family_name; // fallback na nazwisko jeśli brak peselu w testach

      if (!personalId) {
        throw new Error("Nie udało się wyciągnąć unikalnego numeru identyfikacyjnego z portfela");
      }

      // Generujemy bezpieczny hash dla drzewa Merkle'a
      const userHash = crypto.createHash("sha256").update(String(personalId)).digest("hex");

      const token = generateToken({
        username: String(personalId),
        userId: userHash,
        role: "zkp-user",
      });
    
      return token;
    } 
    
    return null; // Status to np. "Requested" - użytkownik jeszcze nie kliknął w telefonie
    
  } catch (err: any) {
    const status = err?.response?.status;
    // W API v2 jeśli transakcja nie jest gotowa, serwer może zwrócić 200 ze statusem "Requested" 
    // lub rzucić błąd 404/405 w zależności od dokładnej podwersji kontenera.
    if (status === 405 || status === 202 || status === 404) {
      return null;
    }
    throw err;
  }
};

export const zkpregisterService = async (userHash: string, commitment: string) => {
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
    const members = await ZkpCommitmentModel.find({ groupId }).sort("index").exec();
    return { root, members };
  } catch (error) {
    console.error("Błąd podczas dumpowania drzewa:", error);
    throw new Error("Nie udało się pobrać danych drzewa");
  }
};