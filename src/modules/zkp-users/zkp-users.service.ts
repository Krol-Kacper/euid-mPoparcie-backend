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
          claims: [{ path: ["family_name"] }, { path: ["given_name"] }],
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

/**
 * STRZELA TYLKO RAZ. Jeśli użytkownik zatwierdził -> zwraca Token.
 * Jeśli nadal czeka -> zwraca null. Zapobiega to blokowaniu Node.js.
 */
export const zkprequestuserHashService = async (
  transactionId: string,
): Promise<string> => {
  const timeoutMs = 5 * 60 * 1000; // Maksymalny czas oczekiwania: 5 minut
  const intervalMs = 2000; // Odstęp między zapytaniami: 2 sekundy
  const started = Date.now();
  const baseUrl = getVerifierBaseUrl();

  while (Date.now() - started < timeoutMs) {
    try {
      // Strzał do API v2 sandboxa
      const resp = await axios.get(
        `${baseUrl}/ui/presentations/${transactionId}`,
        {
          headers: { accept: "application/json" },
        },
      );

      // Jeśli otrzymamy status 200 i transakcja została zakończona sukcesem
      if (
        resp.status === 200 &&
        resp.data
      ) {
        const payload = resp.data;

        // Wyciągamy dane z formatu dc+sd-jwt (zgodnie z nowym body z Brukseli)
        const walletData =
          payload?.get_wallet_response?.verifiable_presentations?.[0]?.claims;

        // Szukamy identyfikatora (w tym profilu v2 najpewniejsze jest nazwisko lub imię)
        const personalId = walletData?.family_name || walletData?.given_name;

        if (!personalId) {
          throw new Error(
            "Bruksela nie zwróciła oczekiwanych pól (family_name/given_name)",
          );
        }

        // Generujemy unikalny userHash dla Twojego drzewa Merkle'a
        const userHash = crypto
          .createHash("sha256")
          .update(String(personalId))
          .digest("hex");

        // Budujemy token dla rejestracji/3
        const token = generateToken({
          username: String(personalId),
          userId: userHash,
          role: "zkp-user",
        });

        return token; // Przerywamy pętlę i zwracamy gotowy token!
      }
    } catch (err: any) {
      const status = err?.response?.status;

      // Kod 405 (Method Not Allowed) lub 404 oznacza w unijnym API, że transakcja istnieje,
      // ale użytkownik jeszcze nie kliknął "Udostępnij" w telefonie.
      if (status === 400) {
        // Logika "Still Pending" — ignorujemy błąd i pozwalamy pętli kręcić się dalej
        console.log(
          `[Polling] Transakcja ${transactionId} wciąż oczekuje (Status HTTP: ${status})...`,
        );
      } else {
        // Jeśli wystąpił inny błąd (np. brak sieci, błąd 500 w Brukseli), rzucamy wyjątek wyżej
        throw err;
      }
    }

    // Odczekaj 2 sekundy przed kolejną próbą
    await sleep(intervalMs);
  }

  // Jeśli pętla wyjdzie poza czas 5 minut
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
