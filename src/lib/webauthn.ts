import { arrayBufferToBase64Url, base64UrlToArrayBuffer } from "./crypto";

// Check if the current browser/system supports the PRF extension
export async function checkPrfSupport(): Promise<boolean> {
  console.log("[WebAuthn] Checking PRF extension support...");
  if (typeof window === "undefined" || !window.PublicKeyCredential) {
    console.warn("[WebAuthn] PublicKeyCredential is not defined in window. WebAuthn is unsupported.");
    return false;
  }
  
  const pubKeyClass = PublicKeyCredential as any;
  if (typeof pubKeyClass.getClientCapabilities !== "function") {
    console.log("[WebAuthn] getClientCapabilities is not a function. Assuming supported but can't verify PRF pre-emptively.");
    return true; 
  }

  try {
    const caps = await pubKeyClass.getClientCapabilities();
    const isSupported = !!caps.extensions?.includes("prf");
    console.log("[WebAuthn] getClientCapabilities returned extensions. PRF supported:", isSupported);
    return isSupported;
  } catch (e) {
    console.error("[WebAuthn] Error checking capabilities:", e);
    return true;
  }
}

export interface RegisterResult {
  credentialId: string;
  prfEnabled: boolean;
  prfSalt: Uint8Array;
  prfOutput?: ArrayBuffer;
}

// Register a new passkey credential requesting PRF support
export async function registerPasskey(username: string = "Vault User"): Promise<RegisterResult> {
  console.log("[WebAuthn] Preparing credentials.create configurations...");
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const rpId = window.location.hostname || "localhost";
  
  // A unique salt generated for this passkey's PRF derivation
  const prfSalt = crypto.getRandomValues(new Uint8Array(32));
  console.log("[WebAuthn] RP ID (Domain):", rpId, "Salt Length:", prfSalt.byteLength);

  const options: any = {
    challenge,
    rp: {
      name: "Passkey Vault App",
      id: rpId
    },
    user: {
      id: userId,
      name: username,
      displayName: username
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },   // ES256 (ECDSA)
      { type: "public-key", alg: -257 }  // RS256 (RSA)
    ],
    authenticatorSelection: {
      residentKey: "required",
      requireResidentKey: true,
      userVerification: "required"
    },
    extensions: {
      prf: {
        eval: {
          first: prfSalt
        }
      }
    }
  };

  console.log("[WebAuthn] Calling navigator.credentials.create with options:", options);
  
  try {
    const credential = (await navigator.credentials.create({
      publicKey: options
    })) as any;

    if (!credential) {
      throw new Error("navigator.credentials.create returned null");
    }

    console.log("[WebAuthn] Credential successfully created:", credential);
    const extResults = credential.getClientExtensionResults() as any;
    console.log("[WebAuthn] Client extension results:", extResults);
    
    const prfEnabled = !!extResults.prf?.enabled;
    
    let prfOutput: ArrayBuffer | undefined = undefined;
    if (extResults.prf?.results?.first) {
      prfOutput = extResults.prf.results.first as ArrayBuffer;
    }

    const credentialId = arrayBufferToBase64Url(credential.rawId);
    console.log("[WebAuthn] Derived Credential ID:", credentialId, "PRF Enabled:", prfEnabled, "Has PRF Output directly:", !!prfOutput);

    return {
      credentialId,
      prfEnabled,
      prfSalt,
      prfOutput
    };
  } catch (e: any) {
    console.error("[WebAuthn Error] navigator.credentials.create failed:", e);
    throw e;
  }
}

// Request the PRF key from an existing passkey by asserting it
export async function getPasskeyPrfOutput(credentialId: string, salt: Uint8A