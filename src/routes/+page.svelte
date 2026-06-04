<script lang="ts">
  import { onMount } from "svelte";
  import { fade, slide, fly, scale } from "svelte/transition";
  import { 
    Lock, Unlock, KeyRound, Key, Plus, Search, Trash2, Edit3, Copy, Check, Eye, EyeOff, 
    Settings, Shield, LogOut, CopyCheck, AlertTriangle, RefreshCw, FileText, Globe, User, ExternalLink, Database
  } from "@lucide/svelte";
  import { appDataDir, join } from "@tauri-apps/api/path";
  import { 
    generateMEK, importMEK, derivePDK, encryptMEK, decryptMEK, 
    generateRecoveryKey, deriveRecoveryDK, encryptField, decryptField,
    base64ToArrayBuffer, arrayBufferToBase64
  } from "$lib/crypto";
  import { 
    initDb, checkVaultInitialized, getRecoveryMetadata, initializeVaultMetadata, 
    loadPasskeys, savePasskey, deletePasskey, loadCredentials, saveCredential, deleteCredential,
    type PasskeyRecord, type DbCredential 
  } from "$lib/db";
  import { 
    checkPrfSupport, registerPasskey, getPasskeyPrfOutput 
  } from "$lib/webauthn";

  // Import shadcn-svelte components
  import { Button } from "$lib/components/ui/button";
  import { Input } from "$lib/components/ui/input";
  import { Label } from "$lib/components/ui/label";
  import { Textarea } from "$lib/components/ui/textarea";
  import { Badge } from "$lib/components/ui/badge";
  import { Separator } from "$lib/components/ui/separator";
  import * as Card from "$lib/components/ui/card";
  import * as Dialog from "$lib/components/ui/dialog";
  import * as Select from "$lib/components/ui/select";
  import ThemeToggle from "$lib/components/ThemeToggle.svelte";

  // App state
  let appState = $state<"loading" | "setup" | "locked" | "dashboard">("loading");
  let prfSupported = $state(false);

  // Cryptographic secrets in memory (never stored to disk)
  let rawMekBytes = $state<Uint8Array | null>(null);
  let mekKey = $state<CryptoKey | null>(null);

  // Credentials and Database loading
  let passkeysList = $state<PasskeyRecord[]>([]);
  let selectedPasskeyId = $state<string>("");
  let recoveryKeyInput = $state("");
  let isUnlocking = $state(false);
  let setupError = $state("");
  let setupSuccess = $state(false);
  let generatedRecoveryKey = $state("");
  let firstPasskeyName = $state("Primary Passkey");

  // Dashboard state
  let decryptedCredentials = $state<{
    id: string;
    title: string;
    url: string;
    username: string;
    password: string;
    notes: string;
    createdAt: number;
    updatedAt: number;
  }[]>([]);

  let searchQuery = $state("");
  let activeCategory = $state<"all" | "login" | "note">("all");
  let selectedCredentialId = $state<string | null>(null);
  let mobileView = $state<"list" | "detail">("list");

  // Add/Edit modal variables
  let showAddModal = $state(false);
  let editMode = $state(false);
  let formId = $state("");
  let formTitle = $state("");
  let formUrl = $state("");
  let formUsername = $state("");
  let formPassword = $state("");
  let formNotes = $state("");
  let showFormPassword = $state(false);

  // Settings
  let showSettings = $state(false);
  let newPasskeyName = $state("");
  let isAddingPasskey = $state(false);
  let showRecoveryKeyReveal = $state(false);
  let actualRecoveryKeyString = $state("");
  let showRecoveryForm = $state(false);
  let dbPath = $state("");

  // UI copy helpers
  let copiedId = $state<string | null>(null);
  let copiedPasswordId = $state<string | null>(null);
  let copiedRecoveryKey = $state(false);

  // Derivations
  let filteredCredentials = $derived.by(() => {
    let result = decryptedCredentials;
    if (activeCategory === "login") {
      result = result.filter(c => c.url.trim() !== "");
    } else if (activeCategory === "note") {
      result = result.filter(c => c.url.trim() === "" && c.password.trim() === "");
    }
    
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(c => 
        c.title.toLowerCase().includes(q) || 
        c.url.toLowerCase().includes(q) || 
        c.username.toLowerCase().includes(q) || 
        c.notes.toLowerCase().includes(q)
      );
    }
    return result;
  });

  let selectedCredential = $derived(
    decryptedCredentials.find(c => c.id === selectedCredentialId) || null
  );

  onMount(async () => {
    try {
      await initDb();
      prfSupported = await checkPrfSupport();
      const isInitialized = await checkVaultInitialized();
      
      if (isInitialized) {
        passkeysList = await loadPasskeys();
        if (passkeysList.length > 0) {
          selectedPasskeyId = passkeysList[0].credential_id;
        }
        appState = "locked";
      } else {
        appState = "setup";
      }
    } catch (e) {
      console.error("Initialization error:", e);
      appState = "setup";
    }

    try {
      const appData = await appDataDir();
      dbPath = await join(appData, "vault.db");
    } catch (e) {
      console.error("Failed to resolve db path:", e);
      dbPath = "Unknown (Unable to resolve Tauri path)";
    }
  });

  async function handleSetup() {
    console.log("[Setup] Starting vault initialization with passkey name:", firstPasskeyName);
    setupError = "";
    setupSuccess = false;
    try {
      console.log("[Setup] Requesting Passkey registration via WebAuthn...");
      const reg = await registerPasskey(firstPasskeyName);
      console.log("[Setup] Passkey registration returned:", {
        credentialId: reg.credentialId,
        prfEnabled: reg.prfEnabled,
        hasPrfOutput: !!reg.prfOutput,
        prfSaltLength: reg.prfSalt.byteLength
      });

      if (!reg.prfEnabled) {
        throw new Error("Your browser registered the Passkey, but the authenticator did not enable the PRF extension. A device with PRF encryption capabilities is required.");
      }

      let prfOutput = reg.prfOutput;
      if (!prfOutput) {
        console.log("[Setup] PRF output was not returned during creation. Triggering immediate assertion fallback to get the key...");
        prfOutput = await getPasskeyPrfOutput(reg.credentialId, reg.prfSalt);
        console.log("[Setup] Immediate assertion fallback successful. PRF output byte length:", prfOutput.byteLength);
      } else {
        console.log("[Setup] PRF output returned directly during registration. Byte length:", prfOutput.byteLength);
      }

      console.log("[Setup] Generating Master Encryption Key (MEK)...");
      const mek = generateMEK();
      rawMekBytes = mek;
      console.log("[Setup] MEK generated successfully. Importing MEK...");
      mekKey = await importMEK(mek);

      console.log("[Setup] Deriving Passkey Derived Key (PDK) using HKDF-SHA256...");
      const pdk = await derivePDK(prfOutput, reg.credentialId);

      console.log("[Setup] Encrypting MEK with PDK using AES-GCM...");
      const encryptedMek = await encryptMEK(mek, pdk);

      console.log("[Setup] Saving primary passkey metadata to SQLite database...");
      await savePasskey(
        reg.credentialId,
        firstPasskeyName,
        arrayBufferToBase64(reg.prfSalt.buffer as ArrayBuffer),
        JSON.stringify(encryptedMek)
      );
      console.log("[Setup] Passkey metadata saved to SQLite.");

      console.log("[Setup] Generating recovery key...");
      const recoveryKey = generateRecoveryKey();
      generatedRecoveryKey = recoveryKey;
      actualRecoveryKeyString = recoveryKey;

      console.log("[Setup] Deriving Recovery Key Derived Key (RecoveryDK) using PBKDF2...");
      const recoverySalt = crypto.getRandomValues(new Uint8Array(16));
      const recoveryDk = await deriveRecoveryDK(recoveryKey, recoverySalt);
      
      console.log("[Setup] Encrypting MEK with RecoveryDK...");
      const encryptedMekWithRecovery = await encryptMEK(mek, recoveryDk);

      console.log("[Setup] Saving recovery metadata to SQLite...");
      await initializeVaultMetadata(
        arrayBufferToBase64(recoverySalt.buffer as ArrayBuffer),
        JSON.stringify(encryptedMekWithRecovery)
      );
      console.log("[Setup] Vault metadata initialized successfully.");

      // Reload passkeys so it is populated in settings
      passkeysList = await loadPasskeys();
      decryptedCredentials = [];
      appState = "dashboard";
    } catch (err: any) {
      console.error("[Setup Error] Failed to initialize vault:", err);
      setupError = err.message || "Credential setup failed. Please make sure biometrics or PIN is configured.";
    }
  }

  function enterVaultFromSetup() {
    decryptedCredentials = [];
    appState = "dashboard";
  }

  async function handleUnlockWithPasskey() {
    isUnlocking = true;
    setupError = "";
    try {
      const record = passkeysList.find(p => p.credential_id === selectedPasskeyId);
      if (!record) throw new Error("Please select a registered passkey.");

      const salt = new Uint8Array(base64ToArrayBuffer(record.prf_salt));
      const encryptedMekData = JSON.parse(record.encrypted_mek);

      const prfOutput = await getPasskeyPrfOutput(record.credential_id, salt);
      const pdk = await derivePDK(prfOutput, record.credential_id);

      const mek = await decryptMEK(encryptedMekData.ciphertext, encryptedMekData.iv, pdk);
      rawMekBytes = mek;
      mekKey = await importMEK(mek);

      await decryptAndLoadVault();
      appState = "dashboard";
    } catch (err: any) {
      console.error(err);
      setupError = err.message || "WebAuthn authentication failed.";
    } finally {
      isUnlocking = false;
    }
  }

  async function handleUnlockWithRecoveryKey() {
    isUnlocking = true;
    setupError = "";
    try {
      const meta = await getRecoveryMetadata();
      if (!meta) throw new Error("Vault metadata is missing.");

      const salt = new Uint8Array(base64ToArrayBuffer(meta.recoverySalt));
      const encryptedMekData = JSON.parse(meta.encryptedMekWithRecovery);

      const recoveryDk = await deriveRecoveryDK(recoveryKeyInput, salt);
      const mek = await decryptMEK(encryptedMekData.ciphertext, encryptedMekData.iv, recoveryDk);

      rawMekBytes = mek;
      mekKey = await importMEK(mek);
      actualRecoveryKeyString = recoveryKeyInput.toUpperCase().replace(/[^A-Z0-9-]/gi, "");

      await decryptAndLoadVault();
      appState = "dashboard";
      recoveryKeyInput = "";
    } catch (err: any) {
      console.error(err);
      setupError = "Incorrect Recovery Key or corrupted data.";
    } finally {
      isUnlocking = false;
    }
  }

  async function decryptAndLoadVault() {
    if (!mekKey) return;
    const rawCreds = await loadCredentials();
    const list = [];
    for (const c of rawCreds) {
      list.push({
        id: c.id,
        title: await decryptField(c.title_encrypted, mekKey),
        url: await decryptField(c.url_encrypted, mekKey),
        username: await decryptField(c.username_encrypted, mekKey),
        password: await decryptField(c.password_encrypted, mekKey),
        notes: await decryptField(c.notes_encrypted, mekKey),
        createdAt: c.created_at,
        updatedAt: c.updated_at
      });
    }
    decryptedCredentials = list;
  }

  async function handleSaveCredential() {
    if (!mekKey) return;
    try {
      const id = editMode ? formId : crypto.randomUUID();
      const title_encrypted = await encryptField(formTitle.trim() || "Untitled Entry", mekKey);
      const url_encrypted = await encryptField(formUrl.trim(), mekKey);
      const username_encrypted = await encryptField(formUsername, mekKey);
      const password_encrypted = await encryptField(formPassword, mekKey);
      const notes_encrypted = await encryptField(formNotes, mekKey);
      const now = Date.now();

      const existing = decryptedCredentials.find(c => c.id === id);
      const created_at = existing ? existing.createdAt : now;

      const cred: DbCredential = {
        id,
        title_encrypted,
        url_encrypted,
        username_encrypted,
        password_encrypted,
        notes_encrypted,
        created_at,
        updated_at: now
      };

      await saveCredential(cred);
      await decryptAndLoadVault();
      showAddModal = false;
      clearForm();
      selectedCredentialId = id;
    } catch (e) {
      console.error("Error saving record:", e);
    }
  }

  async function handleDeleteCredential(id: string) {
    if (!confirm("Are you sure you want to permanently delete this credential?")) return;
    try {
      await deleteCredential(id);
      if (selectedCredentialId === id) {
        selectedCredentialId = null;
      }
      await decryptAndLoadVault();
    } catch (e) {
      console.error("Error deleting record:", e);
    }
  }

  function openEditModal(c: typeof decryptedCredentials[0]) {
    editMode = true;
    formId = c.id;
    formTitle = c.title;
    formUrl = c.url;
    formUsername = c.username;
    formPassword = c.password;
    formNotes = c.notes;
    showFormPassword = false;
    showAddModal = true;
  }

  function openAddModal() {
    editMode = false;
    clearForm();
    showFormPassword = false;
    showAddModal = true;
  }

  function clearForm() {
    formId = "";
    formTitle = "";
    formUrl = "";
    formUsername = "";
    formPassword = "";
    formNotes = "";
  }

  function generateSecurePassword() {
    const chars = "abcdefghijklmnopqrstuvwxyz";
    const caps = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const nums = "0123456789";
    const syms = "!@#$%&*?_=-+";
    
    const pool = chars + caps + nums + syms;
    const bytes = crypto.getRandomValues(new Uint8Array(20));
    let pwd = "";
    for (let i = 0; i < 20; i++) {
      pwd += pool[bytes[i] % pool.length];
    }
    formPassword = pwd;
  }

  async function handleAddBackupPasskey() {
    if (!rawMekBytes) return;
    isAddingPasskey = true;
    setupError = "";
    try {
      const reg = await registerPasskey(newPasskeyName.trim() || "Backup Passkey");
      if (!reg.prfEnabled) {
        throw new Error("This authenticator does not support the WebAuthn PRF extension.");
      }

      let prfOutput = reg.prfOutput;
      if (!prfOutput) {
        prfOutput = await getPasskeyPrfOutput(reg.credentialId, reg.prfSalt);
      }

      const pdk = await derivePDK(prfOutput, reg.credentialId);
      const encryptedMek = await encryptMEK(rawMekBytes, pdk);

      await savePasskey(
        reg.credentialId,
        newPasskeyName.trim() || "Backup Passkey",
        arrayBufferToBase64(reg.prfSalt.buffer as ArrayBuffer),
        JSON.stringify(encryptedMek)
      );

      passkeysList = await loadPasskeys();
      newPasskeyName = "";
    } catch (err: any) {
      console.error(err);
      setupError = err.message || "Failed to register backup passkey.";
    } finally {
      isAddingPasskey = false;
    }
  }

  async function handleDeletePasskey(id: string) {
    if (passkeysList.length <= 1) {
      alert("You cannot delete your only passkey. Please add a backup passkey first to avoid lockout.");
      return;
    }
    if (!confirm("Are you sure you want to delete this backup passkey? You will no longer be able to unlock your database with it.")) return;
    try {
      await deletePasskey(id);
      passkeysList = await loadPasskeys();
      if (selectedPasskeyId === id && passkeysList.length > 0) {
        selectedPasskeyId = passkeysList[0].credential_id;
      }
    } catch (e) {
      console.error("Error deleting passkey:", e);
    }
  }

  function copyText(text: string, id: string) {
    navigator.clipboard.writeText(text);
    copiedId = id;
    setTimeout(() => {
      if (copiedId === id) copiedId = null;
    }, 2000);
  }

  function copyPasswordText(text: string, id: string) {
    navigator.clipboard.writeText(text);
    copiedPasswordId = id;
    setTimeout(() => {
      if (copiedPasswordId === id) copiedPasswordId = null;
    }, 2000);
  }

  function copyRecoveryKeyText() {
    const key = generatedRecoveryKey || actualRecoveryKeyString;
    navigator.clipboard.writeText(key);
    copiedRecoveryKey = true;
    setTimeout(() => {
      copiedRecoveryKey = false;
    }, 2000);
  }

  function lockVault() {
    rawMekBytes = null;
    mekKey = null;
    decryptedCredentials = [];
    selectedCredentialId = null;
    mobileView = "list";
    showRecoveryForm = false;
    setupError = "";
    recoveryKeyInput = "";
    showSettings = false;
    
    loadPasskeys().then(list => {
      passkeysList = list;
      if (passkeysList.length > 0) {
        selectedPasskeyId = passkeysList[0].credential_id;
      }
      appState = "locked";
    });
  }
</script>

<main class="min-h-screen bg-background text-foreground flex flex-col font-sans relative">
  
  {#if appState !== "dashboard"}
    <div class="absolute top-4 right-4 z-50">
      <ThemeToggle />
    </div>
  {/if}

  <!-- LOADING STATE -->
  {#if appState === "loading"}
    <div class="flex-1 flex flex-col items-center justify-center space-y-4" in:fade>
      <div class="w-12 h-12 border-4 border-primary/30 border-t-primary rounded-full animate-spin"></div>
      <p class="text-muted-foreground font-medium tracking-wide">Securing database...</p>
    </div>

  <!-- SETUP STATE -->
  {:else if appState === "setup"}
    <div class="flex-1 flex items-center justify-center p-6" in:fade>
      <Card.Root class="max-w-md w-full shadow-2xl relative overflow-hidden">
        <Card.Header class="text-center space-y-4">
          <div class="mx-auto p-4 bg-primary/10 border border-primary/20 rounded-2xl text-primary w-fit">
            <Shield class="w-10 h-10" />
          </div>
          <Card.Title class="text-3xl font-extrabold tracking-tight">Aegis Vault</Card.Title>
          <Card.Description class="text-sm">
            Create a secure, zero-knowledge, local-first database protected directly by your device's biometric Passkey (via the WebAuthn PRF extension).
          </Card.Description>
        </Card.Header>

        <Card.Content class="space-y-6">
          {#if !prfSupported}
            <div class="flex gap-3 p-4 bg-destructive/10 border border-destructive/20 rounded-2xl text-left text-destructive text-xs leading-normal">
              <AlertTriangle class="w-5 h-5 shrink-0 text-destructive" />
              <div>
                <span class="font-semibold block mb-0.5">Warning: PRF Extension Not Detected</span>
                Your platform WebView2 may not support WebAuthn PRF. You can still try to register, but if it fails, make sure Windows Hello is configured.
              </div>
            </div>
          {/if}

          <div class="space-y-4">
            <div class="space-y-1.5 text-left">
              <Label for="passkey-name" class="text-xs font-semibold uppercase tracking-wider">Primary Passkey Name</Label>
              <Input 
                type="text" 
                id="passkey-name"
                class="w-full"
                bind:value={firstPasskeyName} 
                placeholder="e.g. My Windows Hello" 
              />
            </div>

            {#if setupError}
              <p class="text-destructive text-xs text-left bg-destructive/10 border border-destructive/20 p-3 rounded-xl leading-relaxed">
                {setupError}
              </p>
            {/if}

            <Button 
              class="w-full py-6 flex items-center justify-center gap-2"
              onclick={handleSetup}
            >
              <KeyRound class="w-5 h-5" />
              Initialize Vault with Passkey
            </Button>
          </div>
        </Card.Content>
      </Card.Root>
    </div>

  <!-- LOCKED STATE -->
  {:else if appState === "locked"}
    <div class="flex-1 flex items-center justify-center p-6" in:fade>
      <Card.Root class="max-w-md w-full shadow-2xl relative overflow-hidden">
        <Card.Header class="text-center space-y-4">
          <div class="mx-auto p-4 bg-primary/10 border border-primary/20 rounded-2xl text-primary w-fit">
            <Lock class="w-10 h-10" />
          </div>
          <Card.Title class="text-3xl font-extrabold tracking-tight">Vault Locked</Card.Title>
          <Card.Description class="text-sm">Unlock your vault using a registered Passkey or Recovery Key.</Card.Description>
        </Card.Header>

        <Card.Content class="space-y-6">
          {#if setupError}
            <p class="w-full text-destructive text-xs text-left bg-destructive/10 border border-destructive/20 p-3 rounded-xl leading-relaxed">
              {setupError}
            </p>
          {/if}

          <!-- Option 1: Passkey Unlock -->
          {#if passkeysList.length > 0}
            <div class="w-full space-y-4">
              <div class="space-y-1.5 text-left">
                <Label for="passkey-select" class="text-xs font-semibold uppercase tracking-wider">Select Passkey</Label>
                <div class="relative">
                  <select 
                    id="passkey-select"
                    class="w-full bg-background border border-input focus:ring-1 focus:ring-primary rounded-xl px-4 py-3 text-sm appearance-none transition" 
                    bind:value={selectedPasskeyId}
                  >
                    {#each passkeysList as pk}
                      <option value={pk.credential_id}>{pk.name}</option>
                    {/each}
                  </select>
                  <div class="absolute inset-y-0 right-0 flex items-center px-4 pointer-events-none text-muted-foreground">
                    <Key class="w-4 h-4" />
                  </div>
                </div>
              </div>

              <Button 
                class="w-full py-6 flex items-center justify-center gap-2"
                onclick={handleUnlockWithPasskey}
                disabled={isUnlocking}
              >
                {#if isUnlocking}
                  <RefreshCw class="w-5 h-5 animate-spin" />
                  Authenticating...
                {:else}
                  <Unlock class="w-5 h-5" />
                  Unlock with Passkey
                {/if}
              </Button>
            </div>
          {/if}

          {#if showRecoveryForm}
            <!-- Divider -->
            <div class="w-full flex items-center justify-center gap-3 py-2" in:slide>
              <Separator class="flex-1" />
              <span class="text-xs font-bold text-muted-foreground uppercase tracking-widest font-sans">Recovery Login</span>
              <Separator class="flex-1" />
            </div>

            <!-- Option 2: Recovery Key Unlock -->
            <div class="w-full space-y-4 text-left" in:slide>
              <div class="space-y-1.5">
                <Label for="recovery-input" class="text-xs font-semibold uppercase tracking-wider">Recovery Key</Label>
                <Input 
                  type="text" 
                  id="recovery-input"
                  class="text-center tracking-wider text-sm placeholder:tracking-normal placeholder:font-sans font-mono py-6"
                  bind:value={recoveryKeyInput} 
                  placeholder="VLT-XXXX-XXXX-XXXX..." 
                  disabled={isUnlocking}
                />
              </div>

              <Button 
                variant="outline"
                class="w-full py-6"
                onclick={handleUnlockWithRecoveryKey}
                disabled={isUnlocking || !recoveryKeyInput.trim()}
              >
                Unlock with Recovery Key
              </Button>

              <div class="w-full text-center">
                <Button 
                  variant="link" 
                  class="text-xs text-muted-foreground hover:text-primary p-0 h-auto"
                  onclick={() => showRecoveryForm = false}
                >
                  &larr; Back to Passkey Login
                </Button>
              </div>
            </div>
          {:else}
            <div class="w-full text-center" in:fade>
              <Button 
                variant="link" 
                class="text-xs text-muted-foreground hover:text-primary p-0 h-auto"
                onclick={() => showRecoveryForm = true}
              >
                Lost your passkey? Use recovery key
              </Button>
            </div>
          {/if}
        </Card.Content>
      </Card.Root>
    </div>

  <!-- DASHBOARD STATE -->
  {:else if appState === "dashboard"}
    <!-- Header -->
    <header class="bg-card px-6 py-4 flex items-center justify-between border-b border-border z-10">
      <div class="flex items-center gap-3">
        <div class="p-2 bg-primary/10 border border-primary/20 rounded-xl text-primary shadow-inner">
          <Shield class="w-6 h-6" />
        </div>
        <div class="flex items-center gap-2">
          <span class="text-lg font-bold tracking-wider">Aegis Vault</span>
          <Badge variant="secondary" class="text-[10px] py-0.5">Local Encrypted</Badge>
        </div>
      </div>

      <!-- Controls -->
      <div class="flex items-center gap-2">
        <ThemeToggle />
        <Button 
          variant="outline" 
          size="sm"
          class="flex items-center gap-2 text-xs font-semibold"
          onclick={() => showSettings = !showSettings}
        >
          <Settings class="w-4 h-4" />
          Settings
        </Button>
        <Button 
          variant="destructive" 
          size="sm"
          class="flex items-center gap-2 text-xs font-semibold"
          onclick={lockVault}
        >
          <LogOut class="w-4 h-4" />
          Lock Vault
        </Button>
      </div>
    </header>

    <!-- Main Workspace -->
    <div class="flex-1 flex relative overflow-hidden">

      {#if showSettings}
        <!-- SETTINGS PANEL -->
        <div class="flex-1 overflow-y-auto p-8 max-w-3xl mx-auto w-full space-y-8" in:fade>
          <div class="flex items-center justify-between border-b pb-4">
            <div class="space-y-1">
              <h2 class="text-2xl font-bold">Vault Settings</h2>
              <p class="text-xs text-muted-foreground">Manage your backup passkeys and view recovery items.</p>
            </div>
            <Button 
              variant="link"
              class="text-xs font-semibold text-primary"
              onclick={() => showSettings = false}
            >
              Back to Dashboard
            </Button>
          </div>

          <!-- Registered Passkeys -->
          <Card.Root>
            <Card.Header>
              <Card.Title class="text-md font-bold flex items-center gap-2">
                <Key class="w-5 h-5 text-primary" />
                Registered Passkeys ({passkeysList.length})
              </Card.Title>
              <Card.Description class="text-xs">
                Protect your vault with multiple passkeys. Any of these passkeys can be used to unlock the vault.
              </Card.Description>
            </Card.Header>
            <Card.Content class="space-y-4">
              <div class="divide-y border rounded-xl overflow-hidden bg-muted/40">
                {#each passkeysList as pk}
                  <div class="flex items-center justify-between p-4">
                    <div class="flex items-center gap-3">
                      <div class="p-2 bg-primary/10 rounded-lg text-primary border border-primary/5">
                        <Key class="w-4 h-4" />
                      </div>
                      <div>
                        <span class="text-sm font-semibold block">{pk.name}</span>
                        <span class="text-[10px] text-muted-foreground font-mono block select-all">{pk.credential_id.substring(0, 16)}...</span>
                      </div>
                    </div>
                    <Button 
                      variant="ghost"
                      size="icon"
                      onclick={() => handleDeletePasskey(pk.credential_id)}
                      disabled={passkeysList.length <= 1}
                      title="Delete Passkey"
                    >
                      <Trash2 class="w-4 h-4 text-destructive" />
                    </Button>
                  </div>
                {/each}
              </div>

              <!-- Add Backup Passkey Form -->
              <div class="pt-4 border-t flex flex-col md:flex-row gap-3">
                <div class="flex-1">
                  <Input 
                    type="text" 
                    placeholder="Backup Passkey Name (e.g., YubiKey)" 
                    bind:value={newPasskeyName}
                  />
                </div>
                <Button 
                  onclick={handleAddBackupPasskey}
                  disabled={isAddingPasskey}
                >
                  {#if isAddingPasskey}
                    <RefreshCw class="w-4 h-4 animate-spin" />
                    Registering...
                  {:else}
                    <Plus class="w-4 h-4 mr-2" />
                    Add Backup Passkey
                  {/if}
                </Button>
              </div>
              {#if setupError}
                <p class="text-destructive text-xs bg-destructive/10 border border-destructive/20 p-3 rounded-xl mt-2 leading-relaxed">
                  {setupError}
                </p>
              {/if}
            </Card.Content>
          </Card.Root>

          <!-- Emergency Recovery Key View -->
          <Card.Root>
            <Card.Header>
              <Card.Title class="text-md font-bold flex items-center gap-2">
                <AlertTriangle class="w-5 h-5 text-primary" />
                Emergency Recovery Key
              </Card.Title>
              <Card.Description class="text-xs">
                If you lose all registered passkeys, the recovery key is the only method to regain access.
              </Card.Description>
            </Card.Header>
            <Card.Content>
              <div class="bg-muted border rounded-xl p-4 flex items-center justify-between">
                {#if showRecoveryKeyReveal}
                  <code class="font-mono text-primary text-sm font-bold tracking-wider select-all">
                    {generatedRecoveryKey || actualRecoveryKeyString}
                  </code>
                {:else}
                  <span class="text-xs text-muted-foreground font-mono tracking-widest font-semibold">••••-••••-••••-••••-••••-••••-••••</span>
                {/if}

                <div class="flex items-center gap-2">
                  {#if showRecoveryKeyReveal}
                    <Button 
                      variant="outline"
                      size="icon"
                      onclick={copyRecoveryKeyText}
                    >
                      {#if copiedRecoveryKey}
                        <Check class="w-4 h-4 text-emerald-500" />
                      {:else}
                        <Copy class="w-4 h-4" />
                      {/if}
                    </Button>
                  {/if}
                  <Button 
                    variant="outline"
                    size="sm"
                    onclick={() => showRecoveryKeyReveal = !showRecoveryKeyReveal}
                  >
                    {#if showRecoveryKeyReveal}
                      <EyeOff class="w-3.5 h-3.5 mr-1.5" />
                      Hide Key
                    {:else}
                      <Eye class="w-3.5 h-3.5 mr-1.5" />
                      Reveal Key
                    {/if}
                  </Button>
                </div>
              </div>
            </Card.Content>
          </Card.Root>

          <!-- Database Location Card -->
          <Card.Root>
            <Card.Header>
              <Card.Title class="text-md font-bold flex items-center gap-2">
                <Database class="w-5 h-5 text-primary" />
                Database Location
              </Card.Title>
              <Card.Description class="text-xs">
                Physical path to your encrypted SQLite database file on this device.
              </Card.Description>
            </Card.Header>
            <Card.Content>
              <div class="bg-muted/40 border rounded-xl p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <code class="font-mono text-xs select-all text-muted-foreground break-all leading-relaxed flex-1">
                  {dbPath || "Resolving database path..."}
                </code>
                {#if dbPath}
                  <Button 
                    variant="outline"
                    size="sm"
                    class="shrink-0 font-semibold"
                    onclick={() => copyText(dbPath, "dbpath")}
                  >
                    {#if copiedId === "dbpath"}
                      <Check class="w-4 h-4 text-emerald-500 mr-2" />
                      Copied
                    {:else}
                      <Copy class="w-4 h-4 mr-2" />
                      Copy Path
                    {/if}
                  </Button>
                {/if}
              </div>
            </Card.Content>
          </Card.Root>
        </div>

      {:else}
        <!-- CREDENTIALS WORKSPACE -->
        <!-- Left Panel: Sidebar Filters (Desktop Only) -->
        <aside class="hidden md:flex w-64 bg-card border-r flex-col p-4 space-y-6">
          <Button 
            class="w-full py-6 flex items-center justify-center gap-2"
            onclick={openAddModal}
          >
            <Plus class="w-4 h-4" />
            New Password
          </Button>

          <div class="space-y-1">
            <span class="text-[10px] font-bold text-muted-foreground uppercase tracking-widest px-3 block mb-2">Categories</span>
            
            <Button 
              variant={activeCategory === 'all' ? 'secondary' : 'ghost'}
              class="w-full justify-between px-3 py-6"
              onclick={() => activeCategory = "all"}
            >
              <div class="flex items-center gap-2.5 text-xs font-semibold">
                <Shield class="w-4 h-4" />
                All Accounts
              </div>
              <Badge variant="outline" class="text-[10px]">
                {decryptedCredentials.length}
              </Badge>
            </Button>

            <Button 
              variant={activeCategory === 'login' ? 'secondary' : 'ghost'}
              class="w-full justify-between px-3 py-6"
              onclick={() => activeCategory = "login"}
            >
              <div class="flex items-center gap-2.5 text-xs font-semibold">
                <Globe class="w-4 h-4" />
                Websites / Logins
              </div>
              <Badge variant="outline" class="text-[10px]">
                {decryptedCredentials.filter(c => c.url.trim() !== "").length}
              </Badge>
            </Button>

            <Button 
              variant={activeCategory === 'note' ? 'secondary' : 'ghost'}
              class="w-full justify-between px-3 py-6"
              onclick={() => activeCategory = "note"}
            >
              <div class="flex items-center gap-2.5 text-xs font-semibold">
                <FileText class="w-4 h-4" />
                Secure Notes
              </div>
              <Badge variant="outline" class="text-[10px]">
                {decryptedCredentials.filter(c => c.url.trim() === "" && c.password.trim() === "").length}
              </Badge>
            </Button>
          </div>
        </aside>

        <!-- Middle Panel: Credentials List -->
        <section class="w-full md:w-80 border-r flex flex-col {selectedCredentialId && mobileView === 'detail' ? 'hidden md:flex' : 'flex'}">
          <!-- Search -->
          <div class="p-4 border-b bg-card flex items-center gap-2">
            <div class="relative flex-1">
              <Input 
                type="text" 
                class="w-full pl-9" 
                placeholder="Search passwords..." 
                bind:value={searchQuery}
              />
              <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-muted-foreground">
                <Search class="w-4 h-4" />
              </div>
            </div>
            
            <!-- Mobile New Password FAB/Button -->
            <Button 
              size="icon" 
              class="md:hidden"
              onclick={openAddModal}
              title="New Password"
            >
              <Plus class="w-4 h-4" />
            </Button>
          </div>

          <!-- Mobile Categories Horizontal Scroll -->
          <div class="md:hidden flex gap-2 p-3 overflow-x-auto border-b bg-muted/20 shrink-0">
            <Button 
              variant={activeCategory === 'all' ? 'secondary' : 'ghost'} 
              size="sm"
              class="h-8 text-[11px] font-semibold"
              onclick={() => activeCategory = "all"}
            >
              All ({decryptedCredentials.length})
            </Button>
            <Button 
              variant={activeCategory === 'login' ? 'secondary' : 'ghost'} 
              size="sm"
              class="h-8 text-[11px] font-semibold"
              onclick={() => activeCategory = "login"}
            >
              Logins ({decryptedCredentials.filter(c => c.url.trim() !== "").length})
            </Button>
            <Button 
              variant={activeCategory === 'note' ? 'secondary' : 'ghost'} 
              size="sm"
              class="h-8 text-[11px] font-semibold"
              onclick={() => activeCategory = "note"}
            >
              Notes ({decryptedCredentials.filter(c => c.url.trim() === "" && c.password.trim() === "").length})
            </Button>
          </div>

          <!-- Entries list -->
          <div class="flex-1 overflow-y-auto divide-y">
            {#if filteredCredentials.length === 0}
              <div class="p-8 text-center text-muted-foreground text-xs">
                No credentials found.
              </div>
            {:else}
              {#each filteredCredentials as c}
                <button 
                  class="w-full text-left p-4 transition border-l-2 flex flex-col gap-1 {selectedCredentialId === c.id ? 'bg-primary/5 border-primary' : 'hover:bg-muted/30 border-transparent'}"
                  onclick={() => {
                    selectedCredentialId = c.id;
                    mobileView = "detail";
                  }}
                >
                  <span class="text-xs font-bold truncate">{c.title}</span>
                  <span class="text-[10px] text-muted-foreground truncate">{c.username || 'No Username'}</span>
                  {#if c.url}
                    <span class="text-[9px] text-muted-foreground truncate flex items-center gap-1 font-mono">
                      <Globe class="w-2.5 h-2.5 text-primary/70" />
                      {c.url}
                    </span>
                  {/if}
                </button>
              {/each}
            {/if}
          </div>
        </section>

        <!-- Right Panel: Entry Details -->
        <section class="flex-1 bg-muted/20 p-4 md:p-8 overflow-y-auto {!selectedCredentialId || mobileView === 'list' ? 'hidden md:block' : 'block'}">
          {#if selectedCredential}
            <div class="max-w-2xl mx-auto space-y-6" in:fade>
              
              <!-- Mobile Back Button -->
              <Button 
                variant="ghost" 
                size="sm" 
                class="md:hidden flex items-center gap-1.5 mb-2 pl-0 hover:bg-transparent"
                onclick={() => mobileView = "list"}
              >
                &larr; Back to List
              </Button>

              <!-- Header details -->
              <div class="flex items-start justify-between border-b pb-5">
                <div class="space-y-2">
                  <h2 class="text-2xl font-bold">{selectedCredential.title}</h2>
                  {#if selectedCredential.url}
                    <a 
                      href={selectedCredential.url.startsWith("http") ? selectedCredential.url : `https://${selectedCredential.url}`} 
                      target="_blank" 
                      rel="noopener noreferrer" 
                      class="text-xs text-primary hover:underline font-medium inline-flex items-center gap-1"
                    >
                      <Globe class="w-3.5 h-3.5" />
                      {selectedCredential.url}
                      <ExternalLink class="w-3 h-3" />
                    </a>
                  {:else}
                    <Badge variant="secondary" class="text-[10px] font-bold tracking-wider">SECURE NOTE</Badge>
                  {/if}
                </div>

                <div class="flex items-center gap-2">
                  <Button 
                    variant="outline"
                    size="icon"
                    onclick={() => selectedCredential && openEditModal(selectedCredential)}
                    title="Edit Record"
                  >
                    <Edit3 class="w-4.5 h-4.5" />
                  </Button>
                  <Button 
                    variant="outline"
                    size="icon"
                    onclick={() => selectedCredential && handleDeleteCredential(selectedCredential.id)}
                    title="Delete Record"
                  >
                    <Trash2 class="w-4.5 h-4.5 text-destructive" />
                  </Button>
                </div>
              </div>

              <!-- Information Grid -->
              <div class="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
                <!-- Username field -->
                {#if selectedCredential.username}
                  <div class="border rounded-2xl p-4.5 space-y-1.5 bg-card">
                    <span class="text-[9px] font-bold text-muted-foreground uppercase tracking-widest block">Username</span>
                    <div class="flex items-center justify-between gap-3">
                      <span class="text-xs font-semibold select-all truncate">{selectedCredential.username}</span>
                      <Button 
                        variant="outline"
                        size="icon"
                        class="h-8 w-8"
                        onclick={() => selectedCredential && copyText(selectedCredential.username, "uname")}
                      >
                        {#if copiedId === "uname"}
                          <Check class="w-3.5 h-3.5 text-emerald-500" />
                        {:else}
                          <Copy class="w-3.5 h-3.5" />
                        {/if}
                      </Button>
                    </div>
                  </div>
                {/if}

                <!-- Password field -->
                {#if selectedCredential.password}
                  <div class="border rounded-2xl p-4.5 space-y-1.5 bg-card">
                    <span class="text-[9px] font-bold text-muted-foreground uppercase tracking-widest block">Password</span>
                    <div class="flex items-center justify-between gap-3">
                      {#if copiedPasswordId === "pwd"}
                        <span class="text-xs text-emerald-600 dark:text-emerald-500 font-semibold">Copied!</span>
                      {:else}
                        <span class="text-xs font-mono select-all truncate tracking-wide">••••••••••••••••</span>
                      {/if}
                      <Button 
                        variant="outline"
                        size="icon"
                        class="h-8 w-8"
                        onclick={() => selectedCredential && copyPasswordText(selectedCredential.password, "pwd")}
                      >
                        <Copy class="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  </div>
                {/if}
              </div>

              <!-- Notes field -->
              {#if selectedCredential.notes}
                <div class="border rounded-2xl p-5 space-y-2 bg-card">
                  <span class="text-[9px] font-bold text-muted-foreground uppercase tracking-widest block">Secure Notes</span>
                  <pre class="text-xs text-muted-foreground font-sans whitespace-pre-wrap leading-relaxed select-text">{selectedCredential.notes}</pre>
                </div>
              {/if}

              <!-- Date details -->
              <div class="text-[10px] text-muted-foreground flex items-center justify-between pt-4 border-t font-mono">
                <span>Created: {new Date(selectedCredential.createdAt).toLocaleString()}</span>
                <span>Updated: {new Date(selectedCredential.updatedAt).toLocaleString()}</span>
              </div>

            </div>
          {:else}
            <!-- Placeholder -->
            <div class="h-full flex flex-col items-center justify-center text-center space-y-3" in:fade>
              <div class="p-4 bg-muted border rounded-2xl text-muted-foreground">
                <Lock class="w-8 h-8" />
              </div>
              <p class="text-muted-foreground text-xs">Select a credential to view encrypted details.</p>
            </div>
          {/if}
        </section>
      {/if}

    </div>
  {/if}

  <!-- ADD / EDIT CREDENTIAL MODAL -->
  <Dialog.Root bind:open={showAddModal}>
    <Dialog.Content class="sm:max-w-[425px]">
      <Dialog.Header>
        <Dialog.Title>{editMode ? "Edit Password Record" : "Add Password Record"}</Dialog.Title>
        <Dialog.Description>
          Enter the details to encrypt and save inside your SQLite database.
        </Dialog.Description>
      </Dialog.Header>

      <div class="space-y-4 py-4">
        <!-- Title -->
        <div class="space-y-1.5">
          <Label for="form-title" class="text-xs font-semibold uppercase tracking-wider">Title</Label>
          <Input 
            type="text" 
            id="form-title"
            placeholder="e.g. Google Account"
            bind:value={formTitle}
          />
        </div>

        <!-- URL -->
        <div class="space-y-1.5">
          <Label for="form-url" class="text-xs font-semibold uppercase tracking-wider">Website URL (Optional)</Label>
          <Input 
            type="text" 
            id="form-url"
            placeholder="e.g. accounts.google.com"
            bind:value={formUrl}
          />
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <!-- Username -->
          <div class="space-y-1.5">
            <Label for="form-username" class="text-xs font-semibold uppercase tracking-wider">Username</Label>
            <Input 
              type="text" 
              id="form-username"
              placeholder="e.g. user@gmail.com"
              bind:value={formUsername}
            />
          </div>

          <!-- Password -->
          <div class="space-y-1.5">
            <div class="flex items-center justify-between">
              <Label for="form-password" class="text-xs font-semibold uppercase tracking-wider">Password</Label>
              <Button 
                variant="link"
                class="h-auto p-0 text-[10px] font-bold text-primary"
                onclick={generateSecurePassword}
              >
                Generate
              </Button>
            </div>
            <div class="relative">
              <Input 
                type={showFormPassword ? "text" : "password"} 
                id="form-password"
                class="pr-10 font-mono tracking-wider"
                placeholder="Password"
                bind:value={formPassword}
              />
              <Button 
                variant="ghost"
                size="icon"
                class="absolute inset-y-0 right-0 h-full text-muted-foreground hover:bg-transparent"
                onclick={() => showFormPassword = !showFormPassword}
              >
                {#if showFormPassword}
                  <EyeOff class="w-4 h-4" />
                {:else}
                  <Eye class="w-4 h-4" />
                {/if}
              </Button>
            </div>
          </div>
        </div>

        <!-- Notes -->
        <div class="space-y-1.5">
          <Label for="form-notes" class="text-xs font-semibold uppercase tracking-wider">Notes / Extra Info</Label>
          <Textarea 
            id="form-notes"
            rows={3}
            placeholder="e.g. Security questions or recovery codes..."
            bind:value={formNotes}
          />
        </div>
      </div>

      <Dialog.Footer>
        <Button variant="outline" onclick={() => showAddModal = false}>Cancel</Button>
        <Button onclick={handleSaveCredential}>Save Record</Button>
      </Dialog.Footer>
    </Dialog.Content>
  </Dialog.Root>

</main>
