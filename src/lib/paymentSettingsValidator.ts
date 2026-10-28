import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function resolveProjectRootDir(moduleDir: string = __dirname): string {
  if (
    path.basename(moduleDir) === 'lib' &&
    path.basename(path.dirname(moduleDir)) === 'src'
  ) {
    return path.resolve(moduleDir, '..', '..');
  }
  return path.resolve(moduleDir);
}

export const PROJECT_ROOT_DIR = resolveProjectRootDir(__dirname);

export function resolveDefaultPaymentSettingsPath(
  env?: NodeJS.ProcessEnv,
  moduleDir: string = __dirname
): string {
  const processEnv = env || process.env;
  const customPath = (processEnv.PX_PAYMENT_SETTINGS_PATH || '').trim();
  if (customPath) {
    return path.resolve(customPath);
  }
  return path.resolve(
    resolveProjectRootDir(moduleDir),
    'data',
    'payment-settings.json'
  );
}

export type PaymentEnvironment = 'sandbox' | 'production';

export interface PersistedPaymentSettings {
  environment: PaymentEnvironment;
  public_key: string;
  pix_enabled: boolean;
  pix_instant_enabled: boolean;
  credit_card_enabled: boolean;
  boleto_enabled: boolean;
  updated_at?: string;
  updated_by?: string;
  updated_by_role?: string;
}

export interface CanonicalPaymentConfigResponse {
  configured: boolean;
  is_connected: boolean;
  environment: PaymentEnvironment;
  effective_environment: PaymentEnvironment;
  environment_warning: string | null;
  public_key: string;
  pix_enabled: boolean;
  pix_instant_enabled: boolean;
  credit_card_enabled: boolean;
  boleto_enabled: boolean;
  updated_at: string | null;
  updated_by: string | null;
}

export interface PaymentSettingsValidationResult {
  valid: boolean;
  statusCode: number;
  error?: string;
  code?: string;
  sanitized?: Omit<PersistedPaymentSettings, 'updated_at' | 'updated_by' | 'updated_by_role'>;
}

export const DEFAULT_PAYMENT_SETTINGS_PATH = resolveDefaultPaymentSettingsPath();

export const ALLOWED_PAYMENT_ADMIN_ROLES = ['ADMIN', 'SUPER_ADMIN'] as const;

export function isServerAccessTokenConfigured(rawAccessToken?: string): boolean {
  if (!rawAccessToken || typeof rawAccessToken !== 'string') return false;
  const trimmed = rawAccessToken.trim();
  if (!trimmed) return false;
  if (trimmed.includes('placeholder') || trimmed.includes('****')) return false;
  return true;
}

export function isServerSupabaseSecretConfigured(env?: NodeJS.ProcessEnv): boolean {
  const processEnv = env || process.env;
  const rawSecret = (
    processEnv.SUPABASE_SECRET_KEY ||
    processEnv.SUPABASE_SERVICE_ROLE_KEY ||
    ''
  ).trim();
  if (!rawSecret) return false;
  if (
    rawSecret === 'dummy_secret_for_initialization' ||
    rawSecret.includes('placeholder') ||
    rawSecret.includes('your-')
  ) {
    return false;
  }
  return true;
}

export interface OperationalEnvironmentInfo {
  isCompiledBuild: boolean;
  isPublicOrProductionSecurityGate: boolean;
  isProductionSecurity: boolean;
  paymentStage: PaymentEnvironment;
  pxEnvironment: string;
}

export function resolveOperationalEnvironment(env?: NodeJS.ProcessEnv): OperationalEnvironmentInfo {
  const processEnv = env || process.env;
  const nodeEnv = String(processEnv.NODE_ENV || '').trim().toLowerCase();
  const pxEnv = String(processEnv.PX_ENVIRONMENT || '').trim().toLowerCase();

  const isCompiledBuild = nodeEnv === 'production';
  const isPublicOrProductionSecurityGate = pxEnv === 'production' || nodeEnv === 'production';

  let paymentStage: PaymentEnvironment = 'sandbox';
  if (pxEnv === 'sandbox' || pxEnv === 'staging' || pxEnv === 'development' || pxEnv === 'test') {
    paymentStage = 'sandbox';
  } else if (pxEnv === 'production' || nodeEnv === 'production') {
    paymentStage = 'production';
  }

  return {
    isCompiledBuild,
    isPublicOrProductionSecurityGate,
    isProductionSecurity: isPublicOrProductionSecurityGate,
    paymentStage,
    pxEnvironment: pxEnv || nodeEnv || 'development',
  };
}

export function getDefaultPaymentSettings(env?: NodeJS.ProcessEnv): PersistedPaymentSettings {
  const processEnv = env || process.env;
  const opEnv = resolveOperationalEnvironment(processEnv);
  const defaultPublicKey = (processEnv.MP_PUBLIC_KEY || processEnv.VITE_MP_PUBLIC_KEY || '').trim();

  return {
    environment: opEnv.paymentStage,
    public_key: defaultPublicKey,
    pix_enabled: true,
    pix_instant_enabled: true,
    credit_card_enabled: false,
    boleto_enabled: false,
  };
}

export function validatePaymentSettingsPayload(
  payload: unknown,
  serverSecrets?: { mpAccessToken?: string; mpWebhookSecret?: string; normalizeLegacyUnimplementedMethods?: boolean }
): PaymentSettingsValidationResult {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return {
      valid: false,
      statusCode: 400,
      error: 'Payload de configuração de pagamento inválido ou malformado.',
      code: 'INVALID_PAYLOAD',
    };
  }

  const body = payload as Record<string, unknown>;

  const forbiddenSecretFields = [
    'access_token',
    'webhook_secret',
    'mp_access_token',
    'mp_webhook_secret',
    'client_secret',
    'mp_client_secret',
  ];

  for (const field of forbiddenSecretFields) {
    const val = body[field];
    if (val !== undefined && val !== null && String(val).trim() !== '') {
      return {
        valid: false,
        statusCode: 400,
        error:
          'Operação bloqueada por segurança: Credenciais privadas nunca devem ser enviadas pelo frontend.',
        code: 'SECRET_IN_PAYLOAD_FORBIDDEN',
      };
    }
  }

  const environment = body.environment;
  if (environment !== 'sandbox' && environment !== 'production') {
    return {
      valid: false,
      statusCode: 400,
      error: 'Ambiente inválido. Os valores permitidos são estritamente "sandbox" ou "production".',
      code: 'INVALID_ENVIRONMENT',
    };
  }

  if (typeof body.public_key !== 'string') {
    return {
      valid: false,
      statusCode: 400,
      error: 'O campo public_key deve ser uma string.',
      code: 'INVALID_PUBLIC_KEY_TYPE',
    };
  }

  const publicKey = body.public_key.trim();
  if (publicKey.length > 256) {
    return {
      valid: false,
      statusCode: 400,
      error: 'Chave pública excede o tamanho máximo permitido (256 caracteres).',
      code: 'PUBLIC_KEY_TOO_LONG',
    };
  }

  if (publicKey !== '') {
    const mpPublicKeyPattern = /^(APP_USR|TEST)-[a-zA-Z0-9-]{8,240}$/;
    if (!mpPublicKeyPattern.test(publicKey)) {
      return {
        valid: false,
        statusCode: 400,
        error: 'Formato de Chave Pública inválido.',
        code: 'INVALID_PUBLIC_KEY_FORMAT',
      };
    }
  }

  if (
    typeof body.pix_enabled !== 'boolean' ||
    typeof body.credit_card_enabled !== 'boolean' ||
    typeof body.boleto_enabled !== 'boolean'
  ) {
    return {
      valid: false,
      statusCode: 400,
      error: 'Os campos de pagamento devem ser estritamente booleanos.',
      code: 'INVALID_PAYMENT_METHODS_TYPE',
    };
  }

  const pixEnabled = body.pix_enabled;
  const rawCreditCardEnabled = body.credit_card_enabled;
  const rawBoletoEnabled = body.boleto_enabled;

  // Boleto continua bloqueado; Cartão de Crédito está liberado
  if (!serverSecrets?.normalizeLegacyUnimplementedMethods && rawBoletoEnabled) {
    return {
      valid: false,
      statusCode: 400,
      error: 'Operação bloqueada: Boleto Bancário ainda não possui fluxo homologado.',
      code: 'PAYMENT_METHOD_NOT_IMPLEMENTED',
    };
  }

  const creditCardEnabled = Boolean(rawCreditCardEnabled);
  const boletoEnabled = false;
  const pixInstantEnabled =
    typeof body.pix_instant_enabled === 'boolean' ? body.pix_instant_enabled : pixEnabled;

  if (!pixEnabled) {
    return {
      valid: false,
      statusCode: 400,
      error: 'O método Pix deve permanecer habilitado.',
      code: 'NO_PAYMENT_METHOD_ENABLED',
    };
  }

  return {
    valid: true,
    statusCode: 200,
    sanitized: {
      environment,
      public_key: publicKey,
      pix_enabled: pixEnabled,
      pix_instant_enabled: pixInstantEnabled,
      credit_card_enabled: creditCardEnabled,
      boleto_enabled: boletoEnabled,
    },
  };
}

export type PaymentSettingsResolutionSource =
  | 'default_missing_file'
  | 'persisted_file'
  | 'persisted_durable_audit'
  | 'corrupted_or_unreadable'
  | 'durable_store_unavailable';

export interface PaymentSettingsInspectionResult {
  ok: boolean;
  source: PaymentSettingsResolutionSource;
  settings: PersistedPaymentSettings | null;
  statusCode: number;
  error?: string;
  code?: string;
}

export function inspectPersistedPaymentSettings(
  filePath: string = DEFAULT_PAYMENT_SETTINGS_PATH,
  env?: NodeJS.ProcessEnv
): PaymentSettingsInspectionResult {
  const defaults = getDefaultPaymentSettings(env);

  try {
    const stat = fs.statSync(filePath);
    if (stat.isDirectory()) {
      return {
        ok: false,
        source: 'corrupted_or_unreadable',
        settings: null,
        statusCode: 503,
        error: 'Caminho inválido.',
        code: 'PAYMENT_SETTINGS_CORRUPTED',
      };
    }
  } catch (statErr: any) {
    if (statErr && statErr.code === 'ENOENT') {
      return {
        ok: true,
        source: 'default_missing_file',
        settings: defaults,
        statusCode: 200,
      };
    }
    return {
      ok: false,
      source: 'corrupted_or_unreadable',
      settings: null,
      statusCode: 503,
      error: 'Configurações inacessíveis.',
      code: 'PAYMENT_SETTINGS_UNREADABLE',
    };
  }

  try {
    const raw = fs.readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(raw);
    const validation = validatePaymentSettingsPayload(parsed, {
      mpAccessToken: (env || process.env).MP_ACCESS_TOKEN,
      mpWebhookSecret: (env || process.env).MP_WEBHOOK_SECRET,
      normalizeLegacyUnimplementedMethods: true,
    });

    if (!validation.valid || !validation.sanitized) {
      return {
        ok: false,
        source: 'corrupted_or_unreadable',
        settings: null,
        statusCode: 503,
        error: validation.error || 'Dados inválidos.',
        code: 'PAYMENT_SETTINGS_CORRUPTED',
      };
    }

    return {
      ok: true,
      source: 'persisted_file',
      statusCode: 200,
      settings: {
        ...validation.sanitized,
        credit_card_enabled: Boolean(validation.sanitized.credit_card_enabled), // <-- Permitir estado real
        boleto_enabled: false,
        public_key: validation.sanitized.public_key || defaults.public_key,
        updated_at: typeof parsed.updated_at === 'string' ? parsed.updated_at : undefined,
        updated_by: typeof parsed.updated_by === 'string' ? parsed.updated_by : undefined,
        updated_by_role: typeof parsed.updated_by_role === 'string' ? parsed.updated_by_role : undefined,
      },
    };
  } catch (err) {
    return {
      ok: false,
      source: 'corrupted_or_unreadable',
      settings: null,
      statusCode: 503,
      error: 'Arquivo corrompido.',
      code: 'PAYMENT_SETTINGS_CORRUPTED',
    };
  }
}

export function readPersistedPaymentSettings(
  filePath: string = DEFAULT_PAYMENT_SETTINGS_PATH,
  env?: NodeJS.ProcessEnv
): PersistedPaymentSettings {
  const inspection = inspectPersistedPaymentSettings(filePath, env);
  if (!inspection.ok || !inspection.settings) {
    const err = new Error(inspection.error || 'Configurações indisponíveis.');
    (err as any).code = inspection.code || 'PAYMENT_SETTINGS_CORRUPTED';
    (err as any).statusCode = inspection.statusCode || 503;
    throw err;
  }
  return inspection.settings;
}

export function writePersistedPaymentSettings(
  settings: PersistedPaymentSettings,
  filePath: string = DEFAULT_PAYMENT_SETTINGS_PATH
): PersistedPaymentSettings {
  const validation = validatePaymentSettingsPayload(settings);
  if (!validation.valid || !validation.sanitized) {
    throw new Error(validation.error || 'Configuração inválida.');
  }

  const recordToPersist: PersistedPaymentSettings = {
    environment: validation.sanitized.environment,
    public_key: validation.sanitized.public_key,
    pix_enabled: validation.sanitized.pix_enabled,
    pix_instant_enabled: validation.sanitized.pix_instant_enabled,
    credit_card_enabled: validation.sanitized.credit_card_enabled, // <-- Salvar estado real
    boleto_enabled: false,
    updated_at: settings.updated_at || new Date().toISOString(),
    updated_by: settings.updated_by,
    updated_by_role: settings.updated_by_role,
  };

  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const tempFilePath = `${filePath}.tmp.${process.pid}.${Date.now()}`;
  try {
    fs.writeFileSync(tempFilePath, JSON.stringify(recordToPersist, null, 2), 'utf-8');
    fs.renameSync(tempFilePath, filePath);
  } catch (writeErr) {
    try {
      if (fs.existsSync(tempFilePath)) {
        fs.unlinkSync(tempFilePath);
      }
    } catch {}
    throw writeErr;
  }

  return recordToPersist;
}

export function buildCanonicalPaymentConfigResponse(
  persisted: PersistedPaymentSettings,
  env?: NodeJS.ProcessEnv
): CanonicalPaymentConfigResponse {
  const processEnv = env || process.env;
  const rawAccessToken = (processEnv.MP_ACCESS_TOKEN || '').trim();
  const configured = isServerAccessTokenConfigured(rawAccessToken);
  const isTestAccessToken = configured && rawAccessToken.startsWith('TEST-');
  const pxEnv = String(processEnv.PX_ENVIRONMENT || '').trim().toLowerCase();
  const isLockedSandboxStage = pxEnv === 'sandbox' || pxEnv === 'staging';

  const envPublicKey = (processEnv.MP_PUBLIC_KEY || processEnv.VITE_MP_PUBLIC_KEY || '').trim();
  const effectivePublicKey = persisted.public_key || envPublicKey;

  const effectiveEnvironment: PaymentEnvironment =
    configured &&
    persisted.environment === 'production' &&
    !isLockedSandboxStage &&
    !isTestAccessToken
      ? 'production'
      : 'sandbox';

  let environmentWarning: string | null = null;
  if (persisted.environment === 'production' && !configured) {
    environmentWarning = 'Preferência definida para Produção Real, mas MP_ACCESS_TOKEN ausente.';
  }

  return {
    configured,
    is_connected: configured,
    environment: persisted.environment,
    effective_environment: effectiveEnvironment,
    environment_warning: environmentWarning,
    public_key: effectivePublicKey,
    pix_enabled: Boolean(persisted.pix_enabled),
    pix_instant_enabled: Boolean(persisted.pix_instant_enabled),
    credit_card_enabled: Boolean(persisted.credit_card_enabled), // <-- Retornar estado real ao frontend
    boleto_enabled: false,
    updated_at: persisted.updated_at || null,
    updated_by: persisted.updated_by || null,
  };
}

export function isPaymentMethodAllowedByConfig(
  paymentMethod: string | undefined,
  config: Pick<PersistedPaymentSettings, 'pix_enabled' | 'credit_card_enabled' | 'boleto_enabled'>
): { allowed: boolean; error?: string } {
  const normalized = (paymentMethod || 'pix').trim().toLowerCase();

  if (normalized === 'pix') {
    if (!config.pix_enabled) {
      return { allowed: false, error: 'Pix desabilitado.' };
    }
    return { allowed: true };
  }

  if (normalized === 'credit_card') {
    if (!config.credit_card_enabled) {
      return { allowed: false, error: 'Cartão de Crédito desabilitado.' };
    }
    return { allowed: true };
  }

  if (normalized === 'boleto') {
    if (!config.boleto_enabled) {
      return { allowed: false, error: 'Boleto desabilitado.' };
    }
    return { allowed: true };
  }

  return { allowed: false, error: 'Método de pagamento inválido.' };
}

export interface AuthoritativePaymentSettingsResolution {
  ok: boolean;
  source: string;
  settings: PersistedPaymentSettings | null;
  statusCode: number;
  error?: string;
  code?: string;
}

export async function resolveAuthoritativePaymentSettings(options?: {
  filePath?: string;
  supabaseClient?: any;
  env?: NodeJS.ProcessEnv;
  requireDurableSync?: boolean;
}): Promise<AuthoritativePaymentSettingsResolution> {
  const filePath = options?.filePath || DEFAULT_PAYMENT_SETTINGS_PATH;
  const env = options?.env || process.env;
  const supabaseClient = options?.supabaseClient;
  const requireDurableSync = Boolean(options?.requireDurableSync);

  const localInspection = inspectPersistedPaymentSettings(filePath, env);
  if (!localInspection.ok || !localInspection.settings) {
    return {
      ok: false,
      source: 'corrupted_or_unreadable',
      settings: null,
      statusCode: localInspection.statusCode || 503,
      error: localInspection.error || 'Erro nas configurações.',
      code: localInspection.code || 'PAYMENT_SETTINGS_CORRUPTED',
    };
  }

  if (supabaseClient || requireDurableSync) {
    if (!supabaseClient) {
      return {
        ok: false,
        source: 'supabase_unavailable',
        settings: null,
        statusCode: 503,
        error: 'Armazenamento durável indisponível.',
        code: 'PAYMENT_SETTINGS_UNAVAILABLE',
      };
    }

    let rows: any[] | null = null;
    try {
      const queryBuilder = supabaseClient
        .from('audit_logs')
        .select('id, actor_id, action, entity, entity_id, details, created_at')
        .eq('action', 'UPDATE_PAYMENT_SETTINGS')
        .eq('entity', 'payment_settings')
        .eq('entity_id', 'mercado_pago');

      const queryResponse =
        typeof queryBuilder.order === 'function'
          ? await queryBuilder.order('created_at', { ascending: false }).limit(1)
          : await queryBuilder;

      rows = Array.isArray(queryResponse?.data) ? queryResponse.data : queryResponse?.data ? [queryResponse.data] : [];
    } catch {
      // Ignora erro de BD temporário e usa cache local
    }

    if (rows && rows.length > 0) {
      const latestRecord = rows[0];
      const rawNewConfig = latestRecord?.details?.new_config;
      const validation = validatePaymentSettingsPayload(rawNewConfig, {
        mpAccessToken: env.MP_ACCESS_TOKEN,
        mpWebhookSecret: env.MP_WEBHOOK_SECRET,
        normalizeLegacyUnimplementedMethods: true,
      });

      if (validation.valid && validation.sanitized) {
        const defaults = getDefaultPaymentSettings(env);
        const durableSettings: PersistedPaymentSettings = {
          ...validation.sanitized,
          credit_card_enabled: Boolean(validation.sanitized.credit_card_enabled), // <-- Permitir estado real nas configurações duráveis
          boleto_enabled: false,
          public_key: validation.sanitized.public_key || defaults.public_key,
          updated_at: latestRecord?.details?.updated_at || latestRecord?.created_at,
          updated_by: latestRecord?.actor_id,
          updated_by_role: latestRecord?.details?.actor_role,
        };
        return {
          ok: true,
          source: 'persisted_durable_audit',
          settings: durableSettings,
          statusCode: 200,
        };
      }
    }
  }

  return {
    ok: true,
    source: localInspection.source,
    settings: localInspection.settings,
    statusCode: 200,
  };
}

export async function evaluateCheckoutPaymentMethodGate(params: {
  paymentMethod?: string;
  filePath?: string;
  supabaseClient?: any;
  env?: NodeJS.ProcessEnv;
  requireDurableSync?: boolean;
}) {
  const resolution = await resolveAuthoritativePaymentSettings(params);
  if (!resolution.ok || !resolution.settings) {
    return { allowed: false, statusCode: 503, error: 'Serviço indisponível.' };
  }
  const allowance = isPaymentMethodAllowedByConfig(params.paymentMethod, resolution.settings);
  return { allowed: allowance.allowed, statusCode: allowance.allowed ? 200 : 400, error: allowance.error };
}

export async function executeAuthenticatedPaymentSettingsUpdate(params: {
  authHeader?: string;
  payload: unknown;
  supabaseClient: any;
  filePath?: string;
  env?: NodeJS.ProcessEnv;
}) {
  const { authHeader, payload, supabaseClient, filePath = DEFAULT_PAYMENT_SETTINGS_PATH, env } = params;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return { statusCode: 401, payload: { success: false, error: 'Não autorizado.' } };
  }

  const token = authHeader.slice(7).trim();
  let authenticatedUserId: string;
  let verifiedRole: string;

  try {
    const { data: authData, error: authError } = await supabaseClient.auth.getUser(token);
    if (authError || !authData?.user?.id) {
      return { statusCode: 401, payload: { success: false, error: 'Sessão inválida.' } };
    }
    authenticatedUserId = authData.user.id;

    const { data: profile } = await supabaseClient
      .from('profiles')
      .select('id, role')
      .eq('id', authenticatedUserId)
      .maybeSingle();

    verifiedRole = profile?.role || 'USER';
  } catch {
    return { statusCode: 500, payload: { success: false, error: 'Erro de autenticação.' } };
  }

  if (!ALLOWED_PAYMENT_ADMIN_ROLES.includes(verifiedRole as any)) {
    return { statusCode: 403, payload: { success: false, error: 'Acesso negado.' } };
  }

  const validation = validatePaymentSettingsPayload(payload, {
    mpAccessToken: (env || process.env).MP_ACCESS_TOKEN,
    mpWebhookSecret: (env || process.env).MP_WEBHOOK_SECRET,
  });

  if (!validation.valid || !validation.sanitized) {
    return { statusCode: validation.statusCode, payload: { success: false, error: validation.error } };
  }

  const nowIso = new Date().toISOString();
  let savedSettings: PersistedPaymentSettings;

  try {
    savedSettings = writePersistedPaymentSettings(
      {
        ...validation.sanitized,
        updated_at: nowIso,
        updated_by: authenticatedUserId,
        updated_by_role: verifiedRole,
      },
      filePath
    );
  } catch {
    return { statusCode: 500, payload: { success: false, error: 'Falha ao persistir configurações.' } };
  }

  try {
    await supabaseClient.from('audit_logs').insert({
      actor_id: authenticatedUserId,
      action: 'UPDATE_PAYMENT_SETTINGS',
      entity: 'payment_settings',
      entity_id: 'mercado_pago',
      details: {
        new_config: {
          environment: savedSettings.environment,
          public_key: savedSettings.public_key,
          pix_enabled: savedSettings.pix_enabled,
          pix_instant_enabled: savedSettings.pix_instant_enabled,
          credit_card_enabled: savedSettings.credit_card_enabled,
          boleto_enabled: savedSettings.boleto_enabled,
        },
        actor_role: verifiedRole,
        updated_at: nowIso,
      },
    });
  } catch {
    // Tolerante se tabela de audit_logs estiver em sincronização
  }

  const canonicalConfig = buildCanonicalPaymentConfigResponse(savedSettings, env);
  return {
    statusCode: 200,
    payload: {
      success: true,
      message: 'Configurações salvas com sucesso.',
      config: canonicalConfig,
    },
  };
}
