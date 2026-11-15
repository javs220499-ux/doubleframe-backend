import express, { Express, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { PrismaClient, Prisma } from '@prisma/client';

function isLocalIsolatedTestMode(): boolean {
  // Blindaje estricto: jamás puede activarse en Render ni en NODE_ENV=production
  if (process.env.RENDER || process.env.RENDER_SERVICE_ID || process.env.NODE_ENV === 'production') {
    return false;
  }
  if (process.env.NOVILLO_TEST_MODE !== '1') {
    return false;
  }
  if ((globalThis as Record<string, unknown>).__NOVILLO_TEST_PRISMA__) {
    return true;
  }
  const dbUrl = String(process.env.DATABASE_URL || '');
  return /^postgresql:\/\/[^@]+@(127\.0\.0\.1|localhost):\d{2,5}\/novillo_stage0_pg18_test(\?.*)?$/.test(dbUrl);
}

const IS_LOCAL_TEST_MODE = isLocalIsolatedTestMode();
if (!IS_LOCAL_TEST_MODE) {
  dotenv.config();
}
const prisma: PrismaClient =
  IS_LOCAL_TEST_MODE && (globalThis as Record<string, unknown>).__NOVILLO_TEST_PRISMA__
    ? ((globalThis as Record<string, unknown>).__NOVILLO_TEST_PRISMA__ as PrismaClient)
    : new PrismaClient();
const app: Express = express();
const port = process.env.PORT || 3000;
const AUTH_SECRET = process.env.JWT_SECRET || 'doubleframe_saas_secret_key_2026';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 horas de vigencia por sesión

// ===================================================
// 1. CRIPTOGRAFÍA DE CONTRASEÑAS (SCRYPT + MIGRACIÓN)
// ===================================================
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 };
const SCRYPT_KEYLEN = 64;

function isPasswordHashed(storedPassword: string): boolean {
  if (!storedPassword) return false;
  return (
    storedPassword.startsWith('scrypt$') ||
    storedPassword.startsWith('sha256$') ||
    storedPassword.startsWith('$2a$') ||
    storedPassword.startsWith('$2b$')
  );
}

function hashPassword(plainPassword: string): string {
  const clean = String(plainPassword);
  if (isPasswordHashed(clean)) return clean;
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(clean, salt, SCRYPT_KEYLEN, SCRYPT_PARAMS).toString('hex');
  return `scrypt$${salt}$${derivedKey}`;
}

function safeTimingEqualHex(hexA: string, hexB: string): boolean {
  try {
    const bufA = Buffer.from(hexA, 'hex');
    const bufB = Buffer.from(hexB, 'hex');
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

function verifyPassword(storedPassword: string, inputPassword: string): boolean {
  if (!storedPassword || !inputPassword) return false;

  if (storedPassword.startsWith('scrypt$')) {
    const parts = storedPassword.split('$');
    if (parts.length === 3) {
      const salt = parts[1] || '';
      const expectedHash = parts[2] || '';
      try {
        const computed = crypto.scryptSync(inputPassword, salt, SCRYPT_KEYLEN, SCRYPT_PARAMS).toString('hex');
        return safeTimingEqualHex(computed, expectedHash);
      } catch {
        return false;
      }
    }
    return false;
  }

  if (storedPassword.startsWith('sha256$')) {
    const parts = storedPassword.split('$');
    if (parts.length === 3) {
      const salt = parts[1] || '';
      const expectedHash = parts[2] || '';
      const computed = crypto.createHmac('sha256', salt).update(inputPassword).digest('hex');
      return safeTimingEqualHex(computed, expectedHash);
    }
    return false;
  }

  // Soporte temporal de lectura para cuentas previas en texto plano (se migran automáticamente a scrypt)
  const bufStored = Buffer.from(String(storedPassword), 'utf8');
  const bufInput = Buffer.from(String(inputPassword), 'utf8');
  if (bufStored.length !== bufInput.length) return false;
  return crypto.timingSafeEqual(bufStored, bufInput);
}

async function migrateExistingPlainPasswords(): Promise<void> {
  try {
    const allUsers = await prisma.platformUser.findMany();
    let migratedCount = 0;
    for (const u of allUsers) {
      if (u.password && !u.password.startsWith('scrypt$')) {
        const hashed = hashPassword(u.password);
        await prisma.platformUser.update({
          where: { id: u.id },
          data: { password: hashed }
        });
        migratedCount++;
      }
    }
    if (migratedCount > 0) {
      console.log(`[security]: Se migraron automáticamente ${migratedCount} contraseña(s) a hash seguro scrypt.`);
    }
  } catch (err) {
    console.error('[security]: Error al migrar contraseñas existentes:', err);
  }
}

function sanitizePlatformUser(u: {
  id: string;
  username: string;
  role: string;
  clientId: string | null;
  createdAt?: Date;
  updatedAt?: Date;
}) {
  return {
    id: u.id,
    username: u.username,
    role: u.role,
    clientId: u.clientId,
    hasPassword: true,
    createdAt: u.createdAt,
    updatedAt: u.updatedAt
  };
}

// ===================================================
// 2. AUTENTICACIÓN, TOKENS FIRMADOS Y SESIONES
// ===================================================
interface AuthTokenPayload {
  jti: string;
  id: string;
  username: string;
  role: string;
  clientId: string | null;
  iat: number;
  exp: number;
}

interface AuthenticatedUser {
  jti: string;
  id: string;
  username: string;
  role: string;
  rawClientId: string | null;
  clientIds: string[];
  companyIds: string[];
}

declare global {
  namespace Express {
    interface Request {
      authUser?: AuthenticatedUser;
    }
  }
}

// Lista en memoria de tokens cerrados explícitamente (Logout) hasta su expiración natural
const revokedTokens = new Map<string, number>();

function cleanupRevokedTokens(): void {
  const now = Date.now();
  for (const [jti, exp] of revokedTokens.entries()) {
    if (exp <= now) {
      revokedTokens.delete(jti);
    }
  }
}

function parseClientAndCompanyIds(rawClientId: string | null | undefined): {
  clientIds: string[];
  companyIds: string[];
} {
  if (!rawClientId || rawClientId === 'all') {
    return { clientIds: [], companyIds: [] };
  }
  const str = String(rawClientId);
  let leftPart = str;
  let rightPart = '';
  if (str.includes('::')) {
    const parts = str.split('::');
    leftPart = parts[0] || '';
    rightPart = parts[1] || '';
  }
  const clientIds = Array.from(
    new Set(
      leftPart
        .split(',')
        .map(s => s.trim())
        .filter(s => s && s !== 'all')
    )
  );
  const companyIds = Array.from(
    new Set(
      rightPart
        .split(',')
        .map(s => s.trim())
        .filter(Boolean)
    )
  );
  return { clientIds, companyIds };
}

const parseClientAndCompany = parseClientAndCompanyIds;

function createSessionToken(user: {
  id: string;
  username: string;
  role: string;
  clientId: string | null;
}): string {
  const now = Date.now();
  const payload: AuthTokenPayload = {
    jti: crypto.randomBytes(12).toString('hex'),
    id: user.id,
    username: user.username,
    role: user.role,
    clientId: user.clientId || null,
    iat: now,
    exp: now + SESSION_TTL_MS
  };
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', AUTH_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifySessionToken(token: string | undefined | null): AuthenticatedUser | null {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const data = parts[0] || '';
  const sig = parts[1] || '';
  if (!data || !sig) return null;

  const expectedSig = crypto.createHmac('sha256', AUTH_SECRET).update(data).digest('base64url');
  const bufSig = Buffer.from(sig, 'utf8');
  const bufExpected = Buffer.from(expectedSig, 'utf8');
  if (bufSig.length !== bufExpected.length || !crypto.timingSafeEqual(bufSig, bufExpected)) {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8')) as AuthTokenPayload;
    if (!payload || !payload.username || !payload.role || !payload.exp) return null;
    if (Date.now() > payload.exp) return null;
    cleanupRevokedTokens();
    if (payload.jti && revokedTokens.has(payload.jti)) return null;

    const { clientIds, companyIds } = parseClientAndCompanyIds(payload.clientId);
    return {
      jti: payload.jti || '',
      id: payload.id || payload.username,
      username: payload.username,
      role: payload.role.trim(),
      rawClientId: payload.clientId || null,
      clientIds,
      companyIds
    };
  } catch {
    return null;
  }
}

function extractTokenFromRequest(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (authHeader && typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  const customHeader = req.headers['x-auth-token'];
  if (customHeader && typeof customHeader === 'string') {
    return customHeader.trim();
  }
  if (req.path.startsWith('/api/files/') && typeof req.query.token === 'string' && req.query.token.trim()) {
    return req.query.token.trim();
  }
  return null;
}

interface PassiveSessionEntry {
  jti: string;
  userId: string;
  username: string;
  role: string;
  clientId: string | null;
  userAgentSummary: string;
  firstSeenAt: string;
  lastApiSeenAt: string;
  lastEndpoint: string;
  hasReportedStage0Snapshot: boolean;
  reportedDeviceIds: string[];
}

const passiveSessionsRegistry = new Map<string, PassiveSessionEntry>();

function trackActiveSessionPassively(req: Request, authUser: AuthenticatedUser): void {
  const sessionKey = authUser.jti || `legacy_${authUser.id}_${authUser.username}`;
  const nowIso = new Date().toISOString();
  const uaRaw = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : 'unknown';
  const uaSummary = uaRaw.slice(0, 140);
  const existing = passiveSessionsRegistry.get(sessionKey);
  if (existing) {
    existing.lastApiSeenAt = nowIso;
    existing.lastEndpoint = `${req.method} ${req.path}`;
    existing.userAgentSummary = uaSummary;
  } else if (passiveSessionsRegistry.size < 5000) {
    passiveSessionsRegistry.set(sessionKey, {
      jti: sessionKey,
      userId: authUser.id,
      username: authUser.username,
      role: authUser.role,
      clientId: authUser.rawClientId,
      userAgentSummary: uaSummary,
      firstSeenAt: nowIso,
      lastApiSeenAt: nowIso,
      lastEndpoint: `${req.method} ${req.path}`,
      hasReportedStage0Snapshot: false,
      reportedDeviceIds: []
    });
  }
}

function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const token = extractTokenFromRequest(req);
  const authUser = verifySessionToken(token);
  if (!authUser) {
    res.status(401).json({ error: 'Sesión no válida o expirada. Por favor inicia sesión nuevamente.' });
    return;
  }
  req.authUser = authUser;
  trackActiveSessionPassively(req, authUser);
  next();
}

function requireRoles(allowedRoles: string[]) {
  const normalizedAllowed = allowedRoles.map(r => r.toUpperCase());
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.authUser) {
      res.status(401).json({ error: 'No autenticado' });
      return;
    }
    const userRole = req.authUser.role.toUpperCase();
    if (!normalizedAllowed.includes(userRole)) {
      res.status(403).json({ error: `Permiso denegado para el rol ${req.authUser.role}` });
      return;
    }
    next();
  };
}

function isDiamanteUser(user: AuthenticatedUser): boolean {
  return user.role.toUpperCase() === 'DIAMANTE';
}

function canUserAccessClient(user: AuthenticatedUser, targetClientId: string | null | undefined): boolean {
  if (isDiamanteUser(user)) return true;
  if (!targetClientId || targetClientId === 'all') return false;
  return user.clientIds.includes(String(targetClientId).trim());
}

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// ---------------------------------------------------
// RUTAS PÚBLICAS DE SALUD Y KEEP-ALIVE
// ---------------------------------------------------
app.get('/', (_req: Request, res: Response) => {
  res.json({ message: '🚀 API de SaaS Control de Accesos', version: '1.2.0' });
});

app.get('/api/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ---------------------------------------------------
// ETAPA 4: HELPER DE BITÁCORA DE AUDITORÍA Y MONITOREO (AuditLog)
// ---------------------------------------------------
function getRequestIp(req: Request): string {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.trim() !== '') {
    return (xff.split(',')[0] || '').trim();
  }
  return req.socket?.remoteAddress || '0.0.0.0';
}

async function recordAuditLog(params: {
  username: string;
  role: string;
  saasClientId?: string | null;
  action: string;
  entityType: string;
  entityId?: string | null;
  details?: string | Record<string, unknown> | null;
  ipAddress?: string | null;
}): Promise<void> {
  try {
    const detailsStr =
      params.details === undefined || params.details === null
        ? null
        : typeof params.details === 'string'
        ? params.details
        : JSON.stringify(params.details);

    await prisma.auditLog.create({
      data: {
        username: String(params.username || 'Sistema'),
        role: String(params.role || 'Sistema'),
        saasClientId: params.saasClientId ? String(params.saasClientId) : null,
        action: String(params.action),
        entityType: String(params.entityType),
        entityId: params.entityId ? String(params.entityId) : null,
        details: detailsStr,
        ipAddress: params.ipAddress ? String(params.ipAddress) : null
      }
    });
  } catch (err) {
    console.warn('[audit]: No se pudo escribir en AuditLog:', err);
  }
}

// ---------------------------------------------------
// ETAPA 6: GESTIÓN COMERCIAL SAAS (PLANES, LÍMITES Y SUSPENSIÓN DE CLIENTES)
// ---------------------------------------------------
interface SaasClientCommercialConfig {
  id: string;
  name?: string;
  commercialPlan?: string;
  serviceStatus?: string; // 'ACTIVE' | 'GRACE_PERIOD' | 'SUSPENDED'
  subscriptionEndDate?: string;
  maxCompanies?: number;
  maxWorkers?: number;
  maxUsers?: number;
}

let cachedSaasClientsMap: Map<string, SaasClientCommercialConfig> | null = null;
let cachedSaasClientsExpiresAt = 0;

function invalidateSaasClientsConfigCache(): void {
  cachedSaasClientsMap = null;
  cachedSaasClientsExpiresAt = 0;
}

async function getSaasClientsConfigMap(): Promise<Map<string, SaasClientCommercialConfig>> {
  const now = Date.now();
  if (cachedSaasClientsMap && now < cachedSaasClientsExpiresAt) {
    return cachedSaasClientsMap;
  }
  const map = new Map<string, SaasClientCommercialConfig>();
  try {
    const sysRecord = await prisma.tenant.findFirst({
      where: { saasClientId: '__SYS_CLIENTS__', name: '[CLIENTS_SYSTEM]' },
      orderBy: { createdAt: 'desc' }
    });
    if (sysRecord && sysRecord.documents) {
      const parsed = typeof sysRecord.documents === 'string' ? JSON.parse(sysRecord.documents) : sysRecord.documents;
      if (parsed && Array.isArray(parsed.clients)) {
        for (const cl of parsed.clients) {
          if (cl && cl.id) {
            map.set(String(cl.id), cl as SaasClientCommercialConfig);
          }
        }
      }
    }
  } catch (err) {
    console.warn('[saas-commercial]: Error leyendo configuración comercial de clientes:', err);
  }
  cachedSaasClientsMap = map;
  cachedSaasClientsExpiresAt = now + 10000;
  return map;
}

// ---------------------------------------------------
// AUTENTICACIÓN: LOGIN, LOGOUT, VERIFICACIÓN Y CAMBIO DE CONTRASEÑA
// ---------------------------------------------------
app.post('/api/login', async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Usuario y contraseña obligatorios' });
    }

    const cleanUsername = String(username).trim();
    let dbUser = await prisma.platformUser.findUnique({
      where: { username: cleanUsername }
    });
    if (!dbUser) {
      dbUser = await prisma.platformUser.findFirst({
        where: { username: { equals: cleanUsername, mode: 'insensitive' } }
      });
    }

    const passwordValid =
      dbUser &&
      (verifyPassword(dbUser.password, String(password)) ||
        verifyPassword(dbUser.password, String(password).trim()));

    if (!dbUser || !passwordValid) {
      await recordAuditLog({
        username: cleanUsername,
        role: dbUser ? dbUser.role : 'Desconocido',
        saasClientId: dbUser ? parseClientAndCompanyIds(dbUser.clientId).clientIds[0] || null : null,
        action: 'LOGIN_FAILED',
        entityType: 'AUTH',
        details: `Intento fallido de inicio de sesión para el usuario "${cleanUsername}"`,
        ipAddress: getRequestIp(req)
      });
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }

    // Si la contraseña estaba en formato antiguo (texto plano o sha256), actualizarla en caliente a scrypt
    if (!dbUser.password.startsWith('scrypt$')) {
      try {
        await prisma.platformUser.update({
          where: { id: dbUser.id },
          data: { password: hashPassword(String(password).trim()) }
        });
      } catch (migErr) {
        console.warn('[security]: No se pudo migrar contraseña en login:', migErr);
      }
    }

    const userPayload = {
      id: dbUser.id,
      username: dbUser.username,
      role: dbUser.role,
      clientId: dbUser.clientId
    };

    // ETAPA 6: Verificar si el cliente SaaS asignado al usuario está suspendido comercialmente
    if (String(dbUser.role || '').trim().toUpperCase() !== 'DIAMANTE') {
      const assignedClientIds = parseClientAndCompanyIds(dbUser.clientId).clientIds;
      if (assignedClientIds.length > 0) {
        const clientsMap = await getSaasClientsConfigMap();
        const activeOrAllowed = assignedClientIds.some((cid: string) => {
          const cfg = clientsMap.get(cid);
          return !cfg || cfg.serviceStatus !== 'SUSPENDED';
        });
        if (!activeOrAllowed) {
          await recordAuditLog({
            username: dbUser.username,
            role: dbUser.role,
            saasClientId: assignedClientIds[0] || null,
            action: 'LOGIN_BLOCKED_SUSPENDED',
            entityType: 'AUTH',
            entityId: dbUser.id,
            details: `Inicio de sesión bloqueado: Cliente SaaS en estado SUSPENDIDO`,
            ipAddress: getRequestIp(req)
          });
          return res.status(403).json({
            error: 'El servicio de este proyecto/cliente se encuentra temporalmente suspendido por administración comercial. Contacte al administrador.'
          });
        }
      }
    }

    await recordAuditLog({
      username: dbUser.username,
      role: dbUser.role,
      saasClientId: parseClientAndCompanyIds(dbUser.clientId).clientIds[0] || null,
      action: 'LOGIN_SUCCESS',
      entityType: 'AUTH',
      entityId: dbUser.id,
      details: `Inicio de sesión exitoso (${dbUser.role})`,
      ipAddress: getRequestIp(req)
    });

    return res.json({
      success: true,
      token: createSessionToken(userPayload),
      user: userPayload
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.post('/api/logout', (req: Request, res: Response) => {
  const token = extractTokenFromRequest(req);
  const authUser = verifySessionToken(token);
  if (authUser && authUser.jti) {
    revokedTokens.set(authUser.jti, Date.now() + SESSION_TTL_MS);
    recordAuditLog({
      username: authUser.username,
      role: authUser.role,
      saasClientId: authUser.clientIds[0] || null,
      action: 'LOGOUT',
      entityType: 'AUTH',
      entityId: authUser.id,
      details: 'Cierre de sesión de usuario',
      ipAddress: getRequestIp(req)
    });
  }
  res.json({ success: true });
});

app.get('/api/me', requireAuth, (req: Request, res: Response) => {
  res.json({
    authenticated: true,
    user: req.authUser
  });
});

app.post('/api/change-password', requireAuth, async (req: Request, res: Response) => {
  try {
    const { newPassword } = req.body;
    if (!newPassword || String(newPassword).trim().length < 4) {
      return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 4 caracteres' });
    }
    const authUser = req.authUser!;
    const dbUser = await prisma.platformUser.findUnique({
      where: { username: authUser.username }
    });
    if (!dbUser) {
      return res.status(404).json({ error: 'Cuenta de usuario no encontrada' });
    }
    await prisma.platformUser.update({
      where: { id: dbUser.id },
      data: { password: hashPassword(String(newPassword)) }
    });
    await recordAuditLog({
      username: authUser.username,
      role: authUser.role,
      saasClientId: authUser.clientIds[0] || null,
      action: 'PASSWORD_CHANGE',
      entityType: 'USER',
      entityId: dbUser.id,
      details: `El usuario "${authUser.username}" actualizó su propia contraseña`,
      ipAddress: getRequestIp(req)
    });
    return res.json({ success: true });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Error al cambiar la contraseña' });
  }
});

// ---------------------------------------------------
// RUTAS PARA COMPAÑÍAS (TENANTS) — AISLAMIENTO MULTI-TENANT Y RBAC
// ---------------------------------------------------
app.get('/api/companies', requireAuth, async (req: Request, res: Response) => {
  try {
    const authUser = req.authUser!;
    const { saasClientId } = req.query;

    // Caso especial: configuración de Clientes SaaS ([CLIENTS_SYSTEM])
    if (saasClientId === '__SYS_CLIENTS__') {
      const sysRecords = await prisma.tenant.findMany({
        where: { saasClientId: '__SYS_CLIENTS__' },
        orderBy: { createdAt: 'desc' }
      });

      if (isDiamanteUser(authUser)) {
        return res.json(sysRecords);
      }

      // Para roles que no son Diamante, filtrar únicamente los clientes asignados a este usuario
      const filteredSysRecords = sysRecords.map(rec => {
        if (rec.name !== '[CLIENTS_SYSTEM]' || !rec.documents) return rec;
        try {
          const parsed = typeof rec.documents === 'string' ? JSON.parse(rec.documents) : rec.documents;
          const allClients = Array.isArray(parsed.clients) ? parsed.clients : [];
          const visibleClients = allClients.filter((c: any) => c && authUser.clientIds.includes(String(c.id)));
          const ownUserCompanies: Record<string, unknown> = {};
          if (parsed.userCompanies && parsed.userCompanies[authUser.username]) {
            ownUserCompanies[authUser.username] = parsed.userCompanies[authUser.username];
          }
          return {
            ...rec,
            documents: JSON.stringify({
              ...parsed,
              clients: visibleClients,
              userCompanies: ownUserCompanies
            })
          };
        } catch {
          return rec;
        }
      });
      return res.json(filteredSysRecords);
    }

    const whereClause: Record<string, unknown> = {
      NOT: { saasClientId: '__SYS_CLIENTS__' }
    };

    if (isDiamanteUser(authUser)) {
      if (saasClientId && saasClientId !== 'all') {
        whereClause.saasClientId = String(saasClientId);
      }
    } else {
      if (authUser.clientIds.length === 0) {
        return res.json([]);
      }
      if (saasClientId && saasClientId !== 'all') {
        if (!canUserAccessClient(authUser, String(saasClientId))) {
          return res.status(403).json({ error: 'No tienes permiso para consultar información de este cliente' });
        }
        whereClause.saasClientId = String(saasClientId);
      } else {
        whereClause.saasClientId = { in: authUser.clientIds };
      }

      // Si es Cobre y tiene empresas específicas asignadas, limitar también a sus empresas
      if (authUser.role.toUpperCase() === 'COBRE' && authUser.companyIds.length > 0) {
        whereClause.id = { in: authUser.companyIds };
      }
    }

    const companies = await prisma.tenant.findMany({
      where: whereClause,
      orderBy: { createdAt: 'desc' }
    });
    return res.json(companies);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Error al obtener las compañías' });
  }
});

// ---------------------------------------------------
// ETAPA 2: VALIDACIÓN Y ALMACENAMIENTO CENTRALIZADO DE ARCHIVOS
// ---------------------------------------------------
const ALLOWED_FILE_MIMES = new Set([
  'application/pdf',
  'image/jpeg',
  'image/jpg',
  'image/png',
  'image/webp'
]);

const ALLOWED_FILE_EXTENSIONS = new Set([
  '.pdf',
  '.jpg',
  '.jpeg',
  '.png',
  '.webp'
]);

const MAX_FILE_SIZE_BYTES = 15 * 1024 * 1024; // 15 MB por documento o fotografía

function getExtensionLower(fileName: string): string {
  const clean = String(fileName || '').trim().toLowerCase();
  const lastDot = clean.lastIndexOf('.');
  return lastDot >= 0 ? clean.slice(lastDot) : '';
}

function inferMimeFromExtension(ext: string): string {
  switch (ext) {
    case '.pdf':
      return 'application/pdf';
    case '.jpg':
    case '.jpeg':
      return 'image/jpeg';
    case '.png':
      return 'image/png';
    case '.webp':
      return 'image/webp';
    default:
      return '';
  }
}

function validateAndParseFilePayload(
  fileName: string,
  dataUrlOrBase64: string,
  explicitMime?: string
): {
  valid: boolean;
  error?: string;
  cleanFileName: string;
  mimeType: string;
  sizeBytes: number;
  normalizedDataUrl: string;
} {
  const rawName = String(fileName || '').trim();
  if (!rawName) {
    return { valid: false, error: 'Nombre de archivo obligatorio', cleanFileName: '', mimeType: '', sizeBytes: 0, normalizedDataUrl: '' };
  }
  const cleanFileName = rawName.replace(/[^\w.\- ()áéíóúÁÉÍÓÚñÑ]/g, '_');
  const ext = getExtensionLower(cleanFileName);
  if (!ext || !ALLOWED_FILE_EXTENSIONS.has(ext)) {
    return {
      valid: false,
      error: `Extensión no permitida (${ext || 'sin extensión'}). Solo se permiten archivos PDF, JPG, JPEG, PNG y WEBP.`,
      cleanFileName,
      mimeType: '',
      sizeBytes: 0,
      normalizedDataUrl: ''
    };
  }

  const rawContent = String(dataUrlOrBase64 || '').trim();
  if (!rawContent) {
    return { valid: false, error: 'Contenido de archivo vacío', cleanFileName, mimeType: '', sizeBytes: 0, normalizedDataUrl: '' };
  }

  let detectedMime = (explicitMime || '').trim().toLowerCase();
  let base64Part = rawContent;

  if (rawContent.startsWith('data:')) {
    const commaIdx = rawContent.indexOf(',');
    if (commaIdx < 0) {
      return { valid: false, error: 'Formato DataURL inválido', cleanFileName, mimeType: '', sizeBytes: 0, normalizedDataUrl: '' };
    }
    const header = rawContent.slice(5, commaIdx);
    const mimeMatch = header.split(';')[0]?.trim().toLowerCase() || '';
    if (mimeMatch && mimeMatch !== 'application/octet-stream') {
      detectedMime = mimeMatch;
    }
    base64Part = rawContent.slice(commaIdx + 1);
  }

  if (!detectedMime || detectedMime === 'application/octet-stream') {
    detectedMime = inferMimeFromExtension(ext);
  }
  if (detectedMime === 'image/jpg') {
    detectedMime = 'image/jpeg';
  }

  if (!ALLOWED_FILE_MIMES.has(detectedMime)) {
    return {
      valid: false,
      error: `Tipo MIME no permitido (${detectedMime}). Solo se aceptan documentos PDF e imágenes (JPG, PNG, WEBP).`,
      cleanFileName,
      mimeType: detectedMime,
      sizeBytes: 0,
      normalizedDataUrl: ''
    };
  }

  const byteBuffer = Buffer.from(base64Part, 'base64');
  const sizeBytes = byteBuffer.length;
  if (sizeBytes <= 0) {
    return { valid: false, error: 'El archivo está vacío o corrupto', cleanFileName, mimeType: detectedMime, sizeBytes: 0, normalizedDataUrl: '' };
  }
  if (sizeBytes > MAX_FILE_SIZE_BYTES) {
    return {
      valid: false,
      error: `El archivo excede el tamaño máximo permitido de 15 MB (${(sizeBytes / (1024 * 1024)).toFixed(2)} MB).`,
      cleanFileName,
      mimeType: detectedMime,
      sizeBytes,
      normalizedDataUrl: ''
    };
  }

  const normalizedDataUrl = `data:${detectedMime};base64,${base64Part}`;
  return {
    valid: true,
    cleanFileName,
    mimeType: detectedMime,
    sizeBytes,
    normalizedDataUrl
  };
}

async function extractAndCentralizeCompanyInlineDocs(
  companyId: string | null,
  saasClientId: string | null,
  rawDocuments: unknown,
  uploadedBy: string
): Promise<Record<string, unknown> | null> {
  if (!rawDocuments || typeof rawDocuments !== 'object') return null;
  const docs = JSON.parse(JSON.stringify(rawDocuments)) as Record<string, any>;

  // 1. Centralizar documentos activos en docs._files
  if (docs._files && typeof docs._files === 'object') {
    for (const [docIdxStr, fileEntry] of Object.entries(docs._files)) {
      if (!fileEntry || typeof fileEntry !== 'object') continue;
      const entry = fileEntry as Record<string, any>;
      if (entry.dataUrl && typeof entry.dataUrl === 'string' && entry.dataUrl.startsWith('data:')) {
        const fName = entry.fileName || docs[docIdxStr] || `documento_${docIdxStr}.pdf`;
        const parsed = validateAndParseFilePayload(fName, entry.dataUrl, entry.mimeType);
        if (parsed.valid) {
          try {
            const stored = await prisma.storedFile.create({
              data: {
                saasClientId: saasClientId || null,
                companyId: companyId || null,
                category: 'COMPANY_DOC',
                docIndex: Number.isNaN(parseInt(docIdxStr, 10)) ? null : parseInt(docIdxStr, 10),
                fileName: parsed.cleanFileName,
                mimeType: parsed.mimeType,
                sizeBytes: parsed.sizeBytes,
                uploadedBy,
                externalUrl: entry.fileUrl || null,
                contentData: parsed.normalizedDataUrl
              }
            });
            entry.fileId = stored.id;
            entry.mimeType = parsed.mimeType;
            entry.sizeBytes = parsed.sizeBytes;
            delete entry.dataUrl;
            if (!docs._meta) docs._meta = {};
            if (!docs._meta[docIdxStr]) docs._meta[docIdxStr] = {};
            docs._meta[docIdxStr].fileId = stored.id;
            docs._meta[docIdxStr].mimeType = parsed.mimeType;
            docs._meta[docIdxStr].sizeBytes = parsed.sizeBytes;
          } catch (err) {
            console.warn('[files]: No se pudo centralizar documento activo de empresa:', err);
          }
        }
      }
    }
  }

  // 2. Centralizar documentos del histórico en docs._history
  if (docs._history && typeof docs._history === 'object') {
    for (const [docIdxStr, histList] of Object.entries(docs._history)) {
      if (!Array.isArray(histList)) continue;
      for (const item of histList) {
        if (!item || typeof item !== 'object') continue;
        if (item.dataUrl && typeof item.dataUrl === 'string' && item.dataUrl.startsWith('data:')) {
          const fName = item.fileName || `historico_${docIdxStr}.pdf`;
          const parsed = validateAndParseFilePayload(fName, item.dataUrl, item.mimeType);
          if (parsed.valid) {
            try {
              const stored = await prisma.storedFile.create({
                data: {
                  saasClientId: saasClientId || null,
                  companyId: companyId || null,
                  category: 'COMPANY_HISTORY_DOC',
                  docIndex: Number.isNaN(parseInt(docIdxStr, 10)) ? null : parseInt(docIdxStr, 10),
                  fileName: parsed.cleanFileName,
                  mimeType: parsed.mimeType,
                  sizeBytes: parsed.sizeBytes,
                  uploadedBy,
                  externalUrl: item.fileUrl || null,
                  contentData: parsed.normalizedDataUrl
                }
              });
              item.fileId = stored.id;
              item.mimeType = parsed.mimeType;
              item.sizeBytes = parsed.sizeBytes;
              delete item.dataUrl;
            } catch (err) {
              console.warn('[files]: No se pudo centralizar documento histórico:', err);
            }
          }
        }
      }
    }
  }

  return docs;
}

async function migrateExistingInlineDocuments(): Promise<void> {
  try {
    const companies = await prisma.tenant.findMany();
    let migratedCount = 0;
    for (const comp of companies) {
      if (!comp.documents || comp.name === '[CLIENTS_SYSTEM]') continue;
      try {
        const parsedDocs = typeof comp.documents === 'string' ? JSON.parse(comp.documents) : comp.documents;
        const rawStr = JSON.stringify(parsedDocs);
        if (rawStr.includes('"dataUrl":"data:')) {
          const cleaned = await extractAndCentralizeCompanyInlineDocs(
            comp.id,
            comp.saasClientId,
            parsedDocs,
            'MigracionAutomatica'
          );
          if (cleaned) {
            await prisma.tenant.update({
              where: { id: comp.id },
              data: { documents: JSON.stringify(cleaned) }
            });
            migratedCount++;
          }
        }
      } catch {
        // Ignorar registros con JSON inválido
      }
    }
    if (migratedCount > 0) {
      console.log(`[files]: Se centralizaron documentos inline de ${migratedCount} compañía(s).`);
    }
  } catch (err) {
    console.warn('[files]: Aviso durante migración de documentos inline:', err);
  }
}

app.post(
  '/api/companies',
  requireAuth,
  requireRoles(['Diamante', 'Platino', 'Piedra']),
  async (req: Request, res: Response) => {
    try {
      const authUser = req.authUser!;
      const { name, domain, subscriptionPlan, documents, mandatoryDocs, saasClientId } = req.body;
      if (!name) return res.status(400).json({ error: 'El nombre es obligatorio' });

      const cleanName = String(name).trim();
      const isSystemClientsRecord = cleanName === '[CLIENTS_SYSTEM]' || saasClientId === '__SYS_CLIENTS__';

      if (isSystemClientsRecord && !isDiamanteUser(authUser)) {
        return res.status(403).json({ error: 'Solo usuarios Diamante pueden modificar la configuración global de clientes' });
      }

      // Guardia Piedra solo puede inicializar contenedores de sistema de Visitas o Eventuales si no existían
      if (authUser.role.toUpperCase() === 'PIEDRA') {
        if (cleanName !== '[VISITAS_SYSTEM]' && cleanName !== '[EVENTUALES_SYSTEM]') {
          return res.status(403).json({ error: 'El rol Piedra no puede registrar compañías contratistas' });
        }
      }

      let targetClientId = saasClientId ? String(saasClientId).trim() : null;
      if (!isDiamanteUser(authUser)) {
        if (!targetClientId || targetClientId === 'all') {
          targetClientId = authUser.clientIds[0] || null;
        }
        if (!targetClientId || !canUserAccessClient(authUser, targetClientId)) {
          return res.status(403).json({ error: 'No tienes permiso para crear empresas en este cliente' });
        }
      }

      if (isSystemClientsRecord) {
        invalidateSaasClientsConfigCache();
      } else if (
        targetClientId &&
        cleanName !== '[VISITAS_SYSTEM]' &&
        cleanName !== '[EVENTUALES_SYSTEM]' &&
        !cleanName.startsWith('[EVENTUAL] ')
      ) {
        // ETAPA 6: Validar estado comercial y límite de empresas contratistas del plan SaaS
        const clientsMap = await getSaasClientsConfigMap();
        const clientCfg = clientsMap.get(targetClientId);
        if (clientCfg) {
          if (clientCfg.serviceStatus === 'SUSPENDED' && !isDiamanteUser(authUser)) {
            return res.status(403).json({ error: 'El servicio de este cliente se encuentra suspendido comercialmente.' });
          }
          const maxCompanies = Number(clientCfg.maxCompanies) || 0;
          if (maxCompanies > 0) {
            const currentCount = await prisma.tenant.count({
              where: {
                saasClientId: targetClientId,
                NOT: [
                  { name: '[VISITAS_SYSTEM]' },
                  { name: '[EVENTUALES_SYSTEM]' },
                  { name: '[CLIENTS_SYSTEM]' },
                  { name: { startsWith: '[EVENTUAL] ' } }
                ]
              }
            });
            if (currentCount >= maxCompanies) {
              return res.status(403).json({
                error: `Límite comercial alcanzado: El plan contratado permite máximo ${maxCompanies} empresa(s) contratista(s).`
              });
            }
          }
        }
      }

      const newCompany = await prisma.tenant.create({
        data: {
          name: cleanName,
          domain: domain || null,
          subscriptionPlan: subscriptionPlan || 'BASIC',
          documents: documents ? JSON.stringify(documents) : null,
          mandatoryDocs: mandatoryDocs ? JSON.stringify(mandatoryDocs) : null,
          saasClientId: targetClientId
        }
      });

      if (!isSystemClientsRecord) {
        await recordAuditLog({
          username: authUser.username,
          role: authUser.role,
          saasClientId: targetClientId,
          action: 'COMPANY_CREATE',
          entityType: 'COMPANY',
          entityId: newCompany.id,
          details: `Creación de compañía "${cleanName}"`,
          ipAddress: getRequestIp(req)
        });
      }

      if (documents && !isSystemClientsRecord) {
        const cleanedDocs = await extractAndCentralizeCompanyInlineDocs(
          newCompany.id,
          targetClientId,
          documents,
          authUser.username
        );
        if (cleanedDocs) {
          const updatedWithRefs = await prisma.tenant.update({
            where: { id: newCompany.id },
            data: { documents: JSON.stringify(cleanedDocs) }
          });
          return res.status(201).json(updatedWithRefs);
        }
      }

      return res.status(201).json(newCompany);
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: 'Error al crear la compañía' });
    }
  }
);

app.put(
  '/api/companies/:id',
  requireAuth,
  requireRoles(['Diamante', 'Platino']),
  async (req: Request, res: Response) => {
    try {
      const authUser = req.authUser!;
      const id = String(req.params.id || '');
      const { name, documents, mandatoryDocs } = req.body;

      const existing = await prisma.tenant.findUnique({ where: { id } });
      if (!existing) {
        return res.status(404).json({ error: 'Compañía no encontrada' });
      }

      const isSystemClientsRecord =
        existing.name === '[CLIENTS_SYSTEM]' ||
        existing.saasClientId === '__SYS_CLIENTS__' ||
        name === '[CLIENTS_SYSTEM]';
      if (isSystemClientsRecord) {
        invalidateSaasClientsConfigCache();
      }

      if (isSystemClientsRecord && !isDiamanteUser(authUser)) {
        return res.status(403).json({ error: 'Solo usuarios Diamante pueden modificar la configuración global de clientes' });
      }

      if (!isDiamanteUser(authUser) && !canUserAccessClient(authUser, existing.saasClientId)) {
        return res.status(403).json({ error: 'No tienes permiso para modificar empresas de otro cliente' });
      }

      let finalDocsJson = existing.documents;
      if (documents !== undefined) {
        if (documents && !isSystemClientsRecord) {
          const cleanedDocs = await extractAndCentralizeCompanyInlineDocs(
            id,
            existing.saasClientId,
            documents,
            authUser.username
          );
          finalDocsJson = JSON.stringify(cleanedDocs || documents);
        } else {
          finalDocsJson = documents ? JSON.stringify(documents) : null;
        }
      }

      const updated = await prisma.tenant.update({
        where: { id },
        data: {
          name: name || existing.name,
          documents: finalDocsJson,
          mandatoryDocs: mandatoryDocs !== undefined ? (mandatoryDocs ? JSON.stringify(mandatoryDocs) : null) : existing.mandatoryDocs
        }
      });

      if (!isSystemClientsRecord) {
        await recordAuditLog({
          username: authUser.username,
          role: authUser.role,
          saasClientId: existing.saasClientId,
          action: 'COMPANY_UPDATE',
          entityType: 'COMPANY',
          entityId: id,
          details: `Actualización de compañía "${updated.name}"`,
          ipAddress: getRequestIp(req)
        });
      }

      return res.json(updated);
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: 'Error al actualizar la compañía' });
    }
  }
);

app.delete(
  '/api/companies/:id',
  requireAuth,
  requireRoles(['Diamante', 'Platino']),
  async (req: Request, res: Response) => {
    try {
      const authUser = req.authUser!;
      const id = String(req.params.id || '');

      const existing = await prisma.tenant.findUnique({ where: { id } });
      if (!existing) {
        return res.status(404).json({ error: 'Compañía no encontrada' });
      }

      if (existing.name === '[CLIENTS_SYSTEM]' || existing.saasClientId === '__SYS_CLIENTS__') {
        return res.status(403).json({ error: 'No se puede eliminar el registro maestro de clientes' });
      }

      if (!isDiamanteUser(authUser) && !canUserAccessClient(authUser, existing.saasClientId)) {
        return res.status(403).json({ error: 'No tienes permiso para eliminar empresas de otro cliente' });
      }

      const users = await prisma.user.findMany({ where: { tenantId: id } });
      for (const u of users) {
        try {
          await prisma.attendanceLog.deleteMany({ where: { userId: u.id } });
        } catch {}
        try {
          await prisma.storedFile.deleteMany({ where: { workerId: u.id } });
        } catch {}
        try {
          await prisma.userRole.deleteMany({ where: { userId: u.id } });
        } catch {}
      }
      try {
        await prisma.storedFile.deleteMany({ where: { companyId: id } });
      } catch {}
      await prisma.user.deleteMany({ where: { tenantId: id } });
      await prisma.tenant.delete({ where: { id } });

      await recordAuditLog({
        username: authUser.username,
        role: authUser.role,
        saasClientId: existing.saasClientId,
        action: 'COMPANY_DELETE',
        entityType: 'COMPANY',
        entityId: id,
        details: `Eliminación de compañía "${existing.name}" y ${users.length} trabajador(es) asociados`,
        ipAddress: getRequestIp(req)
      });

      return res.json({ success: true });
    } catch (error) {
      console.error('Delete error:', error);
      return res.status(500).json({ error: 'Error al eliminar la compañía' });
    }
  }
);

// ---------------------------------------------------
// RUTAS PARA TRABAJADORES (USERS) — AISLAMIENTO MULTI-TENANT Y RBAC
// ---------------------------------------------------
app.get('/api/workers', requireAuth, async (req: Request, res: Response) => {
  try {
    const authUser = req.authUser!;
    const { saasClientId } = req.query;
    const whereClause: Record<string, unknown> = {};

    if (isDiamanteUser(authUser)) {
      if (saasClientId && saasClientId !== 'all') {
        whereClause.saasClientId = String(saasClientId);
      }
    } else {
      if (authUser.clientIds.length === 0) {
        return res.json([]);
      }
      if (saasClientId && saasClientId !== 'all') {
        if (!canUserAccessClient(authUser, String(saasClientId))) {
          return res.status(403).json({ error: 'No tienes permiso para consultar trabajadores de este cliente' });
        }
        whereClause.saasClientId = String(saasClientId);
      } else {
        whereClause.saasClientId = { in: authUser.clientIds };
      }

      if (authUser.role.toUpperCase() === 'COBRE' && authUser.companyIds.length > 0) {
        whereClause.tenantId = { in: authUser.companyIds };
      }
    }

    const workers = await prisma.user.findMany({
      where: whereClause,
      orderBy: { createdAt: 'desc' }
    });

    const formattedWorkers = workers
      .map(w => {
        let profile: Record<string, unknown> = {};
        if (w.profileData) {
          try {
            profile = JSON.parse(w.profileData);
          } catch {}
        }
        return {
          id: w.id,
          companyId: w.tenantId,
          name: w.name,
          email: w.email,
          isActive: w.isActive,
          ...profile,
          photo:
            (profile as any).photo ||
            `https://ui-avatars.com/api/?name=${encodeURIComponent(w.name)}&background=random`,
          saasClientId: w.saasClientId
        };
      })
      .filter(w => !(w as any).isDeleted && w.name !== '[ELIMINADO]');

    return res.json(formattedWorkers);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Error al obtener trabajadores' });
  }
});

// Verificación individual de gafete QR (Usada por escáner móvil y vista de verificación QR)
app.get('/api/workers/:id', async (req: Request, res: Response) => {
  try {
    const id = String(req.params.id || '');
    const worker = await prisma.user.findUnique({
      where: { id },
      include: { tenant: true }
    });
    if (!worker) {
      return res.status(404).json({ error: 'Trabajador no encontrado' });
    }

    // Si viene con sesión autenticada, validar aislamiento de cliente
    const token = extractTokenFromRequest(req);
    const authUser = verifySessionToken(token);
    if (authUser && !isDiamanteUser(authUser)) {
      const workerClient = worker.saasClientId || (worker.tenant ? worker.tenant.saasClientId : null);
      if (workerClient && !canUserAccessClient(authUser, workerClient)) {
        return res.status(403).json({ error: 'Este trabajador pertenece a otro cliente' });
      }
    }

    return res.json(worker);
  } catch (error) {
    return res.status(500).json({ error: 'Error al buscar el trabajador' });
  }
});

app.post(
  '/api/workers',
  requireAuth,
  requireRoles(['Diamante', 'Platino', 'Piedra']),
  async (req: Request, res: Response) => {
    try {
      const authUser = req.authUser!;
      const { name, companyId, saasClientId, ...profileData } = req.body;

      if (!name || !companyId) {
        return res.status(400).json({ error: 'Nombre y Compañía son obligatorios' });
      }

      // Si el rol es Piedra (Guardia), únicamente puede registrar Visitas o Visitas Eventuales
      const docsArr = Array.isArray(profileData.docs) ? profileData.docs : [];
      const isVisitOrEventual =
        name === 'Visita Eventual' ||
        profileData.position === 'Visita' ||
        Boolean(profileData.visitCount) ||
        Boolean(profileData.visitAuthor) ||
        docsArr.includes('Visita') ||
        docsArr.includes('Proveedor Eventual');

      if (authUser.role.toUpperCase() === 'PIEDRA') {
        if (!isVisitOrEventual) {
          return res.status(403).json({ error: 'El rol Piedra solo puede registrar Visitas o Eventuales' });
        }
      }

      let targetTenant = await prisma.tenant.findUnique({ where: { id: String(companyId) } });
      let effectiveClientId = saasClientId ? String(saasClientId).trim() : (targetTenant?.saasClientId || null);

      if (!isDiamanteUser(authUser)) {
        if (!effectiveClientId || effectiveClientId === 'all') {
          effectiveClientId = authUser.clientIds[0] || null;
        }
        if (!effectiveClientId || !canUserAccessClient(authUser, effectiveClientId)) {
          return res.status(403).json({ error: 'No tienes permiso para registrar personal en otro cliente' });
        }
        if (
          targetTenant &&
          targetTenant.saasClientId &&
          targetTenant.name !== '[VISITAS_SYSTEM]' &&
          targetTenant.name !== '[EVENTUALES_SYSTEM]' &&
          !canUserAccessClient(authUser, targetTenant.saasClientId)
        ) {
          return res.status(403).json({ error: 'La empresa seleccionada pertenece a otro cliente' });
        }
      } else if (effectiveClientId === 'all') {
        effectiveClientId = targetTenant?.saasClientId || null;
      }

      // Si es Visita o Eventual y el companyId enviado por el navegador estaba en caché obsoleto, resolver o crear la empresa de sistema automáticamente
      if (!targetTenant && isVisitOrEventual) {
        const sysName = name === 'Visita Eventual' ? '[EVENTUALES_SYSTEM]' : '[VISITAS_SYSTEM]';
        targetTenant = await prisma.tenant.findFirst({
          where: {
            name: sysName,
            ...(effectiveClientId ? { saasClientId: effectiveClientId } : {})
          }
        });
        if (!targetTenant) {
          targetTenant = await prisma.tenant.create({
            data: {
              name: sysName,
              documents: JSON.stringify({ _isActive: true, _createdBy: authUser.username || 'Sistema' }),
              saasClientId: effectiveClientId
            }
          });
        }
      }

      if (!targetTenant) {
        return res.status(404).json({ error: 'La compañía seleccionada no existe o fue eliminada' });
      }

      const resolvedCompanyId = targetTenant.id;

      // Anti-rebote (idempotencia): evitar duplicados cuando la red reintenta o se hace clic repetido al guardar un trabajador regular
      if (!isVisitOrEventual) {
        const recentThreshold = new Date(Date.now() - 60 * 1000);
        const existingRecent = await prisma.user.findFirst({
          where: {
            tenantId: resolvedCompanyId,
            name: String(name),
            createdAt: { gte: recentThreshold }
          },
          orderBy: { createdAt: 'desc' }
        });
        if (existingRecent) {
          return res.status(200).json(existingRecent);
        }
      }

      // ETAPA 6: Validar estado comercial y límite de trabajadores del plan SaaS (solo para trabajadores regulares)
      if (!isVisitOrEventual && effectiveClientId) {
        const clientsMap = await getSaasClientsConfigMap();
        const clientCfg = clientsMap.get(effectiveClientId);
        if (clientCfg) {
          if (clientCfg.serviceStatus === 'SUSPENDED' && !isDiamanteUser(authUser)) {
            return res.status(403).json({ error: 'El servicio de este cliente se encuentra suspendido comercialmente.' });
          }
          const maxWorkers = Number(clientCfg.maxWorkers) || 0;
          if (maxWorkers > 0) {
            const currentWorkers = await prisma.user.count({
              where: {
                saasClientId: effectiveClientId,
                NOT: [{ name: 'Visita Eventual' }, { name: '[ELIMINADO]' }],
                tenant: {
                  NOT: [{ name: '[VISITAS_SYSTEM]' }, { name: '[EVENTUALES_SYSTEM]' }]
                }
              }
            });
            if (currentWorkers >= maxWorkers) {
              return res.status(403).json({
                error: `Límite comercial alcanzado: El plan contratado permite máximo ${maxWorkers} trabajador(es) registrado(s).`
              });
            }
          }
        }
      }

      const newWorker = await prisma.user.create({
        data: {
          tenantId: resolvedCompanyId,
          name: String(name),
          email: profileData.email || `${Date.now()}_${Math.random().toString(36).slice(2, 7)}@test.com`,
          passwordHash: hashPassword(profileData.password || '123456'),
          profileData: JSON.stringify(profileData),
          saasClientId: effectiveClientId
        }
      });

      await recordAuditLog({
        username: authUser.username,
        role: authUser.role,
        saasClientId: effectiveClientId,
        action: 'WORKER_CREATE',
        entityType: 'WORKER',
        entityId: newWorker.id,
        details: `Registro de trabajador/visita "${newWorker.name}" (${profileData.position || 'Trabajador'})`,
        ipAddress: getRequestIp(req)
      });

      return res.status(201).json(newWorker);
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: 'Error al crear trabajador' });
    }
  }
);

app.put(
  '/api/workers/:id',
  requireAuth,
  requireRoles(['Diamante', 'Platino', 'Oro']),
  async (req: Request, res: Response) => {
    try {
      const authUser = req.authUser!;
      const id = String(req.params.id || '');
      const { name, companyId, ...profileData } = req.body;

      const existing = await prisma.user.findUnique({
        where: { id },
        include: { tenant: true }
      });
      if (!existing) return res.status(404).json({ error: 'Trabajador no encontrado' });

      const workerClient = existing.saasClientId || (existing.tenant ? existing.tenant.saasClientId : null);
      if (!isDiamanteUser(authUser) && workerClient && !canUserAccessClient(authUser, workerClient)) {
        return res.status(403).json({ error: 'No tienes permiso para modificar trabajadores de otro cliente' });
      }

      let oldProfile: Record<string, unknown> = {};
      if (existing.profileData) {
        try {
          oldProfile = JSON.parse(existing.profileData);
        } catch {}
      }
      const mergedProfile = { ...oldProfile, ...profileData };

      const updatedWorker = await prisma.user.update({
        where: { id },
        data: {
          name: name || existing.name,
          tenantId: companyId || existing.tenantId,
          isActive: typeof profileData.isActive === 'boolean' ? profileData.isActive : existing.isActive,
          profileData: JSON.stringify(mergedProfile)
        }
      });

      const isSanctionChange = Array.isArray(profileData.sanctions);
      const isStatusToggle = typeof profileData.isActive === 'boolean' && Object.keys(profileData).length <= 2;
      await recordAuditLog({
        username: authUser.username,
        role: authUser.role,
        saasClientId: workerClient,
        action: isSanctionChange ? 'SANCTION_UPDATE' : (isStatusToggle ? 'WORKER_STATUS_TOGGLE' : 'WORKER_UPDATE'),
        entityType: 'WORKER',
        entityId: id,
        details: isSanctionChange
          ? `Actualización de sanciones de "${updatedWorker.name}" (${(profileData.sanctions as unknown[]).length} sanción(es) activas)`
          : isStatusToggle
          ? `Cambio de estado QR de "${updatedWorker.name}" a ${updatedWorker.isActive ? 'ACTIVO' : 'INACTIVO'}`
          : `Edición de ficha del trabajador "${updatedWorker.name}"`,
        ipAddress: getRequestIp(req)
      });

      return res.json(updatedWorker);
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: 'Error al actualizar trabajador' });
    }
  }
);

app.delete(
  '/api/workers/:id',
  requireAuth,
  requireRoles(['Diamante', 'Platino', 'Oro']),
  async (req: Request, res: Response) => {
    try {
      const authUser = req.authUser!;
      const id = String(req.params.id || '');

      const existing = await prisma.user.findUnique({
        where: { id },
        include: { tenant: true }
      });
      if (!existing) return res.status(404).json({ error: 'Trabajador no encontrado' });

      const workerClient = existing.saasClientId || (existing.tenant ? existing.tenant.saasClientId : null);
      if (!isDiamanteUser(authUser) && workerClient && !canUserAccessClient(authUser, workerClient)) {
        return res.status(403).json({ error: 'No tienes permiso para eliminar trabajadores de otro cliente' });
      }

      try {
        await prisma.attendanceLog.deleteMany({ where: { userId: id } });
      } catch (e) {
        console.warn('Warning deleting attendanceLog for worker:', id, e);
      }
      try {
        await prisma.storedFile.deleteMany({ where: { workerId: id } });
      } catch (e) {
        console.warn('Warning deleting storedFile for worker:', id, e);
      }
      try {
        await prisma.userRole.deleteMany({ where: { userId: id } });
      } catch (e) {
        console.warn('Warning deleting userRole for worker:', id, e);
      }
      await prisma.user.delete({ where: { id } });

      await recordAuditLog({
        username: authUser.username,
        role: authUser.role,
        saasClientId: workerClient,
        action: 'WORKER_DELETE',
        entityType: 'WORKER',
        entityId: id,
        details: `Eliminación del trabajador "${existing.name}"`,
        ipAddress: getRequestIp(req)
      });

      return res.json({ success: true });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: 'Error al eliminar al trabajador' });
    }
  }
);

// ---------------------------------------------------
// ETAPA 3: RUTAS PARA ASISTENCIAS (LOGS) — OPTIMIZACIÓN, INTEGRIDAD Y SINCRONIZACIÓN OFFLINE
// ---------------------------------------------------
function getCutoff659AmForDate(entryDate: Date, timeZone = 'America/Mexico_City'): Date {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  }).formatToParts(entryDate);

  let h = 0;
  let m = 0;
  let s = 0;
  for (const p of parts) {
    if (p.type === 'hour') h = parseInt(p.value, 10) % 24;
    if (p.type === 'minute') m = parseInt(p.value, 10);
    if (p.type === 'second') s = parseInt(p.value, 10);
  }

  const secsSinceMidnight = h * 3600 + m * 60 + s;
  const targetSecs = 6 * 3600 + 59 * 60; // 06:59:00 AM
  let deltaSecs = targetSecs - secsSinceMidnight;
  if (deltaSecs <= 0) {
    deltaSecs += 24 * 3600;
  }
  return new Date(entryDate.getTime() + deltaSecs * 1000);
}

app.get('/api/logs', requireAuth, async (req: Request, res: Response) => {
  try {
    const authUser = req.authUser!;
    const {
      saasClientId,
      companyId,
      workerId,
      from,
      to,
      limit,
      page,
      paginated,
      allHistory
    } = req.query;

    const andConditions: Record<string, unknown>[] = [];

    // 1. Filtro por trabajador específico
    if (workerId) {
      andConditions.push({ userId: String(workerId).trim() });
    }

    // 2. Filtro por empresa específica
    if (companyId) {
      andConditions.push({ user: { tenantId: String(companyId).trim() } });
    }

    // 3. Filtro por rango de fechas (o ventana por defecto de 90 días para evitar descargas masivas innecesarias)
    const timestampFilter: Record<string, Date> = {};
    if (from) {
      const fromStr = String(from).trim();
      const fromDate = new Date(fromStr.length === 10 ? `${fromStr}T00:00:00.000Z` : fromStr);
      if (!isNaN(fromDate.getTime())) timestampFilter.gte = fromDate;
    }
    if (to) {
      const toStr = String(to).trim();
      const toDate = new Date(toStr.length === 10 ? `${toStr}T23:59:59.999Z` : toStr);
      if (!isNaN(toDate.getTime())) timestampFilter.lte = toDate;
    }
    if (!from && !to && !workerId && String(allHistory) !== 'true') {
      // Ventana inteligente por defecto: últimos 90 días
      const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
      timestampFilter.gte = ninetyDaysAgo;
    }
    if (Object.keys(timestampFilter).length > 0) {
      andConditions.push({ timestamp: timestampFilter });
    }

    // 4. Aislamiento Multi-Tenant y permisos por rol
    if (isDiamanteUser(authUser)) {
      if (saasClientId && saasClientId !== 'all') {
        const targetClient = String(saasClientId);
        andConditions.push({
          OR: [
            { user: { saasClientId: targetClient } },
            { user: { tenant: { saasClientId: targetClient } } }
          ]
        });
      }
    } else {
      if (authUser.clientIds.length === 0) {
        return res.json(String(paginated) === 'true' ? { data: [], page: 1, limit: 0, total: 0 } : []);
      }
      let targetClients = authUser.clientIds;
      if (saasClientId && saasClientId !== 'all') {
        const requestedClient = String(saasClientId);
        if (!canUserAccessClient(authUser, requestedClient)) {
          return res.status(403).json({ error: 'No tienes permiso para consultar asistencias de este cliente' });
        }
        targetClients = [requestedClient];
      }

      if (authUser.role.toUpperCase() === 'COBRE' && authUser.companyIds.length > 0) {
        if (companyId && !authUser.companyIds.includes(String(companyId).trim())) {
          return res.status(403).json({ error: 'No tienes permiso para consultar asistencias de otra empresa' });
        }
        andConditions.push({
          user: {
            saasClientId: { in: targetClients },
            tenantId: { in: authUser.companyIds }
          }
        });
      } else {
        andConditions.push({
          OR: [
            { user: { saasClientId: { in: targetClients } } },
            { user: { tenant: { saasClientId: { in: targetClients } } } }
          ]
        });
      }
    }

    const whereClause = andConditions.length > 0 ? { AND: andConditions } : {};
    const parsedLimit = limit ? parseInt(String(limit), 10) : 5000;
    const take = parsedLimit && !isNaN(parsedLimit) && parsedLimit > 0 ? Math.min(parsedLimit, 15000) : 5000;
    const parsedPage = page ? parseInt(String(page), 10) : 1;
    const currentPage = parsedPage && !isNaN(parsedPage) && parsedPage > 0 ? parsedPage : 1;
    const skip = (currentPage - 1) * take;

    const logs = await prisma.attendanceLog.findMany({
      where: whereClause,
      orderBy: { timestamp: 'desc' },
      skip,
      take
    });

    const formattedLogs = logs.map(log => ({
      id: log.id,
      workerId: log.userId,
      type: log.type,
      timestamp: log.timestamp
    }));

    if (String(paginated) === 'true') {
      const total = await prisma.attendanceLog.count({ where: whereClause });
      return res.json({
        data: formattedLogs,
        page: currentPage,
        limit: take,
        total,
        totalPages: Math.ceil(total / take)
      });
    }

    return res.json(formattedLogs);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Error al obtener asistencias' });
  }
});

app.post(
  '/api/logs',
  requireAuth,
  requireRoles(['Diamante', 'Platino', 'Piedra']),
  async (req: Request, res: Response) => {
    try {
      const authUser = req.authUser!;
      const {
        workerId,
        type,
        timestamp,
        clientLogId,
        stableRecordId,
        localRecordUid,
        allowOverride,
        isOfflineSync
      } = req.body;

      if (!workerId || !type || !['IN', 'OUT'].includes(String(type))) {
        return res.status(400).json({ error: 'Datos de escaneo inválidos' });
      }

      const cleanWorkerId = String(workerId).trim();
      const cleanType = String(type).trim() as 'IN' | 'OUT';
      const cleanClientLogId = clientLogId ? String(clientLogId).trim().slice(0, 120) : null;
      const cleanStableRecordId = stableRecordId ? String(stableRecordId).trim().slice(0, 260) : null;
      const cleanLocalRecordUid = localRecordUid ? String(localRecordUid).trim().slice(0, 160) : null;

      const worker = await prisma.user.findUnique({
        where: { id: cleanWorkerId },
        include: { tenant: true }
      });

      if (!worker) {
        return res.status(404).json({ error: 'Trabajador no encontrado para registrar asistencia' });
      }

      const workerClient = worker.saasClientId || (worker.tenant ? worker.tenant.saasClientId : null);
      if (!isDiamanteUser(authUser)) {
        if (workerClient && !canUserAccessClient(authUser, workerClient)) {
          return res.status(403).json({ error: 'No puedes registrar asistencias de un trabajador de otro cliente' });
        }
      }

      // Parsear perfil del trabajador para validar estado activo y sanciones en entradas en vivo
      let profile: Record<string, unknown> = {};
      if (worker.profileData) {
        try {
          profile = JSON.parse(worker.profileData);
        } catch {}
      }

      if (cleanType === 'IN' && !isOfflineSync) {
        const workerActive = worker.isActive !== false && profile.isActive !== false && profile.qrActive !== false;
        const companyActive = !worker.tenant || worker.tenant.isActive !== false;
        if (!workerActive || !companyActive) {
          return res.status(403).json({
            error: 'Acceso denegado: el código QR del trabajador o su empresa se encuentra inactivo'
          });
        }
        const sanctions = Array.isArray(profile.sanctions) ? profile.sanctions : [];
        if (sanctions.length >= 3) {
          return res.status(403).json({
            error: 'Acceso denegado: el trabajador acumula 3 o más sanciones'
          });
        }
      }

      // Determinar timestamp real del evento (conservando la hora original si se registró offline en caseta)
      const nowMs = Date.now();
      let eventTimestamp = new Date(nowMs);
      if (timestamp) {
        const parsedTs = new Date(String(timestamp));
        if (!isNaN(parsedTs.getTime())) {
          const tsMs = parsedTs.getTime();
          const maxFutureMs = nowMs + 5 * 60 * 1000; // Tolerancia de 5 min por reloj de dispositivo
          const minPastMs = nowMs - 30 * 24 * 60 * 60 * 1000; // Hasta 30 días de cola offline
          if (tsMs <= maxFutureMs && tsMs >= minPastMs) {
            eventTimestamp = parsedTs;
          }
        }
      }

      // 1A. Verificación de Idempotencia Exacta por Identificador Estable (stableRecordId / clientLogId)
      if (cleanStableRecordId || cleanClientLogId) {
        const priorAcks = await prisma.auditLog.findMany({
          where: { action: 'ATTENDANCE_LOG_SYNC_ACK' },
          orderBy: { createdAt: 'desc' },
          take: 500
        });
        for (const ack of priorAcks) {
          if (!ack.details || !ack.entityId) continue;
          try {
            const meta = JSON.parse(ack.details) as {
              attendanceLogId?: string;
              clientLogId?: string | null;
              stableRecordId?: string | null;
              workerId?: string;
              type?: string;
            };
            const matchedStable =
              Boolean(cleanStableRecordId) && meta.stableRecordId === cleanStableRecordId;
            const matchedClientLog =
              Boolean(cleanClientLogId) &&
              meta.clientLogId === cleanClientLogId &&
              String(meta.workerId || '').toLowerCase() === cleanWorkerId.toLowerCase() &&
              meta.type === cleanType;

            if (matchedStable || matchedClientLog) {
              const verifiedLogs = await prisma.attendanceLog.findMany({
                where: { userId: cleanWorkerId, type: cleanType }
              });
              const exactLog = verifiedLogs.find((l) => l.id === (meta.attendanceLogId || ack.entityId));
              if (exactLog) {
                return res.status(200).json({
                  ...exactLog,
                  workerId: exactLog.userId,
                  deduplicated: true,
                  confirmedByExactId: true,
                  confirmedAttendanceLogId: exactLog.id,
                  clientLogId: cleanClientLogId,
                  stableRecordId: cleanStableRecordId,
                  localRecordUid: cleanLocalRecordUid
                });
              }
            }
          } catch {}
        }
      }

      // 1B. Protección Anti-Rebote únicamente para escaneos en vivo sin override ni sincronización de cola offline con ID distinto
      if (!isOfflineSync && !allowOverride) {
        const windowStart = new Date(eventTimestamp.getTime() - 5000);
        const windowEnd = new Date(eventTimestamp.getTime() + 5000);
        const existingNearLog = await prisma.attendanceLog.findFirst({
          where: {
            userId: cleanWorkerId,
            type: cleanType,
            timestamp: {
              gte: windowStart,
              lte: windowEnd
            }
          },
          orderBy: { timestamp: 'desc' }
        });

        if (existingNearLog) {
          return res.status(200).json({
            ...existingNearLog,
            workerId: existingNearLog.userId,
            deduplicated: true,
            confirmedAttendanceLogId: existingNearLog.id,
            clientLogId: cleanClientLogId,
            stableRecordId: cleanStableRecordId
          });
        }
      }

      // 2. Verificación de secuencia coherente IN / OUT en tiempo real (con corte 06:59 AM)
      if (!allowOverride && !isOfflineSync) {
        const lastWorkerLog = await prisma.attendanceLog.findFirst({
          where: {
            userId: cleanWorkerId,
            timestamp: { lte: eventTimestamp }
          },
          orderBy: { timestamp: 'desc' }
        });

        if (lastWorkerLog && lastWorkerLog.type === cleanType) {
          const diffSeconds = (eventTimestamp.getTime() - lastWorkerLog.timestamp.getTime()) / 1000;
          // Si intenta registrar dos entradas o dos salidas idénticas en menos de 60 segundos sin override explícito, devolver el existente
          if (diffSeconds >= 0 && diffSeconds < 60) {
            return res.status(200).json({
              ...lastWorkerLog,
              workerId: lastWorkerLog.userId,
              deduplicated: true,
              confirmedAttendanceLogId: lastWorkerLog.id,
              clientLogId: cleanClientLogId,
              stableRecordId: cleanStableRecordId
            });
          }
        }
      }

      const newLog = await prisma.attendanceLog.create({
        data: {
          userId: cleanWorkerId,
          type: cleanType,
          timestamp: eventTimestamp
        }
      });

      // Registrar confirmación exacta de sincronización con los identificadores estables del registro
      await recordAuditLog({
        username: authUser.username,
        role: authUser.role,
        saasClientId: workerClient,
        action: 'ATTENDANCE_LOG_SYNC_ACK',
        entityType: 'BACKUP',
        entityId: newLog.id,
        details: JSON.stringify({
          attendanceLogId: newLog.id,
          clientLogId: cleanClientLogId,
          stableRecordId: cleanStableRecordId,
          localRecordUid: cleanLocalRecordUid,
          workerId: cleanWorkerId,
          type: cleanType,
          timestamp: eventTimestamp.toISOString()
        }),
        ipAddress: getRequestIp(req)
      });

      return res.status(201).json({
        ...newLog,
        workerId: newLog.userId,
        confirmedAttendanceLogId: newLog.id,
        clientLogId: cleanClientLogId,
        stableRecordId: cleanStableRecordId,
        localRecordUid: cleanLocalRecordUid
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: 'Error al guardar el escaneo' });
    }
  }
);

// ---------------------------------------------------
// ETAPA 2: RUTAS DE ALMACENAMIENTO CENTRALIZADO Y SEGURO DE ARCHIVOS (/api/files)
// ---------------------------------------------------
const FILE_METADATA_SELECT = {
  id: true,
  saasClientId: true,
  companyId: true,
  workerId: true,
  category: true,
  docIndex: true,
  fileName: true,
  mimeType: true,
  sizeBytes: true,
  uploadedBy: true,
  externalUrl: true,
  createdAt: true,
  updatedAt: true
} as const;

app.post(
  '/api/files',
  requireAuth,
  requireRoles(['Diamante', 'Platino', 'Piedra']),
  async (req: Request, res: Response) => {
    try {
      const authUser = req.authUser!;
      const {
        fileName,
        dataUrl,
        mimeType,
        category = 'COMPANY_DOC',
        docIndex,
        companyId,
        workerId,
        saasClientId,
        externalUrl
      } = req.body;

      const cleanCategory = String(category || 'COMPANY_DOC').trim().toUpperCase();
      if (authUser.role.toUpperCase() === 'PIEDRA') {
        if (cleanCategory !== 'VISIT_PHOTO' && cleanCategory !== 'EVENTUAL_PHOTO') {
          return res.status(403).json({ error: 'El rol Piedra solo puede cargar fotografías de visitas o eventuales' });
        }
      }

      const parsed = validateAndParseFilePayload(String(fileName || ''), String(dataUrl || ''), mimeType ? String(mimeType) : undefined);
      if (!parsed.valid) {
        return res.status(400).json({ error: parsed.error || 'Archivo inválido' });
      }

      let resolvedClientId: string | null = saasClientId && saasClientId !== 'all' ? String(saasClientId).trim() : null;
      let resolvedCompanyId: string | null = companyId ? String(companyId).trim() : null;
      const resolvedWorkerId: string | null = workerId ? String(workerId).trim() : null;

      if (resolvedWorkerId) {
        const w = await prisma.user.findUnique({
          where: { id: resolvedWorkerId },
          include: { tenant: true }
        });
        if (w) {
          resolvedCompanyId = resolvedCompanyId || w.tenantId;
          resolvedClientId = resolvedClientId || w.saasClientId || (w.tenant ? w.tenant.saasClientId : null);
        }
      }

      if (resolvedCompanyId && !resolvedClientId) {
        const comp = await prisma.tenant.findUnique({ where: { id: resolvedCompanyId } });
        if (comp) {
          resolvedClientId = comp.saasClientId || null;
        }
      }

      if (!isDiamanteUser(authUser)) {
        if (!resolvedClientId) {
          resolvedClientId = authUser.clientIds[0] || null;
        }
        if (!resolvedClientId || !canUserAccessClient(authUser, resolvedClientId)) {
          return res.status(403).json({ error: 'No tienes permiso para subir archivos en este cliente' });
        }
      }

      const parsedDocIndex =
        docIndex !== undefined && docIndex !== null && !Number.isNaN(parseInt(String(docIndex), 10))
          ? parseInt(String(docIndex), 10)
          : null;

      const createdFile = await prisma.storedFile.create({
        data: {
          saasClientId: resolvedClientId,
          companyId: resolvedCompanyId,
          workerId: resolvedWorkerId,
          category: cleanCategory,
          docIndex: parsedDocIndex,
          fileName: parsed.cleanFileName,
          mimeType: parsed.mimeType,
          sizeBytes: parsed.sizeBytes,
          uploadedBy: authUser.username,
          externalUrl: externalUrl ? String(externalUrl) : null,
          contentData: parsed.normalizedDataUrl
        },
        select: FILE_METADATA_SELECT
      });

      await recordAuditLog({
        username: authUser.username,
        role: authUser.role,
        saasClientId: resolvedClientId,
        action: 'FILE_UPLOAD',
        entityType: 'DOCUMENT',
        entityId: createdFile.id,
        details: `Carga de archivo "${createdFile.fileName}" (${Math.round(createdFile.sizeBytes / 1024)} KB, ${cleanCategory})`,
        ipAddress: getRequestIp(req)
      });

      return res.status(201).json({
        success: true,
        file: createdFile
      });
    } catch (error) {
      console.error('Error uploading file:', error);
      return res.status(500).json({ error: 'Error al almacenar el archivo en el servidor' });
    }
  }
);

app.get('/api/files', requireAuth, async (req: Request, res: Response) => {
  try {
    const authUser = req.authUser!;
    const { saasClientId, companyId, workerId, category } = req.query;
    const whereClause: Record<string, unknown> = {};

    if (companyId) whereClause.companyId = String(companyId);
    if (workerId) whereClause.workerId = String(workerId);
    if (category) whereClause.category = String(category).toUpperCase();

    if (isDiamanteUser(authUser)) {
      if (saasClientId && saasClientId !== 'all') {
        whereClause.saasClientId = String(saasClientId);
      }
    } else {
      if (authUser.clientIds.length === 0) {
        return res.json([]);
      }
      if (saasClientId && saasClientId !== 'all') {
        if (!canUserAccessClient(authUser, String(saasClientId))) {
          return res.status(403).json({ error: 'No tienes permiso para consultar archivos de este cliente' });
        }
        whereClause.saasClientId = String(saasClientId);
      } else {
        whereClause.saasClientId = { in: authUser.clientIds };
      }

      if (authUser.role.toUpperCase() === 'COBRE' && authUser.companyIds.length > 0) {
        whereClause.companyId = { in: authUser.companyIds };
      }
    }

    const files = await prisma.storedFile.findMany({
      where: whereClause,
      select: FILE_METADATA_SELECT,
      orderBy: { createdAt: 'desc' },
      take: 1000
    });

    return res.json(files);
  } catch (error) {
    console.error('Error listing files:', error);
    return res.status(500).json({ error: 'Error al consultar metadatos de archivos' });
  }
});

app.get('/api/files/:id', requireAuth, async (req: Request, res: Response) => {
  try {
    const authUser = req.authUser!;
    const id = String(req.params.id || '').trim();
    if (!id) {
      return res.status(400).json({ error: 'ID de archivo requerido' });
    }

    const stored = await prisma.storedFile.findUnique({ where: { id } });
    if (!stored) {
      return res.status(404).json({ error: 'Archivo no encontrado' });
    }

    if (!isDiamanteUser(authUser)) {
      if (stored.saasClientId && !canUserAccessClient(authUser, stored.saasClientId)) {
        return res.status(403).json({ error: 'No tienes permiso para acceder a un archivo de otro cliente' });
      }
      if (authUser.role.toUpperCase() === 'COBRE' && authUser.companyIds.length > 0) {
        if (stored.companyId && !authUser.companyIds.includes(stored.companyId)) {
          return res.status(403).json({ error: 'No tienes permiso para acceder a archivos de otra empresa' });
        }
      }
    }

    if (req.query.format === 'json') {
      return res.json({
        id: stored.id,
        fileName: stored.fileName,
        mimeType: stored.mimeType,
        sizeBytes: stored.sizeBytes,
        dataUrl: stored.contentData,
        externalUrl: stored.externalUrl,
        createdAt: stored.createdAt
      });
    }

    const rawContent = stored.contentData || '';
    const commaIdx = rawContent.indexOf(',');
    const base64Data = commaIdx >= 0 ? rawContent.slice(commaIdx + 1) : rawContent;
    const fileBuffer = Buffer.from(base64Data, 'base64');

    const dispositionType = req.query.download === '1' ? 'attachment' : 'inline';
    const safeDownloadName = encodeURIComponent(stored.fileName || 'documento');

    res.setHeader('Content-Type', stored.mimeType || 'application/octet-stream');
    res.setHeader('Content-Length', String(fileBuffer.length));
    res.setHeader('Cache-Control', 'private, max-age=3600');
    res.setHeader('Content-Disposition', `${dispositionType}; filename="${safeDownloadName}"; filename*=UTF-8''${safeDownloadName}`);
    return res.send(fileBuffer);
  } catch (error) {
    console.error('Error serving file:', error);
    return res.status(500).json({ error: 'Error al descargar el archivo' });
  }
});

app.delete(
  '/api/files/:id',
  requireAuth,
  requireRoles(['Diamante', 'Platino']),
  async (req: Request, res: Response) => {
    try {
      const authUser = req.authUser!;
      const id = String(req.params.id || '').trim();
      const existing = await prisma.storedFile.findUnique({
        where: { id },
        select: FILE_METADATA_SELECT
      });
      if (!existing) {
        return res.status(404).json({ error: 'Archivo no encontrado' });
      }
      if (!isDiamanteUser(authUser) && existing.saasClientId && !canUserAccessClient(authUser, existing.saasClientId)) {
        return res.status(403).json({ error: 'No tienes permiso para eliminar archivos de otro cliente' });
      }
      await prisma.storedFile.delete({ where: { id } });
      await recordAuditLog({
        username: authUser.username,
        role: authUser.role,
        saasClientId: existing.saasClientId,
        action: 'FILE_DELETE',
        entityType: 'DOCUMENT',
        entityId: id,
        details: `Eliminación de archivo "${existing.fileName}"`,
        ipAddress: getRequestIp(req)
      });
      return res.json({ success: true });
    } catch (error) {
      console.error('Error deleting file:', error);
      return res.status(500).json({ error: 'Error al eliminar el archivo' });
    }
  }
);

// ---------------------------------------------------
// RUTAS PARA USUARIOS DE PLATAFORMA (SaaS) — EXCLUSIVO DIAMANTE
// ---------------------------------------------------
app.get(
  '/api/platform-users',
  requireAuth,
  requireRoles(['Diamante']),
  async (_req: Request, res: Response) => {
    try {
      const users = await prisma.platformUser.findMany({
        orderBy: { createdAt: 'desc' }
      });
      // Jamás devolver el campo password en las respuestas de la API
      return res.json(users.map(sanitizePlatformUser));
    } catch (error) {
      return res.status(500).json({ error: 'Error al obtener usuarios de plataforma' });
    }
  }
);

app.post(
  '/api/platform-users',
  requireAuth,
  requireRoles(['Diamante']),
  async (req: Request, res: Response) => {
    try {
      const authUser = req.authUser!;
      const { username, password, role, clientId } = req.body;
      if (!username || !password || !role) {
        return res.status(400).json({ error: 'Faltan datos obligatorios' });
      }

      // ETAPA 6: Validar límite de cuentas de usuario asignadas por cliente SaaS
      if (String(role).trim().toUpperCase() !== 'DIAMANTE' && clientId) {
        const targetClientIds = parseClientAndCompany(String(clientId)).clientIds;
        if (targetClientIds.length > 0) {
          const [clientsMap, allPlatformUsers] = await Promise.all([
            getSaasClientsConfigMap(),
            prisma.platformUser.findMany()
          ]);
          for (const cid of targetClientIds) {
            const cfg = clientsMap.get(cid);
            const maxUsers = cfg ? Number(cfg.maxUsers) || 0 : 0;
            if (maxUsers > 0) {
              const currentUsersForClient = allPlatformUsers.filter(u =>
                parseClientAndCompany(u.clientId).clientIds.includes(cid)
              ).length;
              if (currentUsersForClient >= maxUsers) {
                return res.status(403).json({
                  error: `Límite comercial alcanzado para el cliente "${cfg?.name || cid}": máximo ${maxUsers} cuenta(s) de usuario permitidas en su plan.`
                });
              }
            }
          }
        }
      }
      const hashedPassword = hashPassword(String(password));
      const newUser = await prisma.platformUser.create({
        data: {
          username: String(username).trim(),
          password: hashedPassword,
          role: String(role).trim(),
          clientId: clientId || null
        }
      });

      await recordAuditLog({
        username: authUser.username,
        role: authUser.role,
        saasClientId: parseClientAndCompany(newUser.clientId).clientIds[0] || null,
        action: 'USER_CREATE',
        entityType: 'USER',
        entityId: newUser.id,
        details: `Creación de cuenta de acceso "${newUser.username}" con rol ${newUser.role}`,
        ipAddress: getRequestIp(req)
      });

      return res.status(201).json(sanitizePlatformUser(newUser));
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: 'Error al crear usuario de plataforma' });
    }
  }
);

app.put(
  '/api/platform-users/:id',
  requireAuth,
  requireRoles(['Diamante']),
  async (req: Request, res: Response) => {
    try {
      const authUser = req.authUser!;
      const id = String(req.params.id || '');
      const { username, password, role, clientId } = req.body;

      const existing = await prisma.platformUser.findUnique({ where: { id } });
      if (!existing) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      const dataToUpdate: {
        username: string;
        role: string;
        clientId: string | null;
        password?: string;
      } = {
        username: username ? String(username).trim() : existing.username,
        role: role ? String(role).trim() : existing.role,
        clientId: clientId !== undefined ? (clientId || null) : existing.clientId
      };

      // Solo actualizar la contraseña si se proporcionó una nueva (no vacía)
      const passwordWasChanged = Boolean(password && String(password).trim() !== '');
      if (passwordWasChanged) {
        dataToUpdate.password = hashPassword(String(password));
      }

      const updatedUser = await prisma.platformUser.update({
        where: { id },
        data: dataToUpdate
      });

      await recordAuditLog({
        username: authUser.username,
        role: authUser.role,
        saasClientId: parseClientAndCompany(updatedUser.clientId).clientIds[0] || null,
        action: 'USER_UPDATE',
        entityType: 'USER',
        entityId: updatedUser.id,
        details: `Actualización de cuenta "${updatedUser.username}" (rol: ${updatedUser.role}${passwordWasChanged ? ', contraseña restablecida' : ''})`,
        ipAddress: getRequestIp(req)
      });

      return res.json(sanitizePlatformUser(updatedUser));
    } catch (error) {
      return res.status(500).json({ error: 'Error al actualizar usuario' });
    }
  }
);

app.delete(
  '/api/platform-users/:id',
  requireAuth,
  requireRoles(['Diamante']),
  async (req: Request, res: Response) => {
    try {
      const authUser = req.authUser!;
      const id = String(req.params.id || '');
      const existing = await prisma.platformUser.findUnique({ where: { id } });
      await prisma.platformUser.delete({ where: { id } });

      await recordAuditLog({
        username: authUser.username,
        role: authUser.role,
        saasClientId: existing ? parseClientAndCompany(existing.clientId).clientIds[0] || null : null,
        action: 'USER_DELETE',
        entityType: 'USER',
        entityId: id,
        details: `Eliminación de cuenta de acceso "${existing ? existing.username : id}"`,
        ipAddress: getRequestIp(req)
      });

      return res.json({ success: true });
    } catch (error) {
      return res.status(500).json({ error: 'Error al eliminar usuario' });
    }
  }
);

// ---------------------------------------------------
// ETAPA 4: BITÁCORA DE AUDITORÍA, MONITOREO Y RESPALDOS AUTOMÁTICOS
// ---------------------------------------------------
app.get(
  '/api/audit-logs',
  requireAuth,
  requireRoles(['Diamante', 'Platino']),
  async (req: Request, res: Response) => {
    try {
      const authUser = req.authUser!;
      const { saasClientId, action, entityType, username, from, to, limit } = req.query;
      const whereClause: Record<string, unknown> = {};

      if (action && action !== 'all') whereClause.action = String(action);
      if (entityType && entityType !== 'all') whereClause.entityType = String(entityType);
      if (username) whereClause.username = { contains: String(username).trim(), mode: 'insensitive' };

      if (from || to) {
        const createdAtFilter: Record<string, Date> = {};
        if (from) {
          const d = new Date(String(from).length === 10 ? `${from}T00:00:00.000Z` : String(from));
          if (!isNaN(d.getTime())) createdAtFilter.gte = d;
        }
        if (to) {
          const d = new Date(String(to).length === 10 ? `${to}T23:59:59.999Z` : String(to));
          if (!isNaN(d.getTime())) createdAtFilter.lte = d;
        }
        if (Object.keys(createdAtFilter).length > 0) {
          whereClause.createdAt = createdAtFilter;
        }
      }

      if (isDiamanteUser(authUser)) {
        if (saasClientId && saasClientId !== 'all') {
          whereClause.saasClientId = String(saasClientId);
        }
      } else {
        if (authUser.clientIds.length === 0) return res.json([]);
        if (saasClientId && saasClientId !== 'all') {
          if (!canUserAccessClient(authUser, String(saasClientId))) {
            return res.status(403).json({ error: 'No tienes permiso para consultar la bitácora de otro cliente' });
          }
          whereClause.saasClientId = String(saasClientId);
        } else {
          whereClause.saasClientId = { in: authUser.clientIds };
        }
      }

      const parsedLimit = limit ? parseInt(String(limit), 10) : 300;
      const take = parsedLimit && !isNaN(parsedLimit) && parsedLimit > 0 ? Math.min(parsedLimit, 2000) : 300;

      const auditLogs = await prisma.auditLog.findMany({
        where: whereClause,
        orderBy: { createdAt: 'desc' },
        take
      });

      return res.json(auditLogs);
    } catch (error) {
      console.error('Error fetching audit logs:', error);
      return res.status(500).json({ error: 'Error al consultar la bitácora de auditoría' });
    }
  }
);

app.post('/api/audit-logs/client-error', requireAuth, async (req: Request, res: Response) => {
  try {
    const authUser = req.authUser!;
    const { message, context, saasClientId } = req.body;
    await recordAuditLog({
      username: authUser.username,
      role: authUser.role,
      saasClientId: saasClientId ? String(saasClientId) : (authUser.clientIds[0] || null),
      action: 'CLIENT_ERROR',
      entityType: 'SYSTEM',
      details: `${String(context || 'Frontend')}: ${String(message || 'Error no especificado').slice(0, 500)}`,
      ipAddress: getRequestIp(req)
    });
    return res.json({ success: true });
  } catch {
    return res.status(500).json({ error: 'Error al registrar incidente' });
  }
});

async function createSystemBackupSnapshot(
  triggerType: 'AUTO_DAILY' | 'MANUAL',
  createdBy: string,
  saasClientId: string | null = null
) {
  const [companies, workers, platformUsers, filesMetadata, totalAttendanceLogs] = await Promise.all([
    prisma.tenant.findMany({ orderBy: { createdAt: 'desc' } }),
    prisma.user.findMany({ orderBy: { createdAt: 'desc' } }),
    prisma.platformUser.findMany({ orderBy: { createdAt: 'desc' } }),
    prisma.storedFile.findMany({ select: FILE_METADATA_SELECT, orderBy: { createdAt: 'desc' } }),
    prisma.attendanceLog.count()
  ]);

  const sanitizedUsers = platformUsers.map(sanitizePlatformUser);
  const stats = {
    companiesCount: companies.length,
    workersCount: workers.length,
    platformUsersCount: sanitizedUsers.length,
    storedFilesCount: filesMetadata.length,
    totalAttendanceLogs
  };

  const snapshotPayload = {
    version: '1.4.0',
    createdAt: new Date().toISOString(),
    triggerType,
    createdBy,
    stats,
    companies,
    workers,
    platformUsers: sanitizedUsers,
    filesMetadata
  };

  const created = await prisma.systemBackupSnapshot.create({
    data: {
      saasClientId,
      triggerType,
      createdBy,
      statsJson: JSON.stringify(stats),
      snapshotData: JSON.stringify(snapshotPayload)
    },
    select: {
      id: true,
      saasClientId: true,
      triggerType: true,
      createdBy: true,
      statsJson: true,
      createdAt: true
    }
  });

  // Mantener solamente los últimos 15 respaldos automáticos para optimizar almacenamiento
  try {
    const oldAutoBackups = await prisma.systemBackupSnapshot.findMany({
      where: { triggerType: 'AUTO_DAILY' },
      orderBy: { createdAt: 'desc' },
      skip: 15,
      select: { id: true }
    });
    if (oldAutoBackups.length > 0) {
      await prisma.systemBackupSnapshot.deleteMany({
        where: { id: { in: oldAutoBackups.map(b => b.id) } }
      });
    }
  } catch {}

  return created;
}

async function runAutomaticDailyBackupIfNeeded() {
  try {
    const twentyHoursAgo = new Date(Date.now() - 20 * 60 * 60 * 1000);
    const recentAuto = await prisma.systemBackupSnapshot.findFirst({
      where: {
        triggerType: 'AUTO_DAILY',
        createdAt: { gte: twentyHoursAgo }
      },
      orderBy: { createdAt: 'desc' },
      select: { id: true, createdAt: true }
    });

    if (!recentAuto) {
      const snap = await createSystemBackupSnapshot('AUTO_DAILY', 'Sistema (Automático)');
      await recordAuditLog({
        username: 'Sistema',
        role: 'Sistema',
        action: 'BACKUP_AUTO_DAILY',
        entityType: 'BACKUP',
        entityId: snap.id,
        details: `Respaldo automático diario generado exitosamente (${snap.statsJson})`
      });
      console.log(`[backup]: Respaldo automático diario creado (${snap.id}).`);
    }
  } catch (err) {
    console.warn('[backup]: Aviso al verificar respaldo automático diario:', err);
  }
}

app.get(
  '/api/backups/snapshots',
  requireAuth,
  requireRoles(['Diamante']),
  async (_req: Request, res: Response) => {
    try {
      const snapshots = await prisma.systemBackupSnapshot.findMany({
        where: { triggerType: { in: ['AUTO_DAILY', 'MANUAL'] } },
        orderBy: { createdAt: 'desc' },
        take: 30,
        select: {
          id: true,
          saasClientId: true,
          triggerType: true,
          createdBy: true,
          statsJson: true,
          createdAt: true
        }
      });
      return res.json(snapshots);
    } catch (error) {
      return res.status(500).json({ error: 'Error al consultar historial de respaldos' });
    }
  }
);

app.post(
  '/api/backups/snapshots',
  requireAuth,
  requireRoles(['Diamante']),
  async (req: Request, res: Response) => {
    try {
      const authUser = req.authUser!;
      const snapshot = await createSystemBackupSnapshot('MANUAL', authUser.username);
      await recordAuditLog({
        username: authUser.username,
        role: authUser.role,
        action: 'BACKUP_CREATE_SNAPSHOT',
        entityType: 'BACKUP',
        entityId: snapshot.id,
        details: `Punto de respaldo manual creado en el servidor (${snapshot.statsJson})`,
        ipAddress: getRequestIp(req)
      });
      return res.status(201).json(snapshot);
    } catch (error) {
      console.error('Error creating backup snapshot:', error);
      return res.status(500).json({ error: 'Error al crear punto de respaldo' });
    }
  }
);

app.get(
  '/api/backups/snapshots/:id',
  requireAuth,
  requireRoles(['Diamante']),
  async (req: Request, res: Response) => {
    try {
      const id = String(req.params.id || '').trim();
      const snapshot = await prisma.systemBackupSnapshot.findUnique({ where: { id } });
      if (!snapshot) {
        return res.status(404).json({ error: 'Punto de respaldo no encontrado' });
      }
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="Snapshot_${snapshot.id.slice(0, 8)}_${snapshot.createdAt.toISOString().split('T')[0]}.json"`);
      return res.send(snapshot.snapshotData);
    } catch (error) {
      return res.status(500).json({ error: 'Error al descargar punto de respaldo' });
    }
  }
);

// ---------------------------------------------------
// ETAPA 6: MÉTRICAS COMERCIALES DE USO POR CLIENTE SAAS (Exclusivo Diamante)
// ---------------------------------------------------
app.get(
  '/api/saas/usage-metrics',
  requireAuth,
  requireRoles(['Diamante']),
  async (_req: Request, res: Response) => {
    try {
      const [allTenants, allWorkers, allPlatformUsers, allFiles] = await Promise.all([
        prisma.tenant.findMany({
          select: { id: true, name: true, saasClientId: true }
        }),
        prisma.user.findMany({
          select: { id: true, name: true, saasClientId: true, tenantId: true, profileData: true }
        }),
        prisma.platformUser.findMany({
          select: { id: true, username: true, role: true, clientId: true }
        }),
        prisma.storedFile
          .findMany({
            select: { id: true, saasClientId: true, sizeBytes: true }
          })
          .catch(() => [])
      ]);

      const metricsByClient: Record<
        string,
        {
          companiesCount: number;
          workersCount: number;
          usersCount: number;
          filesCount: number;
          storageBytes: number;
        }
      > = {};

      const ensureBucket = (cid: string) => {
        if (!metricsByClient[cid]) {
          metricsByClient[cid] = {
            companiesCount: 0,
            workersCount: 0,
            usersCount: 0,
            filesCount: 0,
            storageBytes: 0
          };
        }
        return metricsByClient[cid];
      };

      const tenantClientMap = new Map<string, string>();
      const sysTenantIds = new Set<string>();
      for (const t of allTenants) {
        if (t.saasClientId) tenantClientMap.set(t.id, t.saasClientId);
        if (
          t.name === '[VISITAS_SYSTEM]' ||
          t.name === '[EVENTUALES_SYSTEM]' ||
          t.name === '[CLIENTS_SYSTEM]' ||
          t.name.startsWith('[EVENTUAL] ')
        ) {
          sysTenantIds.add(t.id);
          continue;
        }
        if (t.saasClientId && t.saasClientId !== '__SYS_CLIENTS__') {
          ensureBucket(t.saasClientId).companiesCount++;
        }
      }

      for (const w of allWorkers) {
        if (w.name === 'Visita Eventual' || sysTenantIds.has(w.tenantId)) continue;
        let isVisit = false;
        if (w.profileData) {
          try {
            const p = JSON.parse(w.profileData);
            if (p.position === 'Visita' || (Array.isArray(p.docs) && p.docs.includes('Visita'))) {
              isVisit = true;
            }
          } catch {}
        }
        if (isVisit) continue;
        const cid = w.saasClientId || tenantClientMap.get(w.tenantId);
        if (cid && cid !== '__SYS_CLIENTS__') {
          ensureBucket(cid).workersCount++;
        }
      }

      for (const u of allPlatformUsers) {
        const cids = parseClientAndCompany(u.clientId).clientIds;
        for (const cid of cids) {
          if (cid) ensureBucket(cid).usersCount++;
        }
      }

      for (const f of allFiles) {
        if (f.saasClientId) {
          const b = ensureBucket(f.saasClientId);
          b.filesCount++;
          b.storageBytes += Number(f.sizeBytes) || 0;
        }
      }

      return res.json({
        generatedAt: new Date().toISOString(),
        metricsByClient
      });
    } catch (error) {
      console.error('Error computing SaaS usage metrics:', error);
      return res.status(500).json({ error: 'Error al calcular métricas comerciales de uso' });
    }
  }
);

// ---------------------------------------------------
// RESPALDO COMPLETO DEL SISTEMA (Exclusivo Usuario Diamante)
// ---------------------------------------------------
app.get(
  '/api/backup',
  requireAuth,
  requireRoles(['Diamante']),
  async (req: Request, res: Response) => {
    try {
      const authUser = req.authUser!;
      const [companies, workers, logs, platformUsers, filesMetadata, recentAuditLogs] = await Promise.all([
        prisma.tenant.findMany({ orderBy: { createdAt: 'desc' } }),
        prisma.user.findMany({ orderBy: { createdAt: 'desc' } }),
        prisma.attendanceLog.findMany({ orderBy: { timestamp: 'desc' }, take: 25000 }),
        prisma.platformUser.findMany({ orderBy: { createdAt: 'desc' } }),
        prisma.storedFile.findMany({ select: FILE_METADATA_SELECT, orderBy: { createdAt: 'desc' } }).catch(() => []),
        prisma.auditLog.findMany({ orderBy: { createdAt: 'desc' }, take: 500 }).catch(() => [])
      ]);

      await recordAuditLog({
        username: authUser.username,
        role: authUser.role,
        action: 'BACKUP_EXPORT',
        entityType: 'BACKUP',
        details: `Descarga de respaldo completo (${companies.length} empresas, ${workers.length} trabajadores, ${filesMetadata.length} archivos)`,
        ipAddress: getRequestIp(req)
      });

      return res.json({
        exportedAt: new Date().toISOString(),
        version: '1.4.0',
        companies,
        workers,
        attendanceLogs: logs,
        logs,
        platformUsers: platformUsers.map(sanitizePlatformUser),
        filesMetadata,
        auditLogs: recentAuditLogs
      });
    } catch (error) {
      return res.status(500).json({ error: 'Error al generar respaldo del servidor' });
    }
  }
);

// Monitoreo de errores críticos no controlados en el proceso Node.js
process.on('unhandledRejection', (reason) => {
  console.error('[monitor]: Unhandled Rejection:', reason);
  recordAuditLog({
    username: 'Sistema',
    role: 'Sistema',
    action: 'SYSTEM_ERROR',
    entityType: 'SYSTEM',
    details: `UnhandledRejection: ${reason instanceof Error ? reason.message : String(reason)}`
  });
});

process.on('uncaughtException', (err) => {
  console.error('[monitor]: Uncaught Exception:', err);
  recordAuditLog({
    username: 'Sistema',
    role: 'Sistema',
    action: 'SYSTEM_ERROR',
    entityType: 'SYSTEM',
    details: `UncaughtException: ${err.message}`
  });
});

// ===================================================
// ETAPA 0 (PROTOTIPO LOCAL): PROTECCIÓN DE COLAS OFFLINE E INVENTARIO DE DISPOSITIVOS
// Almacenamiento prototipo en SystemBackupSnapshot (triggerType = 'DEVICE_OFFLINE_QUEUE')
// Sin ventana de gracia de 30 días aprobada: exige sesión activa + validación en vivo en PlatformUser.
// Sin borrado automático de registros, cachés ni respaldos.
// ===================================================

const STAGE0_TRIGGER_TYPE = 'DEVICE_OFFLINE_QUEUE';
const STAGE0_MAX_BATCH_SIZE = 200;
const STAGE0_MAX_RECORDS_PER_DEVICE = 1000;
const STAGE0_MAX_GLOBAL_RECORDS = 5000;
const STAGE0_MAX_GLOBAL_BYTES = 1536 * 1024; // 1.5 MB límite de protección en PostgreSQL

interface Stage0IncomingRecord {
  localRecordUid: string;
  stableRecordId: string;
  originalId?: string | null;
  workerId: string;
  type: 'IN' | 'OUT';
  timestamp: string;
  syncState: 'PENDING' | 'QUARANTINED_PENDING_RESOLUTION' | 'RESOLVED_ADMIN';
  lastRejectStatus?: number | null;
  lastRejectError?: string | null;
  quarantinedAt?: string | null;
}

interface Stage0StoredRecord extends Stage0IncomingRecord {
  firstBackedUpAt: string;
  lastSeenAt: string;
  reportedByUserId: string;
  reportedByUsername: string;
  saasClientId: string;
  deviceId: string;
  adminResolution?: {
    status: 'RESOLVED_ADMIN_APPROVED' | 'RESOLVED_ADMIN_DISMISSED';
    resolvedBy: string;
    resolvedAt: string;
    notes: string;
    insertedAttendanceLogId?: string | null;
  } | null;
}

interface Stage0IdbOrphanDiagnosticItem {
  entityType: 'COMPANY' | 'COMPANY_HISTORY' | 'WORKER';
  entityId: string;
  docIndex: number;
  fileRef: string;
  fileName: string;
  hasLocalCopyInIdb: boolean;
}

interface Stage0DeviceSnapshotPayload {
  schemaVersion: 'stage0-v1';
  deviceId: string;
  saasClientId: string;
  platformUserId: string;
  username: string;
  role: string;
  firstReportedAt: string;
  lastReportedAt: string;
  lastSessionJti: string;
  userAgentSummary: string;
  recordsByStableId: Record<string, Stage0StoredRecord>;
  idbDiagnosticSummary: {
    idbChecked: boolean;
    idbStatus: string;
    totalDocFilesInIdb: number;
    totalDocfileKeysInLocalStorage: number;
    orphanReferencesWithLocalCopyCount: number;
    orphanReferencesMetadata: Stage0IdbOrphanDiagnosticItem[];
  };
}

export function computeStage0CanonicalSha256(
  records: Array<{
    stableRecordId: string;
    workerId: string;
    type: string;
    timestamp: string;
    syncState: string;
  }>
): string {
  const canonicalLines = records.map((r) => {
    const cleanStableId = String(r.stableRecordId || '').trim();
    const cleanWorkerId = String(r.workerId || '').trim().toLowerCase();
    const cleanType = String(r.type || '').trim().toUpperCase();
    const isoTime = new Date(r.timestamp).toISOString();
    const cleanState = String(r.syncState || 'PENDING').trim().toUpperCase();
    return `${cleanStableId}|${cleanWorkerId}|${cleanType}|${isoTime}|${cleanState}`;
  });
  canonicalLines.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const canonicalJoined = canonicalLines.join('\n');
  return crypto.createHash('sha256').update(canonicalJoined, 'utf8').digest('hex');
}

let stage0WriteMutexChain: Promise<unknown> = Promise.resolve();

function withStage0ServerWriteLock<T>(fn: () => Promise<T>): Promise<T> {
  const prev = stage0WriteMutexChain;
  let release!: () => void;
  stage0WriteMutexChain = new Promise<void>((r) => {
    release = r;
  });
  return prev
    .catch(() => {})
    .then(() => fn())
    .finally(() => release());
}

async function requireStage0LiveAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const token = extractTokenFromRequest(req);
  const tokenUser = verifySessionToken(token);
  if (!tokenUser) {
    res.status(401).json({
      error: 'Sesión no válida o expirada. Se requiere autenticación activa para respaldar la cola del dispositivo.'
    });
    return;
  }

  try {
    // Validación estricta en vivo contra PlatformUser (detecta cuentas eliminadas/desactivadas y cambios de rol/cliente)
    let dbUser = await prisma.platformUser.findUnique({ where: { id: tokenUser.id } });
    if (!dbUser && tokenUser.username) {
      dbUser = await prisma.platformUser.findUnique({ where: { username: tokenUser.username } });
    }
    if (!dbUser) {
      res.status(401).json({
        error: 'La cuenta asociada a esta sesión ya no existe o fue revocada en el servidor.'
      });
      return;
    }

    const { clientIds, companyIds } = parseClientAndCompanyIds(dbUser.clientId);
    const liveAuthUser: AuthenticatedUser = {
      jti: tokenUser.jti,
      id: dbUser.id,
      username: dbUser.username,
      role: dbUser.role.trim(),
      rawClientId: dbUser.clientId || null,
      clientIds,
      companyIds
    };

    req.authUser = liveAuthUser;
    trackActiveSessionPassively(req, liveAuthUser);
    next();
  } catch (err) {
    res.status(500).json({ error: 'Error al verificar estado de la cuenta en el servidor' });
  }
}

app.post(
  '/api/device-protection/snapshot',
  requireStage0LiveAuth,
  async (req: Request, res: Response) => {
    try {
      const liveUser = req.authUser!;
      const body = req.body || {};

      // Rechazar cualquier intento de enviar contraseñas, tokens o secretos dentro del cuerpo del respaldo
      const forbiddenKeys = ['password', 'token', 'authToken', 'jwt', 'secret', 'dosprados_auth_token', 'dosprados_session_backup'];
      for (const fk of forbiddenKeys) {
        if (Object.prototype.hasOwnProperty.call(body, fk)) {
          return res.status(400).json({ error: `Campo sensible no permitido en respaldo: ${fk}` });
        }
      }

      const rawDeviceId = typeof body.deviceId === 'string' ? body.deviceId.trim() : '';
      if (!rawDeviceId || !/^[a-zA-Z0-9_-]{8,96}$/.test(rawDeviceId)) {
        return res.status(400).json({ error: 'Identificador de dispositivo (deviceId) inválido' });
      }

      const requestedClientId = typeof body.saasClientId === 'string' ? body.saasClientId.trim() : '';
      let effectiveClientScope = '';
      if (isDiamanteUser(liveUser)) {
        effectiveClientScope = requestedClientId && requestedClientId !== 'all' ? requestedClientId : 'GLOBAL_DIAMANTE';
      } else {
        if (liveUser.clientIds.length === 0) {
          return res.status(403).json({ error: 'La cuenta no tiene proyectos SaaS asignados actualmente' });
        }
        if (requestedClientId && requestedClientId !== 'all') {
          if (!canUserAccessClient(liveUser, requestedClientId)) {
            return res.status(403).json({
              error: 'Permiso revocado o insuficiente para respaldar datos en el proyecto solicitado'
            });
          }
          effectiveClientScope = requestedClientId;
        } else {
          effectiveClientScope = liveUser.clientIds[0]!;
        }
      }

      if (!Array.isArray(body.records)) {
        return res.status(400).json({ error: 'El campo records debe ser un arreglo' });
      }
      if (body.records.length > STAGE0_MAX_BATCH_SIZE) {
        return res.status(400).json({
          error: `El lote supera el máximo de ${STAGE0_MAX_BATCH_SIZE} registros por petición. Envíe en lotes paginados.`
        });
      }

      const clientCanonicalSha256 = typeof body.canonicalSha256 === 'string' ? body.canonicalSha256.trim().toLowerCase() : '';
      if (!/^[a-f0-9]{64}$/.test(clientCanonicalSha256)) {
        return res.status(400).json({ error: 'Se requiere canonicalSha256 válido de 64 caracteres hexadecimales' });
      }

      const expectedPrefix = `${effectiveClientScope}::${rawDeviceId}::`;
      const sanitizedBatch: Stage0IncomingRecord[] = [];
      const seenBatchStableIds = new Set<string>();

      for (const rawRec of body.records) {
        if (!rawRec || typeof rawRec !== 'object') {
          return res.status(400).json({ error: 'Registro de cola malformado' });
        }
        const localRecordUid = String(rawRec.localRecordUid || '').trim();
        const stableRecordId = String(rawRec.stableRecordId || '').trim();
        const workerId = String(rawRec.workerId || '').trim();
        const typeStr = String(rawRec.type || '').trim().toUpperCase();
        const rawTimestamp = String(rawRec.timestamp || '').trim();
        const parsedTime = new Date(rawTimestamp);

        if (!localRecordUid || localRecordUid.length > 160) {
          return res.status(400).json({ error: 'localRecordUid inválido o ausente' });
        }
        if (stableRecordId !== `${expectedPrefix}${localRecordUid}`) {
          return res.status(400).json({
            error: `stableRecordId (${stableRecordId}) no coincide con el prefijo de aislamiento esperado (${expectedPrefix})`
          });
        }
        if (seenBatchStableIds.has(stableRecordId)) {
          return res.status(400).json({
            error: `Colisión detectada en el mismo lote para stableRecordId: ${stableRecordId}`
          });
        }
        seenBatchStableIds.add(stableRecordId);

        if (!workerId || (typeStr !== 'IN' && typeStr !== 'OUT') || Number.isNaN(parsedTime.getTime())) {
          return res.status(400).json({ error: `Datos de asistencia inválidos en ${stableRecordId}` });
        }

        const rawSyncState = String(rawRec.syncState || 'PENDING').trim().toUpperCase();
        const syncState: Stage0IncomingRecord['syncState'] =
          rawSyncState === 'QUARANTINED_PENDING_RESOLUTION'
            ? 'QUARANTINED_PENDING_RESOLUTION'
            : rawSyncState === 'RESOLVED_ADMIN'
              ? 'RESOLVED_ADMIN'
              : 'PENDING';

        sanitizedBatch.push({
          localRecordUid,
          stableRecordId,
          originalId: rawRec.originalId ? String(rawRec.originalId).trim().slice(0, 120) : null,
          workerId,
          type: typeStr as 'IN' | 'OUT',
          timestamp: parsedTime.toISOString(),
          syncState,
          lastRejectStatus:
            typeof rawRec.lastRejectStatus === 'number' ? Number(rawRec.lastRejectStatus) : null,
          lastRejectError:
            typeof rawRec.lastRejectError === 'string' ? rawRec.lastRejectError.slice(0, 300) : null,
          quarantinedAt:
            typeof rawRec.quarantinedAt === 'string' && !Number.isNaN(new Date(rawRec.quarantinedAt).getTime())
              ? new Date(rawRec.quarantinedAt).toISOString()
              : null
        });
      }

      // Verificar aislamiento multi-tenant por workerId: impedir que un teléfono que cambió de cuenta/proyecto
      // mezcle registros de trabajadores de otro cliente SaaS en el alcance actual
      if (effectiveClientScope !== 'GLOBAL_DIAMANTE' && sanitizedBatch.length > 0) {
        const distinctWorkerIds = Array.from(new Set(sanitizedBatch.map((r) => r.workerId)));
        for (const wId of distinctWorkerIds) {
          const workerRow = await prisma.user.findUnique({
            where: { id: wId },
            include: { tenant: true }
          });
          if (workerRow) {
            const workerClient =
              workerRow.saasClientId || (workerRow.tenant ? workerRow.tenant.saasClientId : null);
            if (workerClient && workerClient !== effectiveClientScope) {
              return res.status(403).json({
                error: `Aislamiento multi-tenant: el trabajador ${wId} pertenece al proyecto ${workerClient} y no puede respaldarse bajo ${effectiveClientScope}`
              });
            }
          }
        }
      }

      const serverCanonicalSha256 = computeStage0CanonicalSha256(sanitizedBatch);
      if (serverCanonicalSha256 !== clientCanonicalSha256) {
        return res.status(422).json({
          error: 'Fallo de verificación de integridad SHA-256 entre cliente y servidor',
          clientCanonicalSha256,
          serverCanonicalSha256
        });
      }

      // Sanitizar diagnóstico de solo lectura de IndexedDB (solo metadatos, cero binarios)
      const rawDiag = body.idbDiagnostic && typeof body.idbDiagnostic === 'object' ? body.idbDiagnostic : {};
      const rawOrphanMeta = Array.isArray(rawDiag.orphanReferencesMetadata)
        ? rawDiag.orphanReferencesMetadata.slice(0, 100)
        : [];
      const cleanOrphanMeta: Stage0IdbOrphanDiagnosticItem[] = rawOrphanMeta
        .filter((m: unknown) => m && typeof m === 'object')
        .map((m: Record<string, unknown>) => ({
          entityType:
            m.entityType === 'WORKER'
              ? 'WORKER'
              : m.entityType === 'COMPANY_HISTORY'
                ? 'COMPANY_HISTORY'
                : 'COMPANY',
          entityId: String(m.entityId || '').slice(0, 80),
          docIndex: Number(m.docIndex) || 0,
          fileRef: String(m.fileRef || '').slice(0, 140),
          fileName: String(m.fileName || '').slice(0, 140),
          hasLocalCopyInIdb: Boolean(m.hasLocalCopyInIdb)
        }));

      const nowIso = new Date().toISOString();
      const deviceCompositeKey = `${liveUser.id}::${rawDeviceId}`;
      const uaSummary =
        typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'].slice(0, 140) : 'unknown';

      // Serialización estricta: Mutex en proceso + Bloqueo transaccional pg_advisory_xact_lock en PostgreSQL
      // para impedir que dos respaldos simultáneos sobrescriban JSON o creen filas duplicadas.
      const txResult = await withStage0ServerWriteLock(() =>
        prisma.$transaction(
          async (tx) => {
            if (typeof (tx as { $executeRawUnsafe?: unknown }).$executeRawUnsafe === 'function') {
              await (tx as { $executeRawUnsafe: (sql: string) => Promise<unknown> }).$executeRawUnsafe(
                `SELECT pg_advisory_xact_lock(20261114, hashtext('novillo_stage0_backup_write'))`
              );
            }

            const allDeviceRows = await tx.systemBackupSnapshot.findMany({
              where: { triggerType: STAGE0_TRIGGER_TYPE },
              orderBy: { createdAt: 'asc' }
            });

            const matchingRows = allDeviceRows.filter(
              (r) => r.createdBy === deviceCompositeKey && r.saasClientId === effectiveClientScope
            );
            const targetRow = matchingRows[0] || undefined;

            let globalRecordsCount = 0;
            let globalBytesCount = 0;
            const matchingIds = new Set(matchingRows.map((r) => r.id));

            for (const row of allDeviceRows) {
              globalBytesCount += Buffer.byteLength(row.snapshotData || '', 'utf8');
              if (!matchingIds.has(row.id)) {
                try {
                  const parsed = JSON.parse(row.snapshotData) as Stage0DeviceSnapshotPayload;
                  if (parsed && parsed.recordsByStableId) {
                    globalRecordsCount += Object.keys(parsed.recordsByStableId).length;
                  }
                } catch {}
              }
            }

            let currentPayload: Stage0DeviceSnapshotPayload = {
              schemaVersion: 'stage0-v1',
              deviceId: rawDeviceId,
              saasClientId: effectiveClientScope,
              platformUserId: liveUser.id,
              username: liveUser.username,
              role: liveUser.role,
              firstReportedAt: nowIso,
              lastReportedAt: nowIso,
              lastSessionJti: liveUser.jti || '',
              userAgentSummary: uaSummary,
              recordsByStableId: {},
              idbDiagnosticSummary: {
                idbChecked: Boolean(rawDiag.idbChecked),
                idbStatus: String(rawDiag.idbStatus || 'NOT_REPORTED').slice(0, 60),
                totalDocFilesInIdb: Math.max(0, Number(rawDiag.totalDocFilesInIdb) || 0),
                totalDocfileKeysInLocalStorage: Math.max(0, Number(rawDiag.totalDocfileKeysInLocalStorage) || 0),
                orphanReferencesWithLocalCopyCount: cleanOrphanMeta.length,
                orphanReferencesMetadata: cleanOrphanMeta
              }
            };

            // Si existían una o más filas previas para este (usuario, dispositivo, cliente), consolidar todos sus registros sin perder ninguno
            for (const mRow of matchingRows) {
              if (!mRow.snapshotData) continue;
              try {
                const existingParsed = JSON.parse(mRow.snapshotData) as Stage0DeviceSnapshotPayload;
                if (existingParsed && typeof existingParsed === 'object' && existingParsed.recordsByStableId) {
                  currentPayload = {
                    ...existingParsed,
                    username: liveUser.username,
                    role: liveUser.role,
                    firstReportedAt: currentPayload.firstReportedAt || existingParsed.firstReportedAt || nowIso,
                    lastReportedAt: nowIso,
                    lastSessionJti: liveUser.jti || existingParsed.lastSessionJti || '',
                    userAgentSummary: uaSummary,
                    recordsByStableId: {
                      ...existingParsed.recordsByStableId,
                      ...currentPayload.recordsByStableId
                    },
                    idbDiagnosticSummary: currentPayload.idbDiagnosticSummary
                  };
                }
              } catch {}
            }

            // Verificar qué registros del lote YA fueron sincronizados en AttendanceLog mediante
            // confirmaciones exactas del servidor por identificador estable (stableRecordId / originalId clientLogId).
            // PROHIBIDO usar tolerancia heurística de ±5 segundos por timestamp, para jamás marcar como sincronizado
            // un registro legítimo diferente.
            const alreadySyncedRecordIds: string[] = [];
            if (sanitizedBatch.length > 0) {
              const [allAttendanceLogs, syncAckAudits] = await Promise.all([
                tx.attendanceLog.findMany(),
                tx.auditLog.findMany({
                  where: { action: 'ATTENDANCE_LOG_SYNC_ACK' }
                })
              ]);
              const existingAttendanceLogIds = new Set(allAttendanceLogs.map((l) => l.id));
              const confirmedByStableId = new Map<string, string>();
              const confirmedByClientLogKey = new Map<string, string>();

              for (const ack of syncAckAudits) {
                if (!ack.details) continue;
                try {
                  const meta = JSON.parse(ack.details) as {
                    attendanceLogId?: string;
                    clientLogId?: string | null;
                    stableRecordId?: string | null;
                    workerId?: string;
                    type?: string;
                  };
                  const logId = meta.attendanceLogId || ack.entityId || '';
                  if (!logId || !existingAttendanceLogIds.has(logId)) continue;

                  if (meta.stableRecordId) {
                    confirmedByStableId.set(String(meta.stableRecordId).trim(), logId);
                  }
                  if (meta.clientLogId && meta.workerId && meta.type) {
                    const cKey = `${String(meta.clientLogId).trim()}|${String(meta.workerId).trim().toLowerCase()}|${String(meta.type).trim().toUpperCase()}`;
                    confirmedByClientLogKey.set(cKey, logId);
                  }
                } catch {}
              }

              for (const item of sanitizedBatch) {
                const matchedByStable = confirmedByStableId.get(item.stableRecordId);
                let matchedByClientLog: string | undefined;
                if (item.originalId) {
                  const cKey = `${item.originalId}|${item.workerId.toLowerCase()}|${item.type}`;
                  matchedByClientLog = confirmedByClientLogKey.get(cKey);
                }

                if (matchedByStable || matchedByClientLog) {
                  alreadySyncedRecordIds.push(item.stableRecordId);
                }
              }
            }

            const confirmedRecordIds: string[] = [];
            const unconfirmedRecordIds: string[] = [];
            const resolvedRecordIds: string[] = [];
            let quotaReached = false;
            let quotaReason: string | null = null;

            for (const item of sanitizedBatch) {
              const existingRec = currentPayload.recordsByStableId[item.stableRecordId];
              if (existingRec) {
                currentPayload.recordsByStableId[item.stableRecordId] = {
                  ...existingRec,
                  lastSeenAt: nowIso,
                  syncState: existingRec.adminResolution ? 'RESOLVED_ADMIN' : item.syncState,
                  lastRejectStatus: item.lastRejectStatus ?? existingRec.lastRejectStatus ?? null,
                  lastRejectError: item.lastRejectError ?? existingRec.lastRejectError ?? null,
                  quarantinedAt: item.quarantinedAt ?? existingRec.quarantinedAt ?? null
                };
                confirmedRecordIds.push(item.stableRecordId);
                if (existingRec.adminResolution) {
                  resolvedRecordIds.push(item.stableRecordId);
                }
              } else {
                const deviceRecordsCount = Object.keys(currentPayload.recordsByStableId).length;
                const candidateRecord: Stage0StoredRecord = {
                  ...item,
                  firstBackedUpAt: nowIso,
                  lastSeenAt: nowIso,
                  reportedByUserId: liveUser.id,
                  reportedByUsername: liveUser.username,
                  saasClientId: effectiveClientScope,
                  deviceId: rawDeviceId,
                  adminResolution: null
                };

                const estimatedItemBytes = Buffer.byteLength(JSON.stringify(candidateRecord), 'utf8');
                const currentDeviceBytes = Buffer.byteLength(JSON.stringify(currentPayload), 'utf8');
                const otherDevicesBytes =
                  globalBytesCount - (targetRow ? Buffer.byteLength(targetRow.snapshotData || '', 'utf8') : 0);

                if (deviceRecordsCount >= STAGE0_MAX_RECORDS_PER_DEVICE) {
                  quotaReached = true;
                  quotaReason = `Límite por dispositivo alcanzado (${STAGE0_MAX_RECORDS_PER_DEVICE} registros).`;
                  unconfirmedRecordIds.push(item.stableRecordId);
                  continue;
                }
                if (globalRecordsCount + deviceRecordsCount + 1 > STAGE0_MAX_GLOBAL_RECORDS) {
                  quotaReached = true;
                  quotaReason = `Límite global de registros alcanzado (${STAGE0_MAX_GLOBAL_RECORDS} registros).`;
                  unconfirmedRecordIds.push(item.stableRecordId);
                  continue;
                }
                if (otherDevicesBytes + currentDeviceBytes + estimatedItemBytes > STAGE0_MAX_GLOBAL_BYTES) {
                  quotaReached = true;
                  quotaReason = `Límite global de almacenamiento de protección alcanzado (${STAGE0_MAX_GLOBAL_BYTES} bytes).`;
                  unconfirmedRecordIds.push(item.stableRecordId);
                  continue;
                }

                currentPayload.recordsByStableId[item.stableRecordId] = candidateRecord;
                confirmedRecordIds.push(item.stableRecordId);
              }
            }

            for (const [stId, storedRec] of Object.entries(currentPayload.recordsByStableId)) {
              if (storedRec.adminResolution && !resolvedRecordIds.includes(stId)) {
                resolvedRecordIds.push(stId);
              }
            }

            const allStoredList = Object.values(currentPayload.recordsByStableId);
            const pendingCount = allStoredList.filter((r) => r.syncState === 'PENDING').length;
            const quarantinedCount = allStoredList.filter(
              (r) => r.syncState === 'QUARANTINED_PENDING_RESOLUTION'
            ).length;
            const resolvedCount = allStoredList.filter((r) => Boolean(r.adminResolution)).length;

            const statsObj = {
              schemaVersion: 'stage0-v1',
              deviceId: rawDeviceId,
              saasClientId: effectiveClientScope,
              platformUserId: liveUser.id,
              username: liveUser.username,
              role: liveUser.role,
              totalStoredRecords: allStoredList.length,
              pendingCount,
              quarantinedCount,
              resolvedCount,
              lastBatchCanonicalSha256: serverCanonicalSha256,
              idbOrphanCount: cleanOrphanMeta.length,
              lastReportedAt: nowIso
            };

            const serializedSnapshotData = JSON.stringify(currentPayload);
            const serializedStatsJson = JSON.stringify(statsObj);

            let savedSnapshotId = '';
            if (targetRow) {
              const updated = await tx.systemBackupSnapshot.update({
                where: { id: targetRow.id },
                data: {
                  statsJson: serializedStatsJson,
                  snapshotData: serializedSnapshotData
                }
              });
              savedSnapshotId = updated.id;
            } else {
              const created = await tx.systemBackupSnapshot.create({
                data: {
                  saasClientId: effectiveClientScope,
                  triggerType: STAGE0_TRIGGER_TYPE,
                  createdBy: deviceCompositeKey,
                  statsJson: serializedStatsJson,
                  snapshotData: serializedSnapshotData
                }
              });
              savedSnapshotId = created.id;
            }

            return {
              savedSnapshotId,
              confirmedRecordIds,
              unconfirmedRecordIds,
              resolvedRecordIds,
              alreadySyncedRecordIds,
              quotaReached,
              quotaReason,
              totalStoredForDevice: allStoredList.length
            };
          },
          {
            isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
            maxWait: 15000,
            timeout: 30000
          }
        )
      );

      // Marcar la sesión actual en el padrón pasivo como verificada por Etapa 0
      const sessionKey = liveUser.jti || `legacy_${liveUser.id}_${liveUser.username}`;
      const sessionEntry = passiveSessionsRegistry.get(sessionKey);
      if (sessionEntry) {
        sessionEntry.hasReportedStage0Snapshot = true;
        if (!sessionEntry.reportedDeviceIds.includes(rawDeviceId)) {
          sessionEntry.reportedDeviceIds.push(rawDeviceId);
        }
      }

      if (txResult.quotaReached) {
        await recordAuditLog({
          username: liveUser.username,
          role: liveUser.role,
          saasClientId: effectiveClientScope,
          action: 'DEVICE_BACKUP_QUOTA_REACHED',
          entityType: 'BACKUP',
          entityId: txResult.savedSnapshotId,
          details: `Cuota alcanzada en dispositivo ${rawDeviceId}: ${txResult.quotaReason} (${txResult.unconfirmedRecordIds.length} registros pendientes de cupo)`,
          ipAddress: getRequestIp(req)
        });
      }

      return res.status(200).json({
        success: true,
        snapshotId: txResult.savedSnapshotId,
        deviceId: rawDeviceId,
        saasClientId: effectiveClientScope,
        confirmedCanonicalSha256: serverCanonicalSha256,
        confirmedRecordIds: txResult.confirmedRecordIds,
        unconfirmedRecordIds: txResult.unconfirmedRecordIds,
        resolvedRecordIds: txResult.resolvedRecordIds,
        alreadySyncedRecordIds: txResult.alreadySyncedRecordIds,
        quotaReached: txResult.quotaReached,
        quotaReason: txResult.quotaReason,
        totalStoredForDevice: txResult.totalStoredForDevice,
        savedAt: nowIso
      });
    } catch (error) {
      console.error('Error in POST /api/device-protection/snapshot:', error);
      return res.status(500).json({ error: 'Error interno al respaldar la cola del dispositivo' });
    }
  }
);

app.get(
  '/api/device-protection/status',
  requireStage0LiveAuth,
  requireRoles(['Diamante']),
  async (_req: Request, res: Response) => {
    try {
      const [allPlatformUsers, deviceRows] = await Promise.all([
        prisma.platformUser.findMany({ orderBy: { createdAt: 'asc' } }),
        prisma.systemBackupSnapshot.findMany({
          where: { triggerType: STAGE0_TRIGGER_TYPE },
          orderBy: { createdAt: 'desc' }
        })
      ]);

      const parsedDevices: Array<{
        snapshotId: string;
        deviceId: string;
        saasClientId: string;
        platformUserId: string;
        username: string;
        role: string;
        firstReportedAt: string;
        lastReportedAt: string;
        lastSessionJti: string;
        totalStoredRecords: number;
        pendingCount: number;
        quarantinedCount: number;
        resolvedCount: number;
        idbOrphanCount: number;
        deviceStatus: 'VERIFIED_EMPTY_QUEUE' | 'VERIFIED_BACKED_UP';
      }> = [];

      for (const row of deviceRows) {
        try {
          const payload = JSON.parse(row.snapshotData) as Stage0DeviceSnapshotPayload;
          if (!payload || !payload.deviceId) continue;
          const recs = Object.values(payload.recordsByStableId || {});
          const pendingCount = recs.filter((r) => r.syncState === 'PENDING').length;
          const quarantinedCount = recs.filter(
            (r) => r.syncState === 'QUARANTINED_PENDING_RESOLUTION'
          ).length;
          const resolvedCount = recs.filter((r) => Boolean(r.adminResolution)).length;
          const activeUnresolvedCount = pendingCount + quarantinedCount;

          parsedDevices.push({
            snapshotId: row.id,
            deviceId: payload.deviceId,
            saasClientId: payload.saasClientId,
            platformUserId: payload.platformUserId,
            username: payload.username,
            role: payload.role,
            firstReportedAt: payload.firstReportedAt,
            lastReportedAt: payload.lastReportedAt,
            lastSessionJti: payload.lastSessionJti,
            totalStoredRecords: recs.length,
            pendingCount,
            quarantinedCount,
            resolvedCount,
            idbOrphanCount: payload.idbDiagnosticSummary?.orphanReferencesWithLocalCopyCount || 0,
            deviceStatus: activeUnresolvedCount > 0 ? 'VERIFIED_BACKED_UP' : 'VERIFIED_EMPTY_QUEUE'
          });
        } catch {}
      }

      const activeSessionsList = Array.from(passiveSessionsRegistry.values());
      const unbackedActiveSessions = activeSessionsList.filter((s) => !s.hasReportedStage0Snapshot);

      const accountsReport = allPlatformUsers.map((u) => {
        const userDevices = parsedDevices.filter(
          (d) => d.platformUserId === u.id || d.username === u.username
        );
        const userSessions = activeSessionsList.filter(
          (s) => s.userId === u.id || s.username === u.username
        );
        const userUnbackedSessions = userSessions.filter((s) => !s.hasReportedStage0Snapshot);

        let accountVerificationState:
          | 'UNVERIFIED_ACCOUNT_NO_CONNECTION'
          | 'PARTIALLY_VERIFIED_HAS_LEGACY_ACTIVE_SESSIONS'
          | 'VERIFIED_REPORTED_DEVICES_ONLY' = 'UNVERIFIED_ACCOUNT_NO_CONNECTION';

        if (userDevices.length === 0 && userUnbackedSessions.length > 0) {
          accountVerificationState = 'PARTIALLY_VERIFIED_HAS_LEGACY_ACTIVE_SESSIONS';
        } else if (userDevices.length > 0 && userUnbackedSessions.length > 0) {
          accountVerificationState = 'PARTIALLY_VERIFIED_HAS_LEGACY_ACTIVE_SESSIONS';
        } else if (userDevices.length > 0) {
          accountVerificationState = 'VERIFIED_REPORTED_DEVICES_ONLY';
        }

        return {
          userId: u.id,
          username: u.username,
          role: u.role,
          clientId: u.clientId,
          accountVerificationState,
          reportedDevicesCount: userDevices.length,
          activeSessionsSeenCount: userSessions.length,
          unbackedActiveLegacySessionsCount: userUnbackedSessions.length,
          multiDeviceDetected: userDevices.length > 1 || userSessions.length > 1,
          reportedDevices: userDevices,
          unbackedActiveSessions: userUnbackedSessions
        };
      });

      return res.json({
        generatedAt: new Date().toISOString(),
        inventoryCompletenessWarning:
          'ADVERTENCIA: Este inventario solo conoce los dispositivos y sesiones que se han conectado al servidor. Teléfonos apagados, sin conexión a internet o que aún no abren la aplicación aparecen como NO VERIFICADOS y nunca deben asumirse como respaldados sin confirmación física en caseta.',
        summary: {
          totalPlatformAccounts: allPlatformUsers.length,
          unverifiedAccountsCount: accountsReport.filter(
            (a) => a.accountVerificationState === 'UNVERIFIED_ACCOUNT_NO_CONNECTION'
          ).length,
          accountsWithLegacyUnbackedSessionsCount: accountsReport.filter(
            (a) => a.accountVerificationState === 'PARTIALLY_VERIFIED_HAS_LEGACY_ACTIVE_SESSIONS'
          ).length,
          totalVerifiedDevicesCount: parsedDevices.length,
          totalUnbackedActiveSessionsCount: unbackedActiveSessions.length
        },
        accountsReport,
        verifiedDevices: parsedDevices,
        unbackedActiveSessions
      });
    } catch (error) {
      return res.status(500).json({ error: 'Error al consultar el estado de protección de dispositivos' });
    }
  }
);

app.post(
  '/api/device-protection/resolve-record',
  requireStage0LiveAuth,
  requireRoles(['Diamante']),
  async (req: Request, res: Response) => {
    try {
      const adminUser = req.authUser!;
      const { snapshotId, stableRecordId, resolution, notes } = req.body || {};
      if (
        !snapshotId ||
        !stableRecordId ||
        (resolution !== 'RESOLVED_ADMIN_APPROVED' && resolution !== 'RESOLVED_ADMIN_DISMISSED')
      ) {
        return res.status(400).json({ error: 'Parámetros de resolución inválidos' });
      }

      const nowIso = new Date().toISOString();
      const txResult = await withStage0ServerWriteLock(async () => {
        return await prisma.$transaction(
          async (tx) => {
            try {
              if (typeof (tx as unknown as { $executeRaw?: unknown }).$executeRaw === 'function') {
                await tx.$executeRaw`SELECT pg_advisory_xact_lock(20261114, hashtext('novillo_stage0_backup_write'))`;
              }
            } catch {}

            const row = await tx.systemBackupSnapshot.findUnique({ where: { id: String(snapshotId) } });
            if (!row || row.triggerType !== STAGE0_TRIGGER_TYPE) {
              return { status: 404 as const, error: 'Respaldo de dispositivo no encontrado' };
            }

            const payload = JSON.parse(row.snapshotData) as Stage0DeviceSnapshotPayload;
            const targetRec = payload.recordsByStableId?.[String(stableRecordId)];
            if (!targetRec) {
              return {
                status: 404 as const,
                error: 'Registro específico no encontrado en el respaldo del dispositivo'
              };
            }

            let insertedLogId: string | null = null;
            if (resolution === 'RESOLVED_ADMIN_APPROVED') {
              const worker = await tx.user.findUnique({ where: { id: targetRec.workerId } });
              if (!worker) {
                return {
                  status: 400 as const,
                  error:
                    'No se puede aprobar la inserción en AttendanceLog porque el workerId no existe en la tabla User'
                };
              }
              const createdLog = await tx.attendanceLog.create({
                data: {
                  userId: targetRec.workerId,
                  type: targetRec.type,
                  timestamp: new Date(targetRec.timestamp)
                }
              });
              insertedLogId = createdLog.id;
            }

            targetRec.syncState = 'RESOLVED_ADMIN';
            targetRec.adminResolution = {
              status: resolution,
              resolvedBy: adminUser.username,
              resolvedAt: nowIso,
              notes: String(notes || '').slice(0, 300),
              insertedAttendanceLogId: insertedLogId
            };

            await tx.systemBackupSnapshot.update({
              where: { id: row.id },
              data: {
                snapshotData: JSON.stringify(payload)
              }
            });

            return {
              status: 200 as const,
              rowId: row.id,
              saasClientId: payload.saasClientId,
              insertedLogId
            };
          },
          {
            isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
            maxWait: 15000,
            timeout: 30000
          }
        );
      });

      if (txResult.status !== 200) {
        return res.status(txResult.status).json({ error: txResult.error });
      }

      await recordAuditLog({
        username: adminUser.username,
        role: adminUser.role,
        saasClientId: txResult.saasClientId,
        action: 'DEVICE_QUEUE_RECORD_RESOLVED',
        entityType: 'BACKUP',
        entityId: txResult.rowId,
        details: `Resolución ${resolution} para registro ${stableRecordId} (${notes || 'sin notas'})`,
        ipAddress: getRequestIp(req)
      });

      return res.json({
        success: true,
        stableRecordId,
        resolution,
        insertedAttendanceLogId: txResult.insertedLogId,
        resolvedAt: nowIso
      });
    } catch (error) {
      return res.status(500).json({ error: 'Error al resolver registro en cuarentena' });
    }
  }
);

if (!IS_LOCAL_TEST_MODE) {
  app.listen(port, async () => {
    await migrateExistingPlainPasswords();
    await migrateExistingInlineDocuments();
    await runAutomaticDailyBackupIfNeeded();
    // Revisar cada 6 horas si corresponde generar un nuevo respaldo automático diario
    setInterval(() => {
      runAutomaticDailyBackupIfNeeded();
    }, 6 * 60 * 60 * 1000);
    console.log(`[server]: El servidor está corriendo en http://localhost:${port}`);
  });
}

export { app, isLocalIsolatedTestMode };
