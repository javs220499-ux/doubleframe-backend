import express, { Express, Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { PrismaClient } from '@prisma/client';

dotenv.config();
const prisma = new PrismaClient();
const app: Express = express();
const port = process.env.PORT || 3000;
const AUTH_SECRET = process.env.JWT_SECRET || 'doubleframe_saas_secret_key_2026';

function createSessionToken(payload: Record<string, unknown>): string {
  const data = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + 7 * 24 * 3600 * 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', AUTH_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyPassword(storedPassword: string, inputPassword: string): boolean {
  if (!storedPassword || !inputPassword) return false;
  if (storedPassword.startsWith('sha256$')) {
    const parts = storedPassword.split('$');
    if (parts.length === 3) {
      const salt = parts[1] || '';
      const expectedHash = parts[2] || '';
      const computed = crypto.createHmac('sha256', salt).update(inputPassword).digest('hex');
      return computed === expectedHash;
    }
  }
  return storedPassword === inputPassword;
}

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// ---------------------------------------------------
// RUTAS BÁSICAS Y KEEP-ALIVE
// ---------------------------------------------------
app.get('/', (req: Request, res: Response) => {
  res.json({ message: '🚀 API de SaaS Control de Accesos', version: '1.1.0' });
});

app.get('/api/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ---------------------------------------------------
// RUTAS PARA COMPAÑÍAS (TENANTS)
// ---------------------------------------------------
app.get('/api/companies', async (req: Request, res: Response) => {
  try {
    const { saasClientId } = req.query;
    const whereClause = saasClientId ? { saasClientId: String(saasClientId) } : {};
    const companies = await prisma.tenant.findMany({ where: whereClause, orderBy: { createdAt: 'desc' } });
    res.json(companies);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener las compañías' });
  }
});

app.post('/api/companies', async (req: Request, res: Response) => {
  try {
    const { name, domain, subscriptionPlan, documents, mandatoryDocs, saasClientId } = req.body;
    if (!name) return res.status(400).json({ error: 'El nombre es obligatorio' });

    const newCompany = await prisma.tenant.create({
      data: { 
          name, 
          domain: domain || null, 
          subscriptionPlan: subscriptionPlan || 'BASIC',
          documents: documents ? JSON.stringify(documents) : null,
          mandatoryDocs: mandatoryDocs ? JSON.stringify(mandatoryDocs) : null,
          saasClientId: saasClientId || null
      },
    });
    res.status(201).json(newCompany);
  } catch (error) {
    res.status(500).json({ error: 'Error al crear la compañía' });
  }
});

app.put('/api/companies/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { name, documents, mandatoryDocs } = req.body;
    
    const updated = await prisma.tenant.update({
        where: { id },
        data: {
            name,
            documents: documents ? JSON.stringify(documents) : null,
            mandatoryDocs: mandatoryDocs ? JSON.stringify(mandatoryDocs) : null
        }
    });
    res.json(updated);
  } catch (error) {
      res.status(500).json({ error: 'Error al actualizar' });
  }
});

app.delete('/api/companies/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    
    // Eliminar primero a los trabajadores y sus asistencias asociadas
    const users = await prisma.user.findMany({ where: { tenantId: id } });
    for (const u of users) {
        await prisma.attendanceLog.deleteMany({ where: { userId: u.id } });
    }
    await prisma.user.deleteMany({ where: { tenantId: id } });
    
    // Luego eliminar la empresa
    await prisma.tenant.delete({ where: { id } });
    res.json({ success: true });
  } catch (error) {
    console.error("Delete error:", error);
    res.status(500).json({ error: 'Error al eliminar la compañía' });
  }
});

// ---------------------------------------------------
// RUTAS PARA TRABAJADORES (USERS)
// ---------------------------------------------------
app.get('/api/workers', async (req: Request, res: Response) => {
  try {
    const { saasClientId } = req.query;
    const whereClause = saasClientId ? { saasClientId: String(saasClientId) } : {};
    const workers = await prisma.user.findMany({
      where: whereClause,
      orderBy: { createdAt: 'desc' }
    });
    
    const formattedWorkers = workers.map(w => {
        let profile = {};
        if(w.profileData) {
            try { profile = JSON.parse(w.profileData); } catch(e){}
        }
        return {
            id: w.id,
            companyId: w.tenantId,
            name: w.name,
            email: w.email,
            isActive: w.isActive,
            ...profile, // Expand profile fields (photo, position, imss, allergies, etc.)
            photo: (profile as any).photo || `https://ui-avatars.com/api/?name=${encodeURIComponent(w.name)}&background=random`,
            saasClientId: w.saasClientId
        };
    });

    res.json(formattedWorkers);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener trabajadores' });
  }
});

app.get('/api/workers/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const worker = await prisma.user.findUnique({
      where: { id },
      include: { tenant: true }
    });
    if (!worker) {
      return res.status(404).json({ error: 'Trabajador no encontrado' });
    }
    res.json(worker);
  } catch (error) {
    res.status(500).json({ error: 'Error al buscar el trabajador' });
  }
});

app.post('/api/workers', async (req: Request, res: Response) => {
  try {
    const { name, companyId, saasClientId, ...profileData } = req.body;
    
    if (!name || !companyId) {
      return res.status(400).json({ error: 'Nombre y Compañia son obligatorios' });
    }

    const newWorker = await prisma.user.create({
      data: {
        tenantId: companyId,
        name: name,
        email: profileData.email || `${Date.now()}@test.com`,
        passwordHash: profileData.password || '123456',
        profileData: JSON.stringify(profileData),
        saasClientId: saasClientId || null
      },
    });

    res.status(201).json(newWorker);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al crear trabajador' });
  }
});

app.put('/api/workers/:id', async (req: Request, res: Response) => {
    try {
        const { id } = req.params;
        const { name, companyId, ...profileData } = req.body;
        
        const existing = await prisma.user.findUnique({ where: { id } });
        if(!existing) return res.status(404).json({error: 'Worker not found'});
        
        let oldProfile = {};
        if(existing.profileData) {
            try { oldProfile = JSON.parse(existing.profileData); } catch(e){}
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
        res.json(updatedWorker);
    } catch (error) {
        res.status(500).json({ error: 'Error al actualizar trabajador' });
    }
});

app.delete('/api/workers/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    
    // Primero borramos sus asistencias
    await prisma.attendanceLog.deleteMany({ where: { userId: id } });
    
    // Luego borramos al trabajador
    await prisma.user.delete({ where: { id } });
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar al trabajador' });
  }
});

// ---------------------------------------------------
// RUTAS PARA ASISTENCIAS (LOGS)
// ---------------------------------------------------
app.get('/api/logs', async (req: Request, res: Response) => {
  try {
    const { saasClientId, from, to, limit } = req.query;
    const whereClause: Record<string, unknown> = {};

    if (from || to) {
      const timestampFilter: Record<string, Date> = {};
      if (from) {
        const fromDate = new Date(String(from));
        if (!isNaN(fromDate.getTime())) timestampFilter.gte = fromDate;
      }
      if (to) {
        const toDate = new Date(String(to));
        if (!isNaN(toDate.getTime())) timestampFilter.lte = toDate;
      }
      if (Object.keys(timestampFilter).length > 0) {
        whereClause.timestamp = timestampFilter;
      }
    }

    if (saasClientId && saasClientId !== 'all') {
      whereClause.OR = [
        { user: { saasClientId: String(saasClientId) } },
        { user: { saasClientId: null } }
      ];
    }

    const parsedLimit = limit ? parseInt(String(limit), 10) : undefined;
    const logs = await prisma.attendanceLog.findMany({
      where: whereClause,
      orderBy: { timestamp: 'desc' },
      ...(parsedLimit && !isNaN(parsedLimit) && parsedLimit > 0 ? { take: parsedLimit } : {})
    });
    
    // Adaptamos para app.js
    const formattedLogs = logs.map(log => ({
      id: log.id,
      workerId: log.userId, // app.js espera workerId
      type: log.type,       // 'IN' o 'OUT'
      timestamp: log.timestamp
    }));

    res.json(formattedLogs);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener asistencias' });
  }
});

app.post('/api/logs', async (req: Request, res: Response) => {
  try {
    const { workerId, type } = req.body;
    
    if (!workerId || !type) {
      return res.status(400).json({ error: 'Faltan datos del escaneo' });
    }

    const newLog = await prisma.attendanceLog.create({
      data: {
        userId: workerId,
        type: type,
      },
    });

    res.status(201).json(newLog);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al guardar el escaneo' });
  }
});

// ---------------------------------------------------
// RUTAS PARA USUARIOS DE PLATAFORMA (SaaS)
// ---------------------------------------------------
app.get('/api/platform-users', async (req: Request, res: Response) => {
  try {
    const users = await prisma.platformUser.findMany({
      orderBy: { createdAt: 'desc' }
    });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener usuarios de plataforma' });
  }
});

app.post('/api/platform-users', async (req: Request, res: Response) => {
  try {
    const { username, password, role, clientId } = req.body;
    if (!username || !password || !role) {
      return res.status(400).json({ error: 'Faltan datos obligatorios' });
    }
    const newUser = await prisma.platformUser.create({
      data: { username, password, role, clientId: clientId || null },
    });
    res.status(201).json(newUser);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al crear usuario de plataforma' });
  }
});

app.put('/api/platform-users/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { username, password, role, clientId } = req.body;
    const updatedUser = await prisma.platformUser.update({
      where: { id },
      data: { username, password, role, clientId: clientId || null },
    });
    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar usuario' });
  }
});

app.delete('/api/platform-users/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    await prisma.platformUser.delete({ where: { id } });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar usuario' });
  }
});

// ---------------------------------------------------
// LOGIN (Verifica DB o Mock para Celular)
// ---------------------------------------------------
app.post('/api/login', async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body;
    
    

    // 2. Verificar cuenta "Piedra" para la App del celular
    if (username === 'pedro.guardia') {
      const userPayload = { username, role: 'Piedra', clientId: 'client-1' };
      return res.json({
        success: true,
        token: createSessionToken(userPayload),
        user: userPayload
      });
    }

    // 3. Buscar en la base de datos de usuarios de plataforma
    const dbUser = await prisma.platformUser.findUnique({
      where: { username }
    });

    if (dbUser && verifyPassword(dbUser.password, password)) {
      const userPayload = { 
        id: dbUser.id, 
        username: dbUser.username, 
        role: dbUser.role, 
        clientId: dbUser.clientId 
      };
      return res.json({
        success: true,
        token: createSessionToken(userPayload),
        user: userPayload
      });
    }
    
    return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Error interno del servidor" });
  }
});

// ---------------------------------------------------
// RESPALDO COMPLETO DEL SISTEMA (Para Usuario Diamante)
// ---------------------------------------------------
app.get('/api/backup', async (req: Request, res: Response) => {
  try {
    const [companies, workers, logs, platformUsers] = await Promise.all([
      prisma.tenant.findMany({ orderBy: { createdAt: 'desc' } }),
      prisma.user.findMany({ orderBy: { createdAt: 'desc' } }),
      prisma.attendanceLog.findMany({ orderBy: { timestamp: 'desc' } }),
      prisma.platformUser.findMany({ orderBy: { createdAt: 'desc' } })
    ]);
    res.json({
      exportedAt: new Date().toISOString(),
      version: '1.1.0',
      companies,
      workers,
      logs,
      platformUsers
    });
  } catch (error) {
    res.status(500).json({ error: 'Error al generar respaldo del servidor' });
  }
});

app.listen(port, async () => {

  

  console.log(`[server]: El servidor est corriendo en http://localhost:${port}`);
});
