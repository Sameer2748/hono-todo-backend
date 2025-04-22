import { Hono } from 'hono'
import { PrismaClient } from './generated/prisma/edge'
import { withAccelerate } from '@prisma/extension-accelerate'
import { SignJWT, jwtVerify } from 'jose'

const app = new Hono()

const getClient = (c: any) =>
  new PrismaClient({ datasourceUrl: c.env.DATABASE_URL  }).$extends(withAccelerate())


app.get('/', (c) => c.text('Hello Hono!'))

// Sign‑Up: create user + return JWT
app.post('/signUp', async (c) => {
  const { name, email, password } = await c.req.json()
  const prisma = getClient(c)
  const user = await prisma.user.create({
    data: { name, email, password },
  })

  const token = await new SignJWT({ userId: user.id })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('2h')
    .sign(new TextEncoder().encode(c.env.JWT_SECRET))

  return c.json({ user, token })
})

// Sign‑In: verify credentials + return JWT
app.post('/signIn', async (c) => {
  const { email, password } = await c.req.json()
  const prisma = getClient(c)
  const user = await prisma.user.findUnique({ where: { email } })

  if (!user || user.password !== password) {
    return c.json({ error: 'Invalid credentials' }, 401)
  }

  const token = await new SignJWT({ userId: user.id })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('2h')
    .sign(new TextEncoder().encode(c.env.JWT_SECRET))

  return c.json({ user, token })
})

app.use('/todo/*', async (c, next) => {
  const authHeader = c.req.header('Authorization')
  if (!authHeader) return c.text('Missing Authorization header', 401)

  const token = authHeader.replace('Bearer ', '')
  try {
    const { payload } = await jwtVerify(
      token,
      new TextEncoder().encode(c.env.JWT_SECRET)
    )
    // stash userId for handlers below
    c.set('userId', (payload as any).userId)
    return next()
  } catch (err) {
    return c.text('Invalid or expired token', 401)
  }
})

// Create a new todo for this user
app.post('/todo', async (c) => {
  const { title, done } = await c.req.json()
  const userId = c.get('userId') as number
  const prisma = getClient(c)

  const todo = await prisma.todo.create({
    data: { title, done: done ?? false, userId },
  })
  return c.json({ todo })
})

// List this user’s todos
app.get('/todo', async (c) => {
  const userId = c.get('userId') as number
  const prisma = getClient(c)

  const todos = await prisma.todo.findMany({
    where: { userId },
    orderBy: { id: 'desc' },
  })
  return c.json({ todos })
})

export default app
